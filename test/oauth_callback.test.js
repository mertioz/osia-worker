import { env } from "cloudflare:workers";
import {
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
  SELF,
} from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

import relayWorker from "../src/relay.js";
import {
  callbackIdForState,
  OAUTH_SCHEMA_VERSION,
} from "../src/oauth_callback.js";
import { sanitizeRelayLogData } from "../src/relay_policy.js";

const openedSockets = [];

function createInbox(ws) {
  const messages = [];
  const waiters = [];
  ws.addEventListener("message", (event) => {
    const value = JSON.parse(String(event.data));
    const index = waiters.findIndex(({ predicate }) => predicate(value));
    if (index >= 0) {
      const [{ resolve, timer }] = waiters.splice(index, 1);
      clearTimeout(timer);
      resolve(value);
    } else {
      messages.push(value);
    }
  });
  return {
    async waitFor(predicate, timeoutMs = 1500) {
      const index = messages.findIndex(predicate);
      if (index >= 0) return messages.splice(index, 1)[0];
      return await new Promise((resolve, reject) => {
        const waiter = { predicate, resolve, timer: null };
        waiter.timer = setTimeout(() => {
          const waiterIndex = waiters.indexOf(waiter);
          if (waiterIndex >= 0) waiters.splice(waiterIndex, 1);
          reject(new Error("timed out waiting for OAuth relay message"));
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
    async expectNone(predicate, timeoutMs = 100) {
      const index = messages.findIndex(predicate);
      if (index >= 0) throw new Error("unexpected OAuth relay message");
      await new Promise((resolve, reject) => {
        const waiter = {
          predicate,
          resolve: () => reject(new Error("unexpected OAuth relay message")),
          timer: null,
        };
        waiter.timer = setTimeout(() => {
          const waiterIndex = waiters.indexOf(waiter);
          if (waiterIndex >= 0) waiters.splice(waiterIndex, 1);
          resolve();
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
  };
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function pair() {
  const secret = `oauth-relay-test-${crypto.randomUUID()}`;
  return { secret, pairId: await sha256Hex(secret) };
}

function oauthState() {
  return `${crypto.randomUUID().replaceAll("-", "")}${"A".repeat(43)}`.slice(0, 43);
}

function v2Url(pairId) {
  return `https://relay.test/ws?pair_id=${pairId}`;
}

function v1Url(pairId, role) {
  return `https://relay.test/ws?role=${role}&pair_id=${pairId}` +
    `&device_id=${role}-device-1234&session_id=${role}-session-1234`;
}

async function openSocket(url) {
  const response = await SELF.fetch(url, { headers: { Upgrade: "websocket" } });
  expect(response.status).toBe(101);
  const ws = response.webSocket;
  ws.accept();
  openedSockets.push(ws);
  return { ws, inbox: createInbox(ws) };
}

async function authenticateV2(connection, credentials, role) {
  connection.ws.send(JSON.stringify({
    v: 2,
    type: "PAIR_START",
    role,
    pair_id: credentials.pairId,
    seq: 1,
    ack: 0,
    payload: { secret: credentials.secret },
  }));
  return await connection.inbox.waitFor((message) => message.type === "PAIR_CONFIRM");
}

async function authenticateV1(connection, credentials, role) {
  connection.ws.send(JSON.stringify({
    v: 1,
    type: "PAIR_START",
    role,
    pair_id: credentials.pairId,
    device_id: `${role}-device-1234`,
    session_id: `${role}-session-1234`,
    seq: 1,
    ack: 0,
    payload: { secret: credentials.secret },
  }));
  return await connection.inbox.waitFor((message) => message.type === "PAIR_CONFIRM");
}

function control(credentials, type, seq, payload, role = "pc", extra = {}) {
  return {
    v: 2,
    type,
    role,
    pair_id: credentials.pairId,
    seq,
    ack: 0,
    payload,
    ...extra,
  };
}

async function register(connection, credentials, state, seq = 2, flowKind = "gmail") {
  const callbackId = await callbackIdForState(state);
  connection.ws.send(JSON.stringify(control(
    credentials,
    "OAUTH_FLOW_REGISTER",
    seq,
    {
      schema_version: OAUTH_SCHEMA_VERSION,
      callback_id: callbackId,
      flow_kind: flowKind,
      ttl_seconds: 165,
    },
  )));
  const response = await connection.inbox.waitFor((message) =>
    message.type === "OAUTH_FLOW_REGISTERED" || message.type === "ERROR");
  return { callbackId, response };
}

async function callbackRequest(state, params, ip = crypto.randomUUID()) {
  const search = new URLSearchParams({ state, ...params });
  return await SELF.fetch(`https://relay.test/oauth/callback?${search}`, {
    headers: { "CF-Connecting-IP": ip },
  });
}

function errorCode(message) {
  return message?.payload?.code || "";
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const ws of openedSockets.splice(0)) {
    if (ws.readyState === WebSocket.OPEN) ws.close(1000, "test_done");
  }
});

describe("stable OAuth callback validation", () => {
  it("derives the fixed lowercase SHA-256 callback identifier", async () => {
    expect(await callbackIdForState("a".repeat(43))).toBe(
      "66d34fba71f8f450f7e45598853e53bfc23bbd129027cbb131a2f4ffd7878cd0",
    );
  });

  function fakeEnv() {
    const observed = { limiter: 0, lookups: 0 };
    return {
      observed,
      value: {
        OAUTH_CALLBACK_LIMITER: {
          async limit() {
            observed.limiter++;
            return { success: true };
          },
        },
        OAUTH_CALLBACK_FLOW: {
          getByName() {
            observed.lookups++;
            return { submitCallback: async () => ({ status: "gone" }) };
          },
        },
      },
    };
  }

  it.each([
    ["short state", `state=short&code=x`],
    ["both outcomes", `state=${"A".repeat(43)}&code=x&error=denied`],
    ["no outcome", `state=${"A".repeat(43)}`],
    ["oversized code", `state=${"A".repeat(43)}&code=${"x".repeat(4097)}`],
    ["unsafe error", `state=${"A".repeat(43)}&error=bad%20error`],
    ["oversized URL", `state=${"A".repeat(43)}&code=x&extra=${"z".repeat(8200)}`],
  ])("rejects %s before Durable Object lookup", async (_label, query) => {
    const local = fakeEnv();
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/oauth/callback?${query}`,
      { headers: { "CF-Connecting-IP": "synthetic" } },
    ), local.value);
    expect(response.status).toBe(400);
    expect(local.observed.lookups).toBe(0);
    expect(local.observed.limiter).toBe(0);
  });

  it("applies the IP limiter before a valid-looking Flow DO lookup", async () => {
    const local = fakeEnv();
    local.value.OAUTH_CALLBACK_LIMITER.limit = async () => {
      local.observed.limiter++;
      return { success: false };
    };
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/oauth/callback?state=${"A".repeat(43)}&code=x`,
      { headers: { "CF-Connecting-IP": "synthetic" } },
    ), local.value);
    expect(response.status).toBe(429);
    expect(local.observed.limiter).toBe(1);
    expect(local.observed.lookups).toBe(0);
  });

  it("returns a generic 410 for an unknown well-formed flow", async () => {
    const response = await callbackRequest(oauthState(), { code: "synthetic-code" });
    expect(response.status).toBe(410);
    expect(await response.text()).not.toContain("synthetic-code");
  });
});

describe("OAuth flow registration controls", () => {
  it("accepts authoritative PC v2 registration and idempotent repetition", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    const first = await register(pc, credentials, state, 2);
    expect(first.response).toMatchObject({
      type: "OAUTH_FLOW_REGISTERED",
      payload: { callback_id: first.callbackId },
    });
    const repeated = await register(pc, credentials, state, 3);
    expect(repeated.response.type).toBe("OAUTH_FLOW_REGISTERED");
    expect(repeated.response.payload.expires_at).toBe(first.response.payload.expires_at);
  });

  it("rejects mobile, v1, unauthenticated, malformed, and superseded senders", async () => {
    const credentials = await pair();
    const state = oauthState();
    const callbackId = await callbackIdForState(state);
    const payload = {
      schema_version: 1,
      callback_id: callbackId,
      flow_kind: "gmail",
      ttl_seconds: 165,
    };

    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(mobile, credentials, "mobile");
    mobile.ws.send(JSON.stringify(control(
      credentials, "OAUTH_FLOW_REGISTER", 2, payload, "mobile",
    )));
    expect(errorCode(await mobile.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("oauth_control_forbidden");

    const legacyCredentials = await pair();
    const legacy = await openSocket(v1Url(legacyCredentials.pairId, "pc"));
    await authenticateV1(legacy, legacyCredentials, "pc");
    legacy.ws.send(JSON.stringify({
      ...control(legacyCredentials, "OAUTH_FLOW_REGISTER", 2, payload),
      v: 1,
      device_id: "pc-device-1234",
      session_id: "pc-session-1234",
    }));
    expect(errorCode(await legacy.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("oauth_control_forbidden");

    const unauthenticated = await openSocket(v2Url((await pair()).pairId));
    unauthenticated.ws.send(JSON.stringify(control(
      credentials, "OAUTH_FLOW_REGISTER", 2, payload,
    )));
    expect(errorCode(await unauthenticated.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("not_paired");

    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    pc.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_FLOW_REGISTER",
      2,
      { ...payload, callback_id: callbackId.toUpperCase() },
    )));
    expect(errorCode(await pc.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("invalid_oauth_control");

    const replacement = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(replacement, credentials, "pc");
    expect(errorCode(await pc.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("session_superseded");
  });

  it("rejects conflicting immutable binding and enforces four active flows", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const firstState = oauthState();
    const first = await register(pc, credentials, firstState, 2, "gmail");
    expect(first.response.type).toBe("OAUTH_FLOW_REGISTERED");
    const conflict = await register(pc, credentials, firstState, 3, "mcp");
    expect(errorCode(conflict.response)).toBe("oauth_flow_conflict");

    for (let seq = 4; seq <= 6; seq++) {
      expect((await register(pc, credentials, oauthState(), seq)).response.type)
        .toBe("OAUTH_FLOW_REGISTERED");
    }
    const fifth = await register(pc, credentials, oauthState(), 7);
    expect(errorCode(fifth.response)).toBe("oauth_flow_quota");
  });

  it("defaults TTL and enforces exact bounds while rejecting extra fields", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    let seq = 2;
    for (const [requested, expectedSeconds] of [[undefined, 165], [30, 30], [300, 300]]) {
      const callbackId = await callbackIdForState(oauthState());
      const before = Date.now();
      const payload = {
        schema_version: 1,
        callback_id: callbackId,
        flow_kind: "gmail",
        ...(requested === undefined ? {} : { ttl_seconds: requested }),
      };
      pc.ws.send(JSON.stringify(control(
        credentials, "OAUTH_FLOW_REGISTER", seq++, payload,
      )));
      const response = await pc.inbox.waitFor((message) =>
        message.type === "OAUTH_FLOW_REGISTERED");
      expect(response.payload.expires_at - before).toBeGreaterThanOrEqual(
        expectedSeconds * 1000,
      );
      expect(response.payload.expires_at - before).toBeLessThan(
        expectedSeconds * 1000 + 1000,
      );
    }

    for (const requested of [29, 301]) {
      const callbackId = await callbackIdForState(oauthState());
      pc.ws.send(JSON.stringify(control(
        credentials,
        "OAUTH_FLOW_REGISTER",
        seq++,
        {
          schema_version: 1,
          callback_id: callbackId,
          flow_kind: "gmail",
          ttl_seconds: requested,
        },
      )));
      expect(errorCode(await pc.inbox.waitFor((message) => message.type === "ERROR")))
        .toBe("invalid_oauth_control");
    }

    const callbackId = await callbackIdForState(oauthState());
    pc.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_FLOW_REGISTER",
      seq,
      {
        schema_version: 1,
        callback_id: callbackId,
        flow_kind: "gmail",
        ttl_seconds: 165,
        unexpected: true,
      },
    )));
    expect(errorCode(await pc.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("invalid_oauth_control");
  });

  it("bounds OAuth control bursts independently from ordinary relay traffic", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    const callbackId = await callbackIdForState(state);
    const payload = {
      schema_version: 1,
      callback_id: callbackId,
      flow_kind: "gmail",
      ttl_seconds: 165,
    };
    for (let seq = 2; seq <= 9; seq++) {
      pc.ws.send(JSON.stringify(control(
        credentials, "OAUTH_FLOW_REGISTER", seq, payload,
      )));
      expect((await pc.inbox.waitFor((message) =>
        message.type === "OAUTH_FLOW_REGISTERED")).type)
        .toBe("OAUTH_FLOW_REGISTERED");
    }
    pc.ws.send(JSON.stringify(control(
      credentials, "OAUTH_FLOW_REGISTER", 10, payload,
    )));
    expect(errorCode(await pc.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("oauth_rate_limited");
  });
});

describe("durable callback lifecycle and mailbox", () => {
  it("accepts code and provider refusal, with neutral private browser responses", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");

    const codeState = oauthState();
    const codeRegistration = await register(pc, credentials, codeState, 2, "gmail");
    const codeValue = "private-synthetic-code";
    const codeResponse = await callbackRequest(codeState, {
      code: codeValue,
      scope: "ignored-provider-field",
    });
    expect(codeResponse.status).toBe(200);
    expect(codeResponse.headers.get("cache-control")).toBe("no-store");
    expect(codeResponse.headers.get("pragma")).toBe("no-cache");
    expect(codeResponse.headers.get("referrer-policy")).toBe("no-referrer");
    expect(codeResponse.headers.get("x-content-type-options")).toBe("nosniff");
    expect(codeResponse.headers.get("content-security-policy"))
      .toContain("default-src 'none'");
    const page = await codeResponse.text();
    expect(page).not.toContain(codeState);
    expect(page).not.toContain(codeValue);
    expect(page).not.toContain(codeRegistration.callbackId);
    expect(await pc.inbox.waitFor((message) => message.type === "OAUTH_CALLBACK"))
      .toMatchObject({
        payload: {
          callback_id: codeRegistration.callbackId,
          flow_kind: "gmail",
          code: codeValue,
        },
      });
    await mobile.inbox.expectNone((message) => message.type.startsWith("OAUTH_"));

    const errorState = oauthState();
    const errorRegistration = await register(pc, credentials, errorState, 3, "mcp");
    const refusal = await callbackRequest(errorState, {
      error: "access_denied",
      error_description: "private\u0000 description",
    });
    expect(refusal.status).toBe(200);
    const errorEvent = await pc.inbox.waitFor((message) =>
      message.type === "OAUTH_CALLBACK" &&
      message.payload.callback_id === errorRegistration.callbackId);
    expect(errorEvent.payload).toMatchObject({
      error: "access_denied",
      error_description: "private description",
    });
  });

  it("persists while PC is absent, replays after reconnect, and stops after ACK", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    const state = oauthState();
    const registration = await register(pc, credentials, state, 2);
    pc.ws.close(1000, "synthetic_disconnect");

    expect((await callbackRequest(state, { code: "offline-code" })).status).toBe(200);
    await mobile.inbox.expectNone((message) => message.type === "OAUTH_CALLBACK");

    const relayStub = env.RELAY_SESSION.getByName(credentials.pairId);
    await evictDurableObject(relayStub);
    const reconnected = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(reconnected, credentials, "pc");
    const replay = await reconnected.inbox.waitFor((message) =>
      message.type === "OAUTH_CALLBACK");
    expect(replay.payload.callback_id).toBe(registration.callbackId);

    reconnected.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_CALLBACK_ACK",
      2,
      {
        schema_version: 1,
        callback_id: registration.callbackId,
        disposition: "consumed",
      },
    )));
    reconnected.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_CALLBACK_ACK",
      3,
      {
        schema_version: 1,
        callback_id: registration.callbackId,
        disposition: "consumed",
      },
    )));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect((await callbackRequest(state, { code: "offline-code" })).status).toBe(410);

    const replacement = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(replacement, credentials, "pc");
    await replacement.inbox.expectNone((message) => message.type === "OAUTH_CALLBACK");
  });

  it("makes cancellation durable and removes a pending mailbox entry", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    const registration = await register(pc, credentials, state, 2);
    expect((await callbackRequest(state, { code: "pending-code" })).status).toBe(200);
    await pc.inbox.waitFor((message) => message.type === "OAUTH_CALLBACK");
    pc.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_FLOW_CANCEL",
      3,
      { schema_version: 1, callback_id: registration.callbackId },
    )));
    await new Promise((resolve) => setTimeout(resolve, 50));
    const relayStub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(relayStub, async (_instance, objectState) => {
      expect(await objectState.storage.get(
        `oauth:mailbox:${registration.callbackId}`,
      )).toBeUndefined();
    });
    expect((await callbackRequest(state, { code: "late-code" })).status).toBe(410);
  });

  it("allows exactly one of two competing callback submissions to win", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    await register(pc, credentials, state, 2);
    const responses = await Promise.all([
      callbackRequest(state, { code: "winner-a" }, `ip-${crypto.randomUUID()}`),
      callbackRequest(state, { code: "winner-b" }, `ip-${crypto.randomUUID()}`),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 410]);
  });

  it("keeps an equivalent duplicate callback and mailbox write idempotent", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    const registration = await register(pc, credentials, state, 2);
    expect((await callbackRequest(state, { code: "same-code" })).status).toBe(200);
    await pc.inbox.waitFor((message) => message.type === "OAUTH_CALLBACK");
    expect((await callbackRequest(state, { code: "same-code" })).status).toBe(200);
    const relayStub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(relayStub, async (_instance, objectState) => {
      const mailbox = await objectState.storage.list({ prefix: "oauth:mailbox:" });
      expect(mailbox.size).toBe(1);
      expect(mailbox.has(`oauth:mailbox:${registration.callbackId}`)).toBe(true);
    });
  });

  it("replays a pending callback only to the replacement authoritative PC", async () => {
    const credentials = await pair();
    const oldPc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(oldPc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    const state = oauthState();
    const registration = await register(oldPc, credentials, state, 2);
    expect((await callbackRequest(state, { code: "replacement-code" })).status)
      .toBe(200);
    await oldPc.inbox.waitFor((message) => message.type === "OAUTH_CALLBACK");

    const replacement = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(replacement, credentials, "pc");
    expect(errorCode(await oldPc.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("session_superseded");
    expect((await replacement.inbox.waitFor((message) =>
      message.type === "OAUTH_CALLBACK")).payload.callback_id)
      .toBe(registration.callbackId);
    await mobile.inbox.expectNone((message) => message.type.startsWith("OAUTH_"));
  });

  it("enforces the four-entry pending mailbox quota", async () => {
    const credentials = await pair();
    const relayStub = env.RELAY_SESSION.getByName(credentials.pairId);
    const now = Date.now();
    const callbackIds = await Promise.all(
      Array.from({ length: 5 }, () => callbackIdForState(oauthState())),
    );
    await runInDurableObject(relayStub, async (instance, objectState) => {
      await objectState.storage.put("auth_hash", credentials.pairId);
      for (let index = 0; index < 5; index++) {
        await objectState.storage.put(`oauth:flow:${callbackIds[index]}`, {
          schema_version: 1,
          callback_id: callbackIds[index],
          flow_kind: "gmail",
          created_at: now,
          expires_at: now + 165_000,
          registration_pending: false,
        });
        if (index < 4) {
          await objectState.storage.put(`oauth:mailbox:${callbackIds[index]}`, {
            schema_version: 1,
            callback_id: callbackIds[index],
            flow_kind: "gmail",
            code: `code-${index}`,
            created_at: now,
            expires_at: now + 165_000,
          });
        }
      }
      expect((await instance.enqueueOAuthCallback({
        schema_version: 1,
        pair_id: credentials.pairId,
        callback_id: callbackIds[4],
        flow_kind: "gmail",
        code: "fifth-code",
        created_at: now,
        expires_at: now + 165_000,
      })).status).toBe("quota");
    });
  });

  it("returns 410 after expiry without retaining callback content", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    const registration = await register(pc, credentials, state, 2);
    expect((await callbackRequest(state, { code: "expired-code" })).status).toBe(200);
    await pc.inbox.waitFor((message) => message.type === "OAUTH_CALLBACK");
    const flowStub = env.OAUTH_CALLBACK_FLOW.getByName(registration.callbackId);
    await runInDurableObject(flowStub, async (_instance, objectState) => {
      const flow = await objectState.storage.get("oauth:flow");
      await objectState.storage.put("oauth:flow", {
        ...flow,
        expires_at: Date.now() - 1,
      });
      await objectState.storage.setAlarm(Date.now() + 1000);
    });
    expect(await runDurableObjectAlarm(flowStub)).toBe(true);
    expect((await callbackRequest(state, { code: "expired-code" })).status).toBe(410);
    await runInDurableObject(flowStub, async (_instance, objectState) => {
      expect(await objectState.storage.get("oauth:flow")).toBeUndefined();
    });
    const relayStub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(relayStub, async (_instance, objectState) => {
      expect(await objectState.storage.get(
        `oauth:mailbox:${registration.callbackId}`,
      )).toBeUndefined();
    });
  });
});

describe("inter-Durable-Object reliability", () => {
  it("retries a failed Flow-to-mailbox delivery through the alarm", async () => {
    const callbackId = await callbackIdForState(oauthState());
    const flowStub = env.OAUTH_CALLBACK_FLOW.getByName(callbackId);
    let attempts = 0;
    const syntheticMailbox = new Map();
    await runInDurableObject(flowStub, async (instance, objectState) => {
      instance.relayStub = () => ({
        async enqueueOAuthCallback(entry) {
          attempts++;
          const duplicate = syntheticMailbox.has(entry.callback_id);
          syntheticMailbox.set(entry.callback_id, entry);
          if (attempts === 1) throw new Error("synthetic response loss");
          return { status: duplicate ? "duplicate" : "enqueued" };
        },
      });
      expect((await instance.registerFlow({
        schema_version: 1,
        callback_id: callbackId,
        pair_id: "a".repeat(64),
        flow_kind: "gmail",
        ttl_seconds: 165,
      })).status).toBe("registered");
      expect((await instance.submitCallback({
        schema_version: 1,
        callback_id: callbackId,
        code: "synthetic-code",
      })).status).toBe("accepted");
      const flow = await objectState.storage.get("oauth:flow");
      await objectState.storage.put("oauth:flow", {
        ...flow,
        next_retry_at: Date.now() - 1,
      });
      await objectState.storage.setAlarm(Date.now() + 1000);
    });
    expect(await runDurableObjectAlarm(flowStub)).toBe(true);
    expect(attempts).toBe(2);
    expect(syntheticMailbox.size).toBe(1);
    await runInDurableObject(flowStub, async (_instance, objectState) => {
      expect((await objectState.storage.get("oauth:flow")).status).toBe("enqueued");
    });
  });

  it("retries a failed mailbox-to-Flow ACK idempotently", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    const state = oauthState();
    const registration = await register(pc, credentials, state, 2);
    expect((await callbackRequest(state, { code: "ack-code" })).status).toBe(200);
    await pc.inbox.waitFor((message) => message.type === "OAUTH_CALLBACK");
    const relayStub = env.RELAY_SESSION.getByName(credentials.pairId);
    let attempts = 0;
    let syntheticDisposition = null;
    await runInDurableObject(relayStub, (instance) => {
      instance.flowStub = () => ({
        async acknowledgeCallback(command) {
          attempts++;
          expect(syntheticDisposition === null ||
            syntheticDisposition === command.disposition).toBe(true);
          syntheticDisposition = command.disposition;
          if (attempts === 1) throw new Error("synthetic ACK response loss");
          return { status: "acknowledged" };
        },
      });
    });
    pc.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_CALLBACK_ACK",
      3,
      {
        schema_version: 1,
        callback_id: registration.callbackId,
        disposition: "consumed",
      },
    )));
    await new Promise((resolve) => setTimeout(resolve, 50));
    pc.ws.send(JSON.stringify(control(
      credentials,
      "OAUTH_CALLBACK_ACK",
      4,
      {
        schema_version: 1,
        callback_id: registration.callbackId,
        disposition: "rejected",
      },
    )));
    expect(errorCode(await pc.inbox.waitFor((message) => message.type === "ERROR")))
      .toBe("oauth_flow_conflict");
    await runInDurableObject(relayStub, async (_instance, objectState) => {
      const key = `oauth:ack:${registration.callbackId}`;
      const ack = await objectState.storage.get(key);
      await objectState.storage.put(key, { ...ack, next_retry_at: Date.now() - 1 });
      await objectState.storage.setAlarm(Date.now() + 1000);
    });
    expect(await runDurableObjectAlarm(relayStub)).toBe(true);
    expect(attempts).toBe(2);
    expect(syntheticDisposition).toBe("consumed");
    await runInDurableObject(relayStub, async (_instance, objectState) => {
      expect(await objectState.storage.get(`oauth:ack:${registration.callbackId}`))
        .toBeUndefined();
      expect(await objectState.storage.get(`oauth:mailbox:${registration.callbackId}`))
        .toBeUndefined();
    });
  });

  it("clears callback content before retrying failed expiry cleanup", async () => {
    const callbackId = await callbackIdForState(oauthState());
    const flowStub = env.OAUTH_CALLBACK_FLOW.getByName(callbackId);
    let cleanupAttempts = 0;
    await runInDurableObject(flowStub, async (instance, objectState) => {
      instance.relayStub = () => ({
        async enqueueOAuthCallback() {
          return { status: "enqueued" };
        },
        async removeOAuthCallback() {
          cleanupAttempts++;
          if (cleanupAttempts === 1) throw new Error("synthetic cleanup failure");
          return { status: "removed" };
        },
      });
      await instance.registerFlow({
        schema_version: 1,
        callback_id: callbackId,
        pair_id: "b".repeat(64),
        flow_kind: "mcp",
        ttl_seconds: 165,
      });
      await instance.submitCallback({
        schema_version: 1,
        callback_id: callbackId,
        code: "must-be-cleared",
      });
      const flow = await objectState.storage.get("oauth:flow");
      await objectState.storage.put("oauth:flow", {
        ...flow,
        expires_at: Date.now() - 1,
      });
      await objectState.storage.setAlarm(Date.now() + 1000);
    });
    expect(await runDurableObjectAlarm(flowStub)).toBe(true);
    await runInDurableObject(flowStub, async (_instance, objectState) => {
      const expired = await objectState.storage.get("oauth:flow");
      expect(expired.status).toBe("expired");
      expect(expired.callback).toBeNull();
      expect(JSON.stringify(expired)).not.toContain("must-be-cleared");
      await objectState.storage.put("oauth:flow", {
        ...expired,
        next_retry_at: Date.now() - 1,
      });
      await objectState.storage.setAlarm(Date.now() + 1000);
    });
    expect(await runDurableObjectAlarm(flowStub)).toBe(true);
    expect(cleanupAttempts).toBe(2);
    await runInDurableObject(flowStub, async (_instance, objectState) => {
      expect(await objectState.storage.get("oauth:flow")).toBeUndefined();
    });
  });
});

describe("OAuth callback privacy", () => {
  it("redacts every forbidden OAuth observability field", () => {
    const privateValues = {
      state: "private-state",
      code: "private-code",
      error_description: "private-description",
      callback_id: "private-callback",
      flow_ref: "private-flow",
      request_url: "https://private.invalid/?secret=yes",
      query_string: "state=private",
      authorization: "Bearer private",
      cookie: "private-cookie",
      relay_secret: "private-relay-secret",
      pair_proof: "private-pair-proof",
      oauth_payload: "private-oauth-payload",
    };
    const encoded = JSON.stringify(sanitizeRelayLogData({
      ...privateValues,
      nested: { state: privateValues.state, code: privateValues.code },
    }));
    for (const value of Object.values(privateValues)) {
      expect(encoded).not.toContain(value);
    }
  });

  it("exposes both Durable Object bindings and the callback limiter locally", () => {
    expect(env.RELAY_SESSION).toBeDefined();
    expect(env.OAUTH_CALLBACK_FLOW).toBeDefined();
    expect(env.OAUTH_CALLBACK_LIMITER).toBeDefined();
  });
});
