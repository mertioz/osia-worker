import { env } from "cloudflare:workers";
import {
  evictDurableObject,
  runInDurableObject,
  SELF,
} from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";

import relayWorker, { classifyRelayUrl } from "../src/relay.js";
import {
  RELAY_GUARD_REQUIRED_VARS,
  validateRelayGuardEnvironment,
} from "../src/relay_guard.js";

const openedSockets = [];

function createInbox(ws) {
  const messages = [];
  const waiters = [];
  let closeEvent = null;
  const closeWaiters = [];
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
  ws.addEventListener("close", (event) => {
    closeEvent = event;
    for (const waiter of closeWaiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.resolve(event);
    }
  });
  return {
    async waitFor(predicate, timeoutMs = 1500) {
      const index = messages.findIndex(predicate);
      if (index >= 0) return messages.splice(index, 1)[0];
      return new Promise((resolve, reject) => {
        const waiter = { predicate, resolve, timer: null };
        waiter.timer = setTimeout(() => {
          const waiterIndex = waiters.indexOf(waiter);
          if (waiterIndex >= 0) waiters.splice(waiterIndex, 1);
          reject(new Error("timed out waiting for relay message"));
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
    async expectNone(predicate, timeoutMs = 100) {
      const index = messages.findIndex(predicate);
      if (index >= 0) throw new Error(`unexpected message: ${JSON.stringify(messages[index])}`);
      await new Promise((resolve, reject) => {
        const waiter = {
          predicate,
          resolve: (value) => reject(new Error(`unexpected message: ${JSON.stringify(value)}`)),
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
    async waitForClose(timeoutMs = 1500) {
      if (closeEvent) return closeEvent;
      return new Promise((resolve, reject) => {
        const waiter = { resolve, timer: null };
        waiter.timer = setTimeout(() => {
          const index = closeWaiters.indexOf(waiter);
          if (index >= 0) closeWaiters.splice(index, 1);
          reject(new Error("timed out waiting for relay close"));
        }, timeoutMs);
        closeWaiters.push(waiter);
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
  const secret = `relay-test-${crypto.randomUUID()}`;
  return { secret, pairId: await sha256Hex(secret) };
}

function v1Url(pairId, role, deviceId, sessionId) {
  return `https://relay.test/ws?role=${role}&pair_id=${pairId}` +
    `&device_id=${deviceId}&session_id=${sessionId}`;
}

function v2Url(pairId) {
  return `https://relay.test/ws?pair_id=${pairId}`;
}

async function openSocket(url) {
  const response = await SELF.fetch(url, {
    headers: { Upgrade: "websocket" },
  });
  expect(response.status).toBe(101);
  expect(response.webSocket).not.toBeNull();
  const ws = response.webSocket;
  ws.accept();
  openedSockets.push(ws);
  return { ws, inbox: createInbox(ws) };
}

function v1Message({
  type,
  pairId,
  role,
  deviceId,
  sessionId,
  seq,
  payload = {},
  ...extra
}) {
  return {
    v: 1,
    type,
    role,
    pair_id: pairId,
    device_id: deviceId,
    session_id: sessionId,
    seq,
    ack: 0,
    payload,
    ...extra,
  };
}

function v2Message(message) {
  const { type, pairId, role, seq, payload, ...extra } = message;
  return {
    v: 2,
    type,
    role,
    pair_id: pairId,
    seq,
    ack: 0,
    ...(Object.hasOwn(message, "payload") ? { payload } : {}),
    ...extra,
  };
}

function v2Chunk(credentials, {
  role = "pc",
  seq,
  chunkId,
  chunkIndex = 0,
  chunkCount = 2,
  totalBytes = 40961,
  chunkChars = 40960,
} = {}) {
  return v2Message({
    type: "E2E_CHUNK",
    pairId: credentials.pairId,
    role,
    seq,
    e2e_version: 1,
    alg: "CHACHA20-POLY1305",
    kid: "K".repeat(22),
    frame_seq: seq - chunkIndex,
    priority: "normal",
    final: false,
    nonce: "N".repeat(16),
    chunk_id: chunkId,
    chunk_index: chunkIndex,
    chunk_count: chunkCount,
    total_bytes: totalBytes,
    ciphertext_chunk: "X".repeat(chunkChars),
  });
}

async function authenticateV1(connection, credentials, identity) {
  connection.ws.send(JSON.stringify(v1Message({
    type: "PAIR_START",
    pairId: credentials.pairId,
    role: identity.role,
    deviceId: identity.deviceId,
    sessionId: identity.sessionId,
    seq: 1,
    payload: { secret: credentials.secret },
  })));
  return connection.inbox.waitFor((msg) => msg.type === "PAIR_CONFIRM");
}

function sendV2PairStart(connection, credentials, role, overrides = {}) {
  connection.ws.send(JSON.stringify({
    v: 2,
    type: "PAIR_START",
    role,
    pair_id: credentials.pairId,
    seq: 1,
    ack: 0,
    payload: { secret: credentials.secret },
    ...overrides,
  }));
}

async function authenticateV2(connection, credentials, role) {
  sendV2PairStart(connection, credentials, role);
  return connection.inbox.waitFor((msg) => msg.type === "PAIR_CONFIRM");
}

async function enforceGuard(credentials, overrides = {}) {
  const stub = env.RELAY_SESSION.getByName(credentials.pairId);
  await runInDurableObject(stub, (instance, state) => {
    instance.guard = {
      ...instance.guard,
      mode: "enforce",
      enforce: true,
      ...overrides,
    };
    instance.roleBudgets.clear();
    for (const server of state.getWebSockets()) {
      const meta = server.deserializeAttachment();
      meta.guard_buckets = {};
      server.serializeAttachment(meta);
    }
  });
  return stub;
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

describe("relay upgrade classification", () => {
  it("accepts exact v1 and pair-only v2 URLs", async () => {
    const credentials = await pair();
    const v1 = await openSocket(v1Url(
      credentials.pairId,
      "pc",
      "pc-device-1234",
      "pc-session-1234",
    ));
    const v2 = await openSocket(v2Url(credentials.pairId));
    expect(v1.ws.readyState).toBe(WebSocket.OPEN);
    expect(v2.ws.readyState).toBe(WebSocket.OPEN);
  });

  it.each([
    ["missing pair", "https://relay.test/ws", "invalid_pair_route"],
    ["invalid pair", "https://relay.test/ws?pair_id=ABC", "invalid_pair_route"],
    ["partial v1", `https://relay.test/ws?pair_id=${"a".repeat(64)}&role=pc`, "invalid_request_shape"],
    ["unknown query", `https://relay.test/ws?pair_id=${"a".repeat(64)}&tracking=x`, "invalid_request_shape"],
    ["duplicate query", `https://relay.test/ws?pair_id=${"a".repeat(64)}&pair_id=${"b".repeat(64)}`, "invalid_request_shape"],
  ])("rejects %s", async (_name, url, code) => {
    const response = await SELF.fetch(url, { headers: { Upgrade: "websocket" } });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ ok: false, error: code });
  });

  it("rejects fragments and URL credentials when directly observable", () => {
    expect(classifyRelayUrl(`https://relay.test/ws?pair_id=${"a".repeat(64)}#device_id=x`))
      .toEqual({ error: "invalid_request_shape" });
    expect(classifyRelayUrl(`https://user@relay.test/ws?pair_id=${"a".repeat(64)}`))
      .toEqual({ error: "invalid_request_shape" });
  });
});

describe("pre-Durable-Object abuse guardrails", () => {
  function fakeEnv({ mode = "enforce", accept = "true", limit } = {}) {
    const observed = { durableObjectLookups: 0, limiterCalls: 0 };
    const localEnv = {
      ...Object.fromEntries(
        RELAY_GUARD_REQUIRED_VARS.map((variable) => [variable, env[variable]]),
      ),
      RELAY_GUARD_MODE: mode,
      RELAY_ACCEPT_NEW_SESSIONS: accept,
      RELAY_UPGRADE_LIMITER: {
        async limit() {
          observed.limiterCalls++;
          return { success: limit ? limit(observed.limiterCalls) : true };
        },
      },
      RELAY_SESSION: {
        getByName() {
          observed.durableObjectLookups++;
          return { fetch: async () => new Response(null, { status: 204 }) };
        },
      },
    };
    return { localEnv, observed };
  }

  it.each([
    ["method", "POST", "/ws?pair_id=" + "a".repeat(64), "websocket", 404],
    ["path", "GET", "/other?pair_id=" + "a".repeat(64), "websocket", 404],
    ["upgrade", "GET", "/ws?pair_id=" + "a".repeat(64), "false", 426],
    ["query", "GET", "/ws?pair_id=invalid", "websocket", 400],
  ])("rejects malformed %s before namespace access", async (
    _name,
    method,
    path,
    upgrade,
    status,
  ) => {
    const { localEnv, observed } = fakeEnv();
    const response = await relayWorker.fetch(new Request(`https://relay.test${path}`, {
      method,
      headers: { Upgrade: upgrade },
    }), localEnv);
    expect(response.status).toBe(status);
    expect(observed.durableObjectLookups).toBe(0);
    expect(observed.limiterCalls).toBe(0);
  });

  it("exposes every production guard variable and the native limiter binding", () => {
    const validation = validateRelayGuardEnvironment(env);
    expect(validation.valid).toBe(true);
    expect(validation.guard.mode).toBe("enforce");
  });

  it("bounds random valid-looking pair attempts before namespace access", async () => {
    const { localEnv, observed } = fakeEnv({ limit: (call) => call <= 2 });
    const statuses = [];
    for (let index = 0; index < 4; index++) {
      const pairId = index.toString(16).padStart(64, "0");
      const response = await relayWorker.fetch(new Request(
        `https://relay.test/ws?pair_id=${pairId}`,
        {
          headers: {
            Upgrade: "websocket",
            "CF-Connecting-IP": "test-actor",
          },
        },
      ), localEnv);
      statuses.push(response.status);
    }
    expect(statuses).toEqual([204, 204, 429, 429]);
    expect(observed.limiterCalls).toBe(4);
    expect(observed.durableObjectLookups).toBe(2);
  });

  it("keeps rate-limit decisions observational by default", async () => {
    const { localEnv, observed } = fakeEnv({
      mode: "observe",
      limit: () => false,
    });
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"a".repeat(64)}`,
      {
        headers: {
          Upgrade: "websocket",
          "CF-Connecting-IP": "test-actor",
        },
      },
    ), localEnv);
    expect(response.status).toBe(204);
    expect(observed.durableObjectLookups).toBe(1);
  });

  it("off mode bypasses the upgrade limiter while preserving the relay", async () => {
    const { localEnv, observed } = fakeEnv({
      mode: "off",
      limit: () => false,
    });
    delete localEnv.RELAY_POSTAUTH_BYTE_BURST;
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"a".repeat(64)}`,
      {
        headers: {
          Upgrade: "websocket",
          "CF-Connecting-IP": "test-actor",
        },
      },
    ), localEnv);
    expect(response.status).toBe(204);
    expect(observed.limiterCalls).toBe(0);
    expect(observed.durableObjectLookups).toBe(1);
  });

  it("fails open if the optional edge limiter is unavailable", async () => {
    const { localEnv, observed } = fakeEnv();
    localEnv.RELAY_UPGRADE_LIMITER.limit = async () => {
      observed.limiterCalls++;
      throw new Error("limiter unavailable");
    };
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"a".repeat(64)}`,
      {
        headers: {
          Upgrade: "websocket",
          "CF-Connecting-IP": "test-actor",
        },
      },
    ), localEnv);
    expect(response.status).toBe(204);
    expect(observed.limiterCalls).toBe(1);
    expect(observed.durableObjectLookups).toBe(1);
  });

  it("fails open at runtime if the predeployment-validated limiter binding is missing", async () => {
    const { localEnv, observed } = fakeEnv();
    delete localEnv.RELAY_UPGRADE_LIMITER;
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"a".repeat(64)}`,
      {
        headers: {
          Upgrade: "websocket",
          "CF-Connecting-IP": "test-actor",
        },
      },
    ), localEnv);
    expect(response.status).toBe(204);
    expect(observed.limiterCalls).toBe(0);
    expect(observed.durableObjectLookups).toBe(1);
  });

  it.each([
    ["missing", undefined],
    ["malformed", "invalid"],
    ["zero", "0"],
    ["negative", "-1"],
    ["out of range", String(64 * 1024 * 1024 + 1)],
  ])("rejects %s enforce configuration before namespace access", async (
    _label,
    value,
  ) => {
    const { localEnv, observed } = fakeEnv();
    if (value === undefined) delete localEnv.RELAY_POSTAUTH_BYTE_BURST;
    else localEnv.RELAY_POSTAUTH_BYTE_BURST = value;
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"a".repeat(64)}`,
      { headers: { Upgrade: "websocket" } },
    ), localEnv);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      ok: false,
      error: "relay_configuration_invalid",
    });
    expect(observed.durableObjectLookups).toBe(0);
    expect(observed.limiterCalls).toBe(0);
  });

  it("can disable new upgrades without touching existing sockets", async () => {
    const { localEnv, observed } = fakeEnv({ accept: "false" });
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"a".repeat(64)}`,
      { headers: { Upgrade: "websocket" } },
    ), localEnv);
    expect(response.status).toBe(503);
    expect(observed.durableObjectLookups).toBe(0);
  });

  it("keeps an authenticated socket usable while new sessions are disabled", async () => {
    const credentials = await pair();
    const existing = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(existing, credentials, "pc");

    const { localEnv } = fakeEnv({ accept: "false" });
    const response = await relayWorker.fetch(new Request(
      `https://relay.test/ws?pair_id=${"b".repeat(64)}`,
      { headers: { Upgrade: "websocket" } },
    ), localEnv);
    expect(response.status).toBe(503);

    existing.ws.send(JSON.stringify(v2Message({
      type: "PING",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
    })));
    expect(await existing.inbox.waitFor((msg) => msg.type === "PONG"))
      .toMatchObject({ type: "PONG", ack: 2 });
  });
});

describe("route-bound authentication", () => {
  it("accepts a valid proof and exposes no v2 role before PAIR_START", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, (_instance, state) => {
      const [server] = state.getWebSockets();
      const meta = server.deserializeAttachment();
      expect(meta.protocol_version).toBe(2);
      expect(meta.role).toBeNull();
      expect(meta.authenticated).toBe(false);
      expect(meta.generation).toBeNull();
    });

    const confirm = await authenticateV2(connection, credentials, "pc");
    expect(confirm.payload).toMatchObject({
      relay_protocol_version: 2,
      identity_mode: "role_authority",
    });
    expect(confirm).not.toHaveProperty("device_id");
    expect(confirm).not.toHaveProperty("session_id");
  });

  it("rejects a wrong first claimant without poisoning storage", async () => {
    const credentials = await pair();
    const attacker = await openSocket(v2Url(credentials.pairId));
    sendV2PairStart(attacker, {
      ...credentials,
      secret: "wrong-route-proof",
    }, "pc");
    const error = await attacker.inbox.waitFor((msg) => msg.type === "ERROR");
    expect(errorCode(error)).toBe("pair_proof_mismatch");
    expect(error).not.toHaveProperty("pair_id");

    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("auth_hash")).toBeUndefined();
    });

    const legitimate = await openSocket(v2Url(credentials.pairId));
    await expect(authenticateV2(legitimate, credentials, "pc"))
      .resolves.toMatchObject({ type: "PAIR_CONFIRM" });
  });

  it("repairs inconsistent legacy state only after a valid route proof", async () => {
    const credentials = await pair();
    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put("auth_hash", "0".repeat(64));
    });
    const connection = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(connection, credentials, "mobile");
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("auth_hash")).toBe(credentials.pairId);
    });
  });

  it("rejects invalid roles, unexpected PAIR_START identity, and non-PAIR_START first frames", async () => {
    const credentials = await pair();
    const invalidRole = await openSocket(v2Url(credentials.pairId));
    sendV2PairStart(invalidRole, credentials, "tablet");
    expect(errorCode(await invalidRole.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("invalid_role");

    const extraIdentity = await openSocket(v2Url(credentials.pairId));
    sendV2PairStart(extraIdentity, credentials, "pc", { device_id: "forbidden-device" });
    expect(errorCode(await extraIdentity.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("invalid_pair_route");

    const wrongFirst = await openSocket(v2Url(credentials.pairId));
    wrongFirst.ws.send(JSON.stringify(v2Message({
      type: "PING",
      pairId: credentials.pairId,
      role: "pc",
      seq: 1,
    })));
    expect(errorCode(await wrongFirst.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("not_paired");
  });
});

describe("protocol isolation and routing", () => {
  it("preserves v1-to-v1 E2E routing", async () => {
    const credentials = await pair();
    const pcIdentity = { role: "pc", deviceId: "pc-device-1234", sessionId: "pc-session-1234" };
    const mobileIdentity = { role: "mobile", deviceId: "mobile-device-1234", sessionId: "mobile-session-1234" };
    const pc = await openSocket(v1Url(credentials.pairId, ...Object.values(pcIdentity)));
    const mobile = await openSocket(v1Url(credentials.pairId, ...Object.values(mobileIdentity)));
    await authenticateV1(pc, credentials, pcIdentity);
    await authenticateV1(mobile, credentials, mobileIdentity);

    const frame = v1Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      ...pcIdentity,
      seq: 2,
      e2e_version: 1,
      alg: "CHACHA20-POLY1305",
      kid: "K".repeat(22),
      from: pcIdentity.deviceId,
      to: mobileIdentity.deviceId,
      priority: "normal",
      final: false,
      nonce: "N".repeat(16),
      ciphertext: "opaque-v1-ciphertext",
    });
    pc.ws.send(JSON.stringify(frame));
    expect(await mobile.inbox.waitFor((msg) => msg.type === "E2E_FRAME"))
      .toEqual(frame);

    const chunk = v1Message({
      type: "E2E_CHUNK",
      pairId: credentials.pairId,
      ...pcIdentity,
      seq: 3,
      e2e_version: 1,
      alg: "CHACHA20-POLY1305",
      kid: "K".repeat(22),
      from: pcIdentity.deviceId,
      to: mobileIdentity.deviceId,
      to_session_id: mobileIdentity.sessionId,
      frame_seq: 3,
      priority: "normal",
      final: false,
      nonce: "N".repeat(16),
      chunk_id: "C".repeat(22),
      chunk_index: 0,
      chunk_count: 1,
      total_bytes: 10,
      ciphertext_chunk: "X".repeat(10),
    });
    delete chunk.payload;
    pc.ws.send(JSON.stringify(chunk));
    expect(await mobile.inbox.waitFor((msg) => msg.type === "E2E_CHUNK"))
      .toEqual(chunk);
  });

  it("restores pre-transition v1 attachments after hibernation", async () => {
    const credentials = await pair();
    const identity = { role: "pc", deviceId: "pc-device-1234", sessionId: "pc-session-1234" };
    const connection = await openSocket(v1Url(credentials.pairId, ...Object.values(identity)));
    await authenticateV1(connection, credentials, identity);
    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, (_instance, state) => {
      const [server] = state.getWebSockets();
      const legacyMeta = server.deserializeAttachment();
      delete legacyMeta.protocol_version;
      delete legacyMeta.authoritative;
      delete legacyMeta.superseded;
      delete legacyMeta.blocked;
      delete legacyMeta.generation;
      server.serializeAttachment(legacyMeta);
    });
    await evictDurableObject(stub);

    connection.ws.send(JSON.stringify(v1Message({
      type: "PING",
      pairId: credentials.pairId,
      ...identity,
      seq: 2,
    })));
    expect(await connection.inbox.waitFor((msg) => msg.type === "PONG"))
      .toMatchObject({ v: 1, type: "PONG", ack: 2 });
  });

  it("routes every v2 E2E type to exactly one authoritative peer", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");

    const hello = v2Message({
      type: "E2E_HELLO",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
      payload: { public_key: "opaque-key", nonce_base: "opaque-base" },
    });
    pc.ws.send(JSON.stringify(hello));
    expect(await mobile.inbox.waitFor((msg) => msg.type === "E2E_HELLO")).toEqual(hello);
    await mobile.inbox.expectNone((msg) => msg.type === "E2E_HELLO");
    await pc.inbox.expectNone((msg) => msg.type === "E2E_HELLO");

    const ready = v2Message({
      type: "E2E_READY",
      pairId: credentials.pairId,
      role: "mobile",
      seq: 2,
      payload: { confirmation: "opaque-confirmation" },
    });
    mobile.ws.send(JSON.stringify(ready));
    expect(await pc.inbox.waitFor((msg) => msg.type === "E2E_READY")).toEqual(ready);

    const frame = v2Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      role: "pc",
      seq: 3,
      e2e_version: 1,
      alg: "CHACHA20-POLY1305",
      kid: "K".repeat(22),
      priority: "critical",
      final: false,
      nonce: "N".repeat(16),
      ciphertext: "opaque-v2-ciphertext",
    });
    pc.ws.send(JSON.stringify(frame));
    expect(await mobile.inbox.waitFor((msg) => msg.type === "E2E_FRAME")).toEqual(frame);

    const chunk = v2Message({
      type: "E2E_CHUNK",
      pairId: credentials.pairId,
      role: "pc",
      seq: 4,
      e2e_version: 1,
      alg: "CHACHA20-POLY1305",
      kid: "K".repeat(22),
      frame_seq: 4,
      priority: "normal",
      final: false,
      nonce: "N".repeat(16),
      chunk_id: "C".repeat(22),
      chunk_index: 0,
      chunk_count: 1,
      total_bytes: 10,
      ciphertext_chunk: "X".repeat(10),
    });
    pc.ws.send(JSON.stringify(chunk));
    expect(await mobile.inbox.waitFor((msg) => msg.type === "E2E_CHUNK")).toEqual(chunk);
  });

  it.each([
    [1, 2],
    [2, 1],
  ])("rejects mixed v%s PC and v%s mobile", async (pcVersion, mobileVersion) => {
    const credentials = await pair();
    const pcIdentity = { role: "pc", deviceId: "pc-device-1234", sessionId: "pc-session-1234" };
    const mobileIdentity = { role: "mobile", deviceId: "mobile-device-1234", sessionId: "mobile-session-1234" };
    const pc = pcVersion === 1
      ? await openSocket(v1Url(credentials.pairId, ...Object.values(pcIdentity)))
      : await openSocket(v2Url(credentials.pairId));
    const mobile = mobileVersion === 1
      ? await openSocket(v1Url(credentials.pairId, ...Object.values(mobileIdentity)))
      : await openSocket(v2Url(credentials.pairId));

    if (pcVersion === 1) await authenticateV1(pc, credentials, pcIdentity);
    else await authenticateV2(pc, credentials, "pc");

    if (mobileVersion === 1) {
      mobile.ws.send(JSON.stringify(v1Message({
        type: "PAIR_START",
        pairId: credentials.pairId,
        ...mobileIdentity,
        seq: 1,
        payload: { secret: credentials.secret },
      })));
    } else {
      sendV2PairStart(mobile, credentials, "mobile");
    }

    expect(errorCode(await pc.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("update_required");
    expect(errorCode(await mobile.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("update_required");
    const routedOrReady = (msg) => msg.type.startsWith("E2E_") ||
      msg.type === "PC_READY" || msg.type === "MOBILE_READY";
    await pc.inbox.expectNone(routedOrReady);
    await mobile.inbox.expectNone(routedOrReady);
  });
});

describe("v2 authority, replay, and hibernation", () => {
  it("supersedes an older same-role socket and preserves the current peer", async () => {
    const credentials = await pair();
    const oldPc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(oldPc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");

    const newPc = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(newPc, credentials, "pc");
    expect(errorCode(await oldPc.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("session_superseded");

    const frame = v2Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
      e2e_version: 1,
      alg: "CHACHA20-POLY1305",
      kid: "K".repeat(22),
      priority: "normal",
      final: false,
      nonce: "N".repeat(16),
      ciphertext: "new-authority-only",
    });
    newPc.ws.send(JSON.stringify(frame));
    expect(await mobile.inbox.waitFor((msg) => msg.ciphertext === "new-authority-only"))
      .toEqual(frame);
    await newPc.inbox.expectNone((msg) => msg.type === "DISCONNECT");

    const reverse = v2Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      role: "mobile",
      seq: 2,
      ciphertext: "current-pc-only",
    });
    mobile.ws.send(JSON.stringify(reverse));
    expect(await newPc.inbox.waitFor((msg) => msg.ciphertext === "current-pc-only"))
      .toEqual(reverse);
    await oldPc.inbox.expectNone((msg) => msg.ciphertext === "current-pc-only");

    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, (_instance, state) => {
      const current = state.getWebSockets()
        .map((server) => server.deserializeAttachment())
        .filter((meta) => meta.protocol_version === 2 && meta.authoritative === true);
      expect(current).toHaveLength(2);
      expect(new Set(current.map((meta) => meta.role))).toEqual(new Set(["pc", "mobile"]));
      expect(current.every((meta) => Number.isSafeInteger(meta.generation))).toBe(true);
    });
  });

  it("rejects stale frames and stale close callbacks from attachment state", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    const staleClient = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");

    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, async (instance, state) => {
      const staleServer = state.getWebSockets().find((server) => {
        const meta = server.deserializeAttachment();
        return meta.protocol_version === 2 && meta.authenticated === false;
      });
      expect(staleServer).toBeDefined();
      const staleMeta = staleServer.deserializeAttachment();
      Object.assign(staleMeta, {
        role: "pc",
        authenticated: true,
        generation: 0,
        authoritative: true,
        superseded: false,
        last_seq: 1,
      });
      staleServer.serializeAttachment(staleMeta);
      await instance.webSocketClose(staleServer, 1006, "");
      await instance.webSocketMessage(staleServer, JSON.stringify(v2Message({
        type: "E2E_FRAME",
        pairId: credentials.pairId,
        role: "pc",
        seq: 2,
        ciphertext: "must-not-route",
      })));
    });
    await mobile.inbox.expectNone((msg) =>
      msg.ciphertext === "must-not-route" || msg.type === "DISCONNECT");
    expect(staleClient.ws.readyState).not.toBe(WebSocket.OPEN);
  });

  it("restores authoritative routing from serialized attachments after eviction", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    const stub = env.RELAY_SESSION.getByName(credentials.pairId);

    await evictDurableObject(stub);
    const frame = v2Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
      ciphertext: "after-hibernation",
    });
    pc.ws.send(JSON.stringify(frame));
    expect(await mobile.inbox.waitFor((msg) => msg.ciphertext === "after-hibernation"))
      .toEqual(frame);
  });

  it("rejects v2 resume without changing the monotonic sequence", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(connection, credentials, "pc");
    connection.ws.send(JSON.stringify(v2Message({
      type: "RECONNECT_RESUME",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
    })));
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("resume_not_supported");

    connection.ws.send(JSON.stringify(v2Message({
      type: "PING",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
    })));
    expect(await connection.inbox.waitFor((msg) => msg.type === "PONG"))
      .toMatchObject({ type: "PONG", ack: 2 });

    connection.ws.send(JSON.stringify(v2Message({
      type: "PONG",
      pairId: credentials.pairId,
      role: "pc",
      seq: 3,
    })));
    await connection.inbox.expectNone((msg) =>
      msg.type === "PING" || msg.type === "PONG" || msg.type === "E2E_HELLO");
  });

  it("does not allow legacy resume to roll sequence backward", async () => {
    const credentials = await pair();
    const identity = { role: "pc", deviceId: "pc-device-1234", sessionId: "pc-session-1234" };
    const connection = await openSocket(v1Url(credentials.pairId, ...Object.values(identity)));
    await authenticateV1(connection, credentials, identity);
    connection.ws.send(JSON.stringify(v1Message({
      type: "PING",
      pairId: credentials.pairId,
      ...identity,
      seq: 2,
    })));
    await connection.inbox.waitFor((msg) => msg.type === "PONG");
    connection.ws.send(JSON.stringify(v1Message({
      type: "RECONNECT_RESUME",
      pairId: credentials.pairId,
      ...identity,
      seq: 1,
    })));
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("replay_rejected");
  });
});

describe("bounded relay abuse behavior", () => {
  it("closes an unauthenticated socket after the bounded handshake deadline", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, async (instance, state) => {
      instance.guard = { ...instance.guard, mode: "enforce", enforce: true };
      const [server] = state.getWebSockets();
      const meta = server.deserializeAttachment();
      meta.handshake_deadline = Date.now() - 1;
      server.serializeAttachment(meta);
      await instance.alarm();
    });
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("handshake_timeout");
    expect((await connection.inbox.waitForClose()).code).toBe(1008);
  });

  it("bounds a control-frame burst by count and reports routed totals", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(connection, credentials, "pc");
    await enforceGuard(credentials, {
      postAuthMessageRate: 0,
      postAuthMessageBurst: 3,
      postAuthByteRate: 1_000_000,
      postAuthByteBurst: 1_000_000,
      postAuthBytesPerMinute: 1_000_000,
    });

    let accepted = 0;
    for (let seq = 2; seq <= 4; seq++) {
      connection.ws.send(JSON.stringify(v2Message({
        type: "PING",
        pairId: credentials.pairId,
        role: "pc",
        seq,
      })));
      await connection.inbox.waitFor((msg) => msg.type === "PONG");
      accepted++;
    }
    connection.ws.send(JSON.stringify(v2Message({
      type: "PING",
      pairId: credentials.pairId,
      role: "pc",
      seq: 5,
    })));
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("rate_limited");
    expect((await connection.inbox.waitForClose()).code).toBe(1013);
    expect(accepted).toBe(3);
  });

  it.each(["observe", "off"])(
    "%s mode preserves authenticated traffic beyond an observed budget",
    async (mode) => {
      const credentials = await pair();
      const connection = await openSocket(v2Url(credentials.pairId));
      await authenticateV2(connection, credentials, "pc");
      const stub = env.RELAY_SESSION.getByName(credentials.pairId);
      await runInDurableObject(stub, (instance, state) => {
        instance.guard = {
          ...instance.guard,
          mode,
          enforce: false,
          postAuthMessageRate: 0,
          postAuthMessageBurst: 1,
          postAuthByteRate: 0,
          postAuthByteBurst: 1_000_000,
          postAuthBytesPerMinute: 1_000_000,
        };
        instance.roleBudgets.clear();
        for (const server of state.getWebSockets()) {
          const meta = server.deserializeAttachment();
          meta.guard_buckets = {};
          server.serializeAttachment(meta);
        }
      });

      for (const seq of [2, 3]) {
        connection.ws.send(JSON.stringify(v2Message({
          type: "PING",
          pairId: credentials.pairId,
          role: "pc",
          seq,
        })));
        await connection.inbox.waitFor((msg) =>
          msg.type === "PONG" && msg.ack === seq);
      }
      expect(connection.ws.readyState).toBe(WebSocket.OPEN);
    },
  );

  it("persists pre-auth budgets and closes an invalid-JSON flood quickly", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    await enforceGuard(credentials, {
      preAuthMessageRate: 0,
      preAuthMessageBurst: 3,
      preAuthByteRate: 0,
      preAuthByteBurst: 1_000_000,
    });

    for (let index = 0; index < 3; index++) {
      connection.ws.send("{");
      expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
        .toBe("invalid_json");
    }
    connection.ws.send("{");
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("rate_limited");
    expect((await connection.inbox.waitForClose()).code).toBe(1008);
  });

  it("bounds opaque authenticated bytes before routing to the peer", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    await enforceGuard(credentials, {
      postAuthMessageRate: 0,
      postAuthMessageBurst: 10,
      postAuthByteRate: 0,
      postAuthByteBurst: 256,
      postAuthBytesPerMinute: 1_000_000,
    });

    pc.ws.send(JSON.stringify(v2Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
      ciphertext: "X".repeat(512),
    })));
    expect(errorCode(await pc.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("rate_limited");
    expect((await pc.inbox.waitForClose()).code).toBe(1013);
    await mobile.inbox.expectNone((msg) => msg.type === "E2E_FRAME");
  });

  it("closes oversized and unsupported frame types with stable categories", async () => {
    const firstCredentials = await pair();
    const oversized = await openSocket(v2Url(firstCredentials.pairId));
    await authenticateV2(oversized, firstCredentials, "pc");
    await enforceGuard(firstCredentials);
    oversized.ws.send("X".repeat(65537));
    expect(errorCode(await oversized.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("frame_too_large");
    expect((await oversized.inbox.waitForClose()).code).toBe(1009);

    const secondCredentials = await pair();
    const binary = await openSocket(v2Url(secondCredentials.pairId));
    await authenticateV2(binary, secondCredentials, "pc");
    await enforceGuard(secondCredentials);
    binary.ws.send(new Uint8Array(16));
    expect(errorCode(await binary.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("binary_not_supported");
    expect((await binary.inbox.waitForClose()).code).toBe(1003);
  });

  it("enforces the configured frame limit immediately below, at, and above", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");

    function encodedFrame(seq, totalBytes) {
      const base = v2Message({
        type: "E2E_FRAME",
        pairId: credentials.pairId,
        role: "pc",
        seq,
        ciphertext: "",
      });
      const baseBytes = new TextEncoder().encode(JSON.stringify(base)).byteLength;
      return JSON.stringify({
        ...base,
        ciphertext: "X".repeat(totalBytes - baseBytes),
      });
    }

    for (const [seq, bytes] of [[2, 65_535], [3, 65_536]]) {
      const encoded = encodedFrame(seq, bytes);
      expect(new TextEncoder().encode(encoded).byteLength).toBe(bytes);
      pc.ws.send(encoded);
      await mobile.inbox.waitFor((msg) =>
        msg.type === "E2E_FRAME" && msg.seq === seq);
    }
    pc.ws.send(encodedFrame(4, 65_537));
    expect(errorCode(await pc.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("frame_too_large");
    expect((await pc.inbox.waitForClose()).code).toBe(1009);
  });

  it("hard-stops a slow peer immediately above the projected queue limit", async () => {
    const credentials = await pair();
    const source = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(source, credentials, "pc");
    const stub = await enforceGuard(credentials, {
      hardBackpressureBytes: 1_000,
    });

    await runInDurableObject(stub, (instance, state) => {
      const sourceServer = state.getWebSockets().find((candidate) =>
        candidate.deserializeAttachment().role === "pc");
      const sourceMeta = sourceServer.deserializeAttachment();
      const message = v2Message({
        type: "E2E_FRAME",
        pairId: credentials.pairId,
        role: "pc",
        seq: 2,
        ciphertext: "opaque",
      });
      const outboundBytes = new TextEncoder().encode(JSON.stringify(message)).byteLength;
      const target = (bufferedAmount) => ({
        bufferedAmount,
        sent: [],
        closeCode: null,
        send(value) { this.sent.push(value); },
        close(code) { this.closeCode = code; },
      });
      const below = target(1_000 - outboundBytes - 1);
      const at = target(1_000 - outboundBytes);
      const above = target(1_000 - outboundBytes + 1);

      instance.forwardToTarget(sourceServer, sourceMeta, below, message);
      instance.forwardToTarget(sourceServer, sourceMeta, at, message);
      instance.forwardToTarget(sourceServer, sourceMeta, above, message);
      expect(below.sent).toHaveLength(1);
      expect(at.sent).toHaveLength(1);
      expect(above.sent).toHaveLength(0);
      expect(above.closeCode).toBe(1013);
    });
    expect(errorCode(await source.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("peer_backpressure");
  });

  it("bounds concurrent chunk transfers and routes only accepted pieces", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    await enforceGuard(credentials, {
      maxChunkInflight: 2,
      postAuthMessageRate: 0,
      postAuthMessageBurst: 100,
      postAuthByteRate: 0,
      postAuthByteBurst: 1_000_000,
      postAuthBytesPerMinute: 10_000_000,
    });

    let routed = 0;
    for (const [index, marker] of ["A", "B", "C"].entries()) {
      pc.ws.send(JSON.stringify(v2Chunk(credentials, {
        seq: index + 2,
        chunkId: marker.repeat(22),
      })));
      if (index < 2) {
        await mobile.inbox.waitFor((msg) => msg.type === "E2E_CHUNK");
        routed++;
      }
    }
    expect(errorCode(await pc.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("chunk_transfer_failed");
    expect((await pc.inbox.waitForClose()).code).toBe(1008);
    await mobile.inbox.expectNone((msg) =>
      msg.type === "E2E_CHUNK" && msg.chunk_id === "C".repeat(22));
    expect(routed).toBe(2);
  });

  it("expires incomplete chunk accounting without timers or polling", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    const stub = await enforceGuard(credentials, {
      chunkTimeoutMs: 10,
      postAuthMessageBurst: 100,
      postAuthByteBurst: 1_000_000,
      postAuthBytesPerMinute: 10_000_000,
    });

    pc.ws.send(JSON.stringify(v2Chunk(credentials, {
      seq: 2,
      chunkId: "D".repeat(22),
    })));
    await mobile.inbox.waitFor((msg) => msg.type === "E2E_CHUNK");
    await runInDurableObject(stub, (_instance, state) => {
      const server = state.getWebSockets().find((candidate) =>
        candidate.deserializeAttachment().role === "pc");
      const meta = server.deserializeAttachment();
      meta.chunk_transfers[0].last_at = Date.now() - 11;
      server.serializeAttachment(meta);
    });
    pc.ws.send(JSON.stringify(v2Message({
      type: "PING",
      pairId: credentials.pairId,
      role: "pc",
      seq: 3,
    })));
    await pc.inbox.waitFor((msg) => msg.type === "PONG");
    await runInDurableObject(stub, (_instance, state) => {
      const server = state.getWebSockets().find((candidate) =>
        candidate.deserializeAttachment().role === "pc");
      expect(server.deserializeAttachment().chunk_transfers).toEqual([]);
    });
    expect(pc.ws.readyState).toBe(WebSocket.OPEN);
  });

  it("fails excessive chunk metadata closed in enforce mode", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(connection, credentials, "pc");
    await enforceGuard(credentials);
    connection.ws.send(JSON.stringify(v2Chunk(credentials, {
      seq: 2,
      chunkId: "E".repeat(22),
      chunkCount: 257,
      totalBytes: 257 * 40960,
    })));
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("chunk_transfer_failed");
    expect((await connection.inbox.waitForClose()).code).toBe(1008);
  });

  it("suppresses repeated error responses and samples amplification logs", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(connection, credentials, "pc");
    await enforceGuard(credentials, {
      errorResponseBurst: 2,
      errorResponseRatePerMinute: 0,
      postAuthMessageBurst: 100,
      postAuthByteBurst: 1_000_000,
      postAuthBytesPerMinute: 1_000_000,
    });
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    for (let seq = 2; seq <= 4; seq++) {
      connection.ws.send(JSON.stringify(v2Message({
        type: "UNKNOWN",
        pairId: credentials.pairId,
        role: "pc",
        seq,
      })));
    }
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("unknown_type");
    expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("unknown_type");
    expect((await connection.inbox.waitForClose()).code).toBe(1008);
    const suppressionLogs = spy.mock.calls.filter(([entry]) =>
      String(entry).includes("relay_error_response_suppressed"));
    expect(suppressionLogs).toHaveLength(1);
  });
});

describe("legitimate traffic headroom", () => {
  it.each([
    ["normal chat", 32, 512],
    ["long streamed answer", 400, 512],
    ["tool-heavy answer", 128, 4096],
  ])("routes the %s profile without guard rejection", async (
    _profile,
    messageCount,
    ciphertextChars,
  ) => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    await enforceGuard(credentials);

    let sentBytes = 0;
    for (let index = 0; index < messageCount; index++) {
      const message = v2Message({
        type: "E2E_FRAME",
        pairId: credentials.pairId,
        role: "pc",
        seq: index + 2,
        priority: index === messageCount - 1 ? "critical" : "normal",
        final: index === messageCount - 1,
        ciphertext: "X".repeat(ciphertextChars),
      });
      const encoded = JSON.stringify(message);
      sentBytes += new TextEncoder().encode(encoded).byteLength;
      pc.ws.send(encoded);
    }

    let routedBytes = 0;
    for (let index = 0; index < messageCount; index++) {
      const routed = await mobile.inbox.waitFor(
        (msg) => msg.type === "E2E_FRAME",
        5000,
      );
      routedBytes += new TextEncoder().encode(JSON.stringify(routed)).byteLength;
    }
    expect(routedBytes).toBe(sentBytes);
    expect(pc.ws.readyState).toBe(WebSocket.OPEN);
  });

  it("routes one maximum client-compatible aggregate chunk transfer", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");
    await enforceGuard(credentials);

    const totalBytes = 8 * 1024 * 1024;
    const fullChunkChars = 40960;
    const chunkCount = Math.ceil(totalBytes / fullChunkChars);
    const chunkId = "F".repeat(22);
    let sentBytes = 0;
    for (let index = 0; index < chunkCount; index++) {
      const chunkChars = index === chunkCount - 1
        ? totalBytes - fullChunkChars * (chunkCount - 1)
        : fullChunkChars;
      const chunk = v2Chunk(credentials, {
        seq: index + 2,
        chunkId,
        chunkIndex: index,
        chunkCount,
        totalBytes,
        chunkChars,
      });
      const encoded = JSON.stringify(chunk);
      sentBytes += new TextEncoder().encode(encoded).byteLength;
      pc.ws.send(encoded);
    }

    let routedBytes = 0;
    for (let index = 0; index < chunkCount; index++) {
      const routed = await mobile.inbox.waitFor(
        (msg) => msg.type === "E2E_CHUNK",
        10_000,
      );
      routedBytes += new TextEncoder().encode(JSON.stringify(routed)).byteLength;
    }
    expect(chunkCount).toBe(205);
    expect(routedBytes).toBe(sentBytes);
    expect(pc.ws.readyState).toBe(WebSocket.OPEN);
  });

  it("preserves authoritative mobile replacement as well as PC replacement", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const oldMobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(oldMobile, credentials, "mobile");
    const newMobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(newMobile, credentials, "mobile");
    expect(errorCode(await oldMobile.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("session_superseded");

    pc.ws.send(JSON.stringify(v2Message({
      type: "E2E_FRAME",
      pairId: credentials.pairId,
      role: "pc",
      seq: 2,
      ciphertext: "replacement-check",
    })));
    await newMobile.inbox.waitFor((msg) => msg.type === "E2E_FRAME");
    await oldMobile.inbox.expectNone((msg) => msg.type === "E2E_FRAME");
  });
});

describe("security and privacy regression", () => {
  it("keeps public plaintext FRAME and BATCH fail-closed", async () => {
    const credentials = await pair();
    const connection = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(connection, credentials, "mobile");
    for (const [index, type] of ["FRAME", "BATCH"].entries()) {
      connection.ws.send(JSON.stringify(v2Message({
        type,
        pairId: credentials.pairId,
        role: "mobile",
        seq: index + 2,
        payload: type === "FRAME" ? { frame: { content: "plaintext" } } :
          { frames: [{ content: "plaintext" }] },
      })));
      expect(errorCode(await connection.inbox.waitFor((msg) => msg.type === "ERROR")))
        .toBe("e2e_required");
    }
  });

  it("keeps frame size rejection and reserved close-code handling safe", async () => {
    const credentials = await pair();
    const pc = await openSocket(v2Url(credentials.pairId));
    const mobile = await openSocket(v2Url(credentials.pairId));
    await authenticateV2(pc, credentials, "pc");
    await authenticateV2(mobile, credentials, "mobile");

    const stub = env.RELAY_SESSION.getByName(credentials.pairId);
    await runInDurableObject(stub, async (instance, state) => {
      const server = state.getWebSockets().find((candidate) =>
        candidate.deserializeAttachment().role === "pc");
      await expect(instance.webSocketClose(server, 1005, "")).resolves.toBeUndefined();
    });
    expect(await mobile.inbox.waitFor((msg) => msg.type === "DISCONNECT"))
      .toMatchObject({ payload: { code: 1005 } });

    pc.ws.send("X".repeat(65537));
    expect(errorCode(await pc.inbox.waitFor((msg) => msg.type === "ERROR")))
      .toBe("frame_too_large");
    expect((await pc.inbox.waitForClose()).code).toBe(1009);
  });

  it("does not emit forbidden relay metadata in application logs", async () => {
    const credentials = await pair();
    const forbidden = [
      credentials.pairId,
      credentials.secret,
      "private-device-id",
      "private-session-id",
      "private-kid",
      "private-nonce",
      "private-ciphertext",
    ];
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const connection = await openSocket(v1Url(
      credentials.pairId,
      "pc",
      "private-device-id",
      "private-session-id",
    ));
    connection.ws.send(JSON.stringify(v1Message({
      type: "PAIR_START",
      pairId: credentials.pairId,
      role: "pc",
      deviceId: "private-device-id",
      sessionId: "private-session-id",
      seq: 1,
      payload: { secret: credentials.secret },
    })));
    await connection.inbox.waitFor((msg) => msg.type === "PAIR_CONFIRM");
    const encodedLogs = JSON.stringify(spy.mock.calls);
    for (const value of forbidden) expect(encodedLogs).not.toContain(value);
    expect(encodedLogs).not.toContain(credentials.pairId.slice(0, 12));
  });
});
