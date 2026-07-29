import { DurableObject } from "cloudflare:workers";

export const OAUTH_CALLBACK_PATH = "/oauth/callback";
export const OAUTH_SCHEMA_VERSION = 1;
export const OAUTH_DEFAULT_TTL_SECONDS = 165;
export const OAUTH_MIN_TTL_SECONDS = 30;
export const OAUTH_MAX_TTL_SECONDS = 300;
export const OAUTH_MAX_ACTIVE_FLOWS = 4;
export const OAUTH_MAX_PENDING_CALLBACKS = 4;

export const TYPE_OAUTH_FLOW_REGISTER = "OAUTH_FLOW_REGISTER";
export const TYPE_OAUTH_FLOW_CANCEL = "OAUTH_FLOW_CANCEL";
export const TYPE_OAUTH_CALLBACK_ACK = "OAUTH_CALLBACK_ACK";
export const TYPE_OAUTH_FLOW_REGISTERED = "OAUTH_FLOW_REGISTERED";
export const TYPE_OAUTH_CALLBACK = "OAUTH_CALLBACK";

const CALLBACK_ID_RE = /^[0-9a-f]{64}$/;
const PAIR_ID_RE = /^[0-9a-f]{64}$/;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const ERROR_RE = /^[A-Za-z0-9._~-]{1,128}$/;
const FLOW_KINDS = new Set(["gmail", "mcp"]);
const ACK_DISPOSITIONS = new Set(["consumed", "rejected"]);
const CONTROL_TYPES = new Set([
  TYPE_OAUTH_FLOW_REGISTER,
  TYPE_OAUTH_FLOW_CANCEL,
  TYPE_OAUTH_CALLBACK_ACK,
]);
const CONTROL_ENVELOPE_FIELDS = new Set([
  "v",
  "type",
  "role",
  "pair_id",
  "seq",
  "ack",
  "payload",
]);
const REGISTER_FIELDS = new Set([
  "schema_version",
  "callback_id",
  "flow_kind",
  "ttl_seconds",
]);
const CANCEL_FIELDS = new Set(["schema_version", "callback_id"]);
const ACK_FIELDS = new Set([
  "schema_version",
  "callback_id",
  "disposition",
]);
const FLOW_REGISTER_RPC_FIELDS = new Set([
  "schema_version",
  "callback_id",
  "pair_id",
  "flow_kind",
  "ttl_seconds",
]);
const FLOW_CANCEL_RPC_FIELDS = new Set([
  "schema_version",
  "callback_id",
  "pair_id",
]);
const FLOW_ACK_RPC_FIELDS = new Set([
  "schema_version",
  "callback_id",
  "pair_id",
  "disposition",
]);
const FLOW_STORAGE_KEY = "oauth:flow";
const CLEANUP_RETRY_WINDOW_MS = 30_000;
const DELIVERY_RETRY_BASE_MS = 2_000;
const DELIVERY_RETRY_MAX_MS = 15_000;
const UTF8_ENCODER = new TextEncoder();

const CALLBACK_HEADERS = Object.freeze({
  "cache-control": "no-store",
  pragma: "no-cache",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
});

const RECEIVED_PAGE = "<!doctype html><html><head><meta charset=\"utf-8\"><title>OSIA</title></head><body><main><h1>Authorization response received</h1><p>You may return to OSIA.</p></main></body></html>";
const UNAVAILABLE_PAGE = "<!doctype html><html><head><meta charset=\"utf-8\"><title>OSIA</title></head><body><main><h1>Authorization response unavailable</h1><p>Return to OSIA and try again.</p></main></body></html>";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactFields(value, expected) {
  if (!isPlainObject(value)) return false;
  const fields = Object.keys(value);
  return fields.length === expected.size &&
    fields.every((field) => expected.has(field));
}

function utf8ByteLength(value) {
  return UTF8_ENCODER.encode(String(value)).byteLength;
}

function sanitizeErrorDescription(value) {
  if (typeof value !== "string") return "";
  const withoutControls = value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  return [...withoutControls].slice(0, 256).join("");
}

function htmlResponse(status, received = false) {
  return new Response(received ? RECEIVED_PAGE : UNAVAILABLE_PAGE, {
    status,
    headers: {
      ...CALLBACK_HEADERS,
      "content-type": "text/html; charset=utf-8",
    },
  });
}

function clampTtlSeconds(value) {
  const requested = Number.isSafeInteger(value) && value > 0
    ? value
    : OAUTH_DEFAULT_TTL_SECONDS;
  return Math.min(
    OAUTH_MAX_TTL_SECONDS,
    Math.max(OAUTH_MIN_TTL_SECONDS, requested),
  );
}

function callbackPayloadEquivalent(left, right) {
  return left?.callback_id === right?.callback_id &&
    left?.flow_kind === right?.flow_kind &&
    left?.code === right?.code && left?.error === right?.error &&
    left?.error_description === right?.error_description;
}

export function isValidCallbackId(value) {
  return CALLBACK_ID_RE.test(String(value || ""));
}

export function isOAuthControlType(value) {
  return CONTROL_TYPES.has(String(value || ""));
}

export function validateOAuthControlEnvelope(msg) {
  if (!hasExactFields(msg, CONTROL_ENVELOPE_FIELDS)) {
    return "invalid_oauth_control";
  }
  if (msg.v !== 2 || msg.role !== "pc" || !PAIR_ID_RE.test(msg.pair_id) ||
      !Number.isSafeInteger(msg.seq) || msg.seq <= 0 ||
      !Number.isSafeInteger(msg.ack) || msg.ack < 0) {
    return "invalid_oauth_control";
  }
  if (!isOAuthControlType(msg.type)) return "invalid_oauth_control";

  const payload = msg.payload;
  if (msg.type === TYPE_OAUTH_FLOW_REGISTER) {
    const fields = isPlainObject(payload) ? Object.keys(payload) : [];
    if (fields.length < 3 || fields.length > 4 ||
        !fields.every((field) => REGISTER_FIELDS.has(field)) ||
        payload.schema_version !== OAUTH_SCHEMA_VERSION ||
        !isValidCallbackId(payload.callback_id) ||
        !FLOW_KINDS.has(payload.flow_kind) ||
        (Object.hasOwn(payload, "ttl_seconds") &&
          (!Number.isSafeInteger(payload.ttl_seconds) ||
            payload.ttl_seconds < OAUTH_MIN_TTL_SECONDS ||
            payload.ttl_seconds > OAUTH_MAX_TTL_SECONDS))) {
      return "invalid_oauth_control";
    }
    return "";
  }
  if (msg.type === TYPE_OAUTH_FLOW_CANCEL) {
    if (!hasExactFields(payload, CANCEL_FIELDS) ||
        payload.schema_version !== OAUTH_SCHEMA_VERSION ||
        !isValidCallbackId(payload.callback_id)) {
      return "invalid_oauth_control";
    }
    return "";
  }
  if (!hasExactFields(payload, ACK_FIELDS) ||
      payload.schema_version !== OAUTH_SCHEMA_VERSION ||
      !isValidCallbackId(payload.callback_id) ||
      !ACK_DISPOSITIONS.has(payload.disposition)) {
    return "invalid_oauth_control";
  }
  return "";
}

export async function callbackIdForState(state) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    UTF8_ENCODER.encode(state),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function validatePublicCallback(request) {
  if (utf8ByteLength(request.url) > 8 * 1024) {
    return { error: "malformed" };
  }
  let url;
  try {
    url = new URL(request.url);
  } catch {
    return { error: "malformed" };
  }
  if (request.method !== "GET" || url.pathname !== OAUTH_CALLBACK_PATH ||
      url.hash || url.username || url.password) {
    return { error: "malformed" };
  }

  const states = url.searchParams.getAll("state");
  const codes = url.searchParams.getAll("code");
  const errors = url.searchParams.getAll("error");
  const descriptions = url.searchParams.getAll("error_description");
  if (states.length !== 1 || !STATE_RE.test(states[0]) ||
      codes.length > 1 || errors.length > 1 || descriptions.length > 1 ||
      (codes.length === 1) === (errors.length === 1)) {
    return { error: "malformed" };
  }

  if (codes.length === 1) {
    if (codes[0].length === 0 || utf8ByteLength(codes[0]) > 4096) {
      return { error: "malformed" };
    }
    return { state: states[0], callback: { code: codes[0] } };
  }

  if (!ERROR_RE.test(errors[0])) return { error: "malformed" };
  return {
    state: states[0],
    callback: {
      error: errors[0],
      ...(descriptions.length === 1
        ? { error_description: sanitizeErrorDescription(descriptions[0]) }
        : {}),
    },
  };
}

export async function handleOAuthCallbackRequest(request, env) {
  const parsed = validatePublicCallback(request);
  if (parsed.error) return htmlResponse(400);

  const limiter = env.OAUTH_CALLBACK_LIMITER;
  const limiterKey = request.headers.get("CF-Connecting-IP")?.trim() || "unknown";
  if (!limiter || typeof limiter.limit !== "function") {
    return htmlResponse(503);
  }
  try {
    const limited = await limiter.limit({ key: limiterKey });
    if (!limited?.success) return htmlResponse(429);
  } catch {
    return htmlResponse(503);
  }

  const callbackId = await callbackIdForState(parsed.state);
  if (!env.OAUTH_CALLBACK_FLOW ||
      typeof env.OAUTH_CALLBACK_FLOW.getByName !== "function") {
    return htmlResponse(503);
  }
  try {
    const result = await env.OAUTH_CALLBACK_FLOW.getByName(callbackId)
      .submitCallback({
        schema_version: OAUTH_SCHEMA_VERSION,
        callback_id: callbackId,
        ...parsed.callback,
      });
    if (result?.status === "accepted") return htmlResponse(200, true);
    if (result?.status === "rate_limited") return htmlResponse(429);
    if (result?.status === "gone" || result?.status === "conflict") {
      return htmlResponse(410);
    }
    return htmlResponse(503);
  } catch {
    return htmlResponse(503);
  }
}

export class OAuthCallbackFlow extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  relayStub(pairId) {
    return this.env.RELAY_SESSION.getByName(pairId);
  }

  async readFlow() {
    return await this.ctx.storage.get(FLOW_STORAGE_KEY) || null;
  }

  async writeFlow(flow) {
    await this.ctx.storage.put(FLOW_STORAGE_KEY, flow);
  }

  async scheduleAlarm(flow, now = Date.now()) {
    let target = null;
    if (flow.status === "pending_delivery") {
      target = Math.min(flow.expires_at, flow.next_retry_at || now);
    } else if (flow.status === "registered" || flow.status === "enqueued") {
      target = flow.expires_at;
    } else if (flow.cleanup_at) {
      target = flow.next_retry_at
        ? Math.min(flow.next_retry_at, flow.cleanup_at)
        : flow.cleanup_at;
    }
    if (target === null) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current !== target) {
      await this.ctx.storage.setAlarm(target);
    }
  }

  async registerFlow(input) {
    if (!hasExactFields(input, FLOW_REGISTER_RPC_FIELDS) ||
        input.schema_version !== OAUTH_SCHEMA_VERSION ||
        !isValidCallbackId(input.callback_id) ||
        !PAIR_ID_RE.test(String(input.pair_id || "")) ||
        !FLOW_KINDS.has(input.flow_kind) ||
        !Number.isSafeInteger(input.ttl_seconds) ||
        input.ttl_seconds < OAUTH_MIN_TTL_SECONDS ||
        input.ttl_seconds > OAUTH_MAX_TTL_SECONDS) {
      return { status: "invalid" };
    }
    const now = Date.now();
    const existing = await this.readFlow();
    if (existing) {
      const identical = existing.callback_id === input.callback_id &&
        existing.pair_id === input.pair_id &&
        existing.flow_kind === input.flow_kind;
      if (!identical) return { status: "conflict" };
      if (["cancelled", "consumed", "rejected", "expired"].includes(existing.status) ||
          existing.expires_at <= now) {
        return { status: "gone" };
      }
      return { status: "registered", expires_at: existing.expires_at };
    }

    const ttlSeconds = clampTtlSeconds(input.ttl_seconds);
    const flow = {
      schema_version: OAUTH_SCHEMA_VERSION,
      callback_id: input.callback_id,
      pair_id: input.pair_id,
      flow_kind: input.flow_kind,
      created_at: now,
      expires_at: now + ttlSeconds * 1000,
      status: "registered",
      callback: null,
      delivery_attempts: 0,
      next_retry_at: null,
      cleanup_at: null,
    };
    await this.writeFlow(flow);
    await this.scheduleAlarm(flow, now);
    return { status: "registered", expires_at: flow.expires_at };
  }

  validateSubmittedCallback(input) {
    if (!isPlainObject(input) || input.schema_version !== OAUTH_SCHEMA_VERSION ||
        !isValidCallbackId(input.callback_id)) {
      return null;
    }
    const keys = Object.keys(input);
    const hasCode = Object.hasOwn(input, "code");
    const hasError = Object.hasOwn(input, "error");
    const allowed = hasCode
      ? new Set(["schema_version", "callback_id", "code"])
      : new Set(["schema_version", "callback_id", "error", "error_description"]);
    if (hasCode === hasError || !keys.every((key) => allowed.has(key)) ||
        (hasCode && keys.length !== 3) ||
        (hasError && keys.length < 3)) {
      return null;
    }
    if (hasCode) {
      if (typeof input.code !== "string" || input.code.length === 0 ||
          utf8ByteLength(input.code) > 4096) return null;
      return { code: input.code };
    }
    if (!ERROR_RE.test(String(input.error || ""))) return null;
    if (Object.hasOwn(input, "error_description") &&
        (typeof input.error_description !== "string" ||
          input.error_description !== sanitizeErrorDescription(input.error_description))) {
      return null;
    }
    return {
      error: input.error,
      ...(Object.hasOwn(input, "error_description")
        ? { error_description: input.error_description }
        : {}),
    };
  }

  async submitCallback(input) {
    const callback = this.validateSubmittedCallback(input);
    if (!callback) return { status: "invalid" };
    const now = Date.now();
    let flow = await this.readFlow();
    if (!flow || flow.callback_id !== input.callback_id ||
        flow.expires_at <= now ||
        ["cancelled", "consumed", "rejected", "expired"].includes(flow.status)) {
      return { status: "gone" };
    }

    const delivery = {
      callback_id: flow.callback_id,
      flow_kind: flow.flow_kind,
      created_at: now,
      ...callback,
    };
    if (flow.callback) {
      if (!callbackPayloadEquivalent(flow.callback, delivery)) {
        return { status: "conflict" };
      }
    } else {
      flow = {
        ...flow,
        status: "pending_delivery",
        callback: delivery,
        next_retry_at: now,
      };
      await this.writeFlow(flow);
      await this.scheduleAlarm(flow, now);
    }

    await this.attemptDelivery();
    return { status: "accepted" };
  }

  async attemptDelivery() {
    const now = Date.now();
    let flow = await this.readFlow();
    if (!flow || !flow.callback || flow.expires_at <= now ||
        flow.status !== "pending_delivery") return;

    let delivered = false;
    try {
      const result = await this.relayStub(flow.pair_id).enqueueOAuthCallback({
        schema_version: OAUTH_SCHEMA_VERSION,
        pair_id: flow.pair_id,
        callback_id: flow.callback_id,
        flow_kind: flow.flow_kind,
        ...flow.callback,
        created_at: flow.callback.created_at,
        expires_at: flow.expires_at,
      });
      delivered = result?.status === "enqueued" || result?.status === "duplicate";
    } catch {
      delivered = false;
    }

    const latest = await this.readFlow();
    if (!latest) return;
    if (latest.status !== "pending_delivery" || !latest.callback) {
      if (delivered) {
        try {
          await this.relayStub(flow.pair_id).removeOAuthCallback({
            schema_version: OAUTH_SCHEMA_VERSION,
            pair_id: flow.pair_id,
            callback_id: flow.callback_id,
          });
        } catch {
          // The pair mailbox has its own expiry alarm and contains the same TTL.
        }
      }
      return;
    }

    if (delivered) {
      flow = { ...latest, status: "enqueued", next_retry_at: null };
    } else {
      const attempts = latest.delivery_attempts + 1;
      const delay = Math.min(
        DELIVERY_RETRY_MAX_MS,
        DELIVERY_RETRY_BASE_MS * 2 ** Math.min(attempts - 1, 3),
      );
      flow = {
        ...latest,
        delivery_attempts: attempts,
        next_retry_at: Math.min(latest.expires_at, now + delay),
      };
    }
    await this.writeFlow(flow);
    await this.scheduleAlarm(flow, now);
  }

  async cancelFlow(input) {
    if (!hasExactFields(input, FLOW_CANCEL_RPC_FIELDS) ||
        input.schema_version !== OAUTH_SCHEMA_VERSION ||
        !isValidCallbackId(input.callback_id) ||
        !PAIR_ID_RE.test(String(input.pair_id || ""))) {
      return { status: "invalid" };
    }
    const flow = await this.readFlow();
    if (!flow) return { status: "gone" };
    if (flow.callback_id !== input.callback_id || flow.pair_id !== input.pair_id) {
      return { status: "conflict" };
    }
    if (flow.status === "cancelled") return { status: "cancelled" };
    if (["consumed", "rejected", "expired"].includes(flow.status)) {
      return { status: "gone" };
    }
    const cancelled = {
      ...flow,
      status: "cancelled",
      callback: null,
      next_retry_at: null,
      cleanup_at: Date.now() + CLEANUP_RETRY_WINDOW_MS,
    };
    await this.writeFlow(cancelled);
    await this.scheduleAlarm(cancelled);
    return { status: "cancelled" };
  }

  async acknowledgeCallback(input) {
    if (!hasExactFields(input, FLOW_ACK_RPC_FIELDS) ||
        input.schema_version !== OAUTH_SCHEMA_VERSION ||
        !isValidCallbackId(input.callback_id) ||
        !PAIR_ID_RE.test(String(input.pair_id || "")) ||
        !ACK_DISPOSITIONS.has(input.disposition)) {
      return { status: "invalid" };
    }
    const flow = await this.readFlow();
    if (!flow) return { status: "gone" };
    if (flow.callback_id !== input.callback_id || flow.pair_id !== input.pair_id) {
      return { status: "conflict" };
    }
    if (flow.status === input.disposition) {
      return { status: "acknowledged" };
    }
    if (["cancelled", "consumed", "rejected", "expired"].includes(flow.status)) {
      return { status: "gone" };
    }
    const acknowledged = {
      ...flow,
      status: input.disposition,
      callback: null,
      next_retry_at: null,
      cleanup_at: Date.now() + CLEANUP_RETRY_WINDOW_MS,
    };
    await this.writeFlow(acknowledged);
    await this.scheduleAlarm(acknowledged);
    return { status: "acknowledged" };
  }

  async expire(flow, now) {
    const expired = {
      ...flow,
      status: "expired",
      callback: null,
      next_retry_at: now + DELIVERY_RETRY_BASE_MS,
      cleanup_at: now + CLEANUP_RETRY_WINDOW_MS,
    };
    await this.writeFlow(expired);
    try {
      await this.relayStub(flow.pair_id).removeOAuthCallback({
        schema_version: OAUTH_SCHEMA_VERSION,
        pair_id: flow.pair_id,
        callback_id: flow.callback_id,
      });
      await this.ctx.storage.deleteAll();
    } catch {
      await this.scheduleAlarm(expired, now);
    }
  }

  async retryExpiryCleanup(flow, now) {
    try {
      await this.relayStub(flow.pair_id).removeOAuthCallback({
        schema_version: OAUTH_SCHEMA_VERSION,
        pair_id: flow.pair_id,
        callback_id: flow.callback_id,
      });
      await this.ctx.storage.deleteAll();
    } catch {
      const attempts = flow.delivery_attempts + 1;
      const retryAt = Math.min(
        flow.cleanup_at,
        now + Math.min(
          DELIVERY_RETRY_MAX_MS,
          DELIVERY_RETRY_BASE_MS * 2 ** Math.min(attempts - 1, 3),
        ),
      );
      const pendingCleanup = {
        ...flow,
        delivery_attempts: attempts,
        next_retry_at: retryAt,
      };
      await this.writeFlow(pendingCleanup);
      await this.scheduleAlarm(pendingCleanup, now);
    }
  }

  async alarm() {
    const now = Date.now();
    const flow = await this.readFlow();
    if (!flow) return;
    if (flow.expires_at <= now &&
        !["cancelled", "consumed", "rejected", "expired"].includes(flow.status)) {
      await this.expire(flow, now);
      return;
    }
    if (flow.status === "pending_delivery" && flow.next_retry_at <= now) {
      await this.attemptDelivery();
      return;
    }
    if (flow.status === "expired" && flow.next_retry_at <= now &&
        flow.cleanup_at > now) {
      await this.retryExpiryCleanup(flow, now);
      return;
    }
    if (flow.cleanup_at && flow.cleanup_at <= now) {
      await this.ctx.storage.deleteAll();
      return;
    }
    await this.scheduleAlarm(flow, now);
  }
}
