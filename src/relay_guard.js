const GUARD_MODES = new Set(["off", "observe", "enforce"]);
const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);
const FALSE_VALUES = new Set(["0", "false", "no", "off"]);

const KIB = 1024;
const MIB = 1024 * KIB;

export const RELAY_GUARD_NUMERIC_FIELDS = Object.freeze({
  MAX_FRAME_BYTES: Object.freeze({ key: "maxFrameBytes", defaultValue: 64 * KIB, min: 1024, max: 32 * MIB }),
  BACKPRESSURE_BYTES: Object.freeze({ key: "backpressureBytes", defaultValue: 256 * KIB, min: 1024, max: 32 * MIB }),
  MAX_BATCH_ITEMS: Object.freeze({ key: "maxBatchItems", defaultValue: 32, min: 1, max: 1024 }),
  RELAY_HANDSHAKE_TIMEOUT_MS: Object.freeze({ key: "handshakeTimeoutMs", defaultValue: 10_000, min: 1000, max: 300_000 }),
  RELAY_PREAUTH_MESSAGES_PER_SECOND: Object.freeze({ key: "preAuthMessageRate", defaultValue: 1, min: 1, max: 10_000 }),
  RELAY_PREAUTH_MESSAGE_BURST: Object.freeze({ key: "preAuthMessageBurst", defaultValue: 4, min: 1, max: 10_000 }),
  RELAY_PREAUTH_BYTES_PER_SECOND: Object.freeze({ key: "preAuthByteRate", defaultValue: 4 * KIB, min: 1, max: 32 * MIB }),
  RELAY_PREAUTH_BYTE_BURST: Object.freeze({ key: "preAuthByteBurst", defaultValue: 16 * KIB, min: 1, max: 32 * MIB }),
  RELAY_POSTAUTH_MESSAGES_PER_SECOND: Object.freeze({ key: "postAuthMessageRate", defaultValue: 200, min: 1, max: 100_000 }),
  RELAY_POSTAUTH_MESSAGE_BURST: Object.freeze({ key: "postAuthMessageBurst", defaultValue: 512, min: 1, max: 100_000 }),
  RELAY_POSTAUTH_BYTES_PER_SECOND: Object.freeze({ key: "postAuthByteRate", defaultValue: 2 * MIB, min: 1, max: 64 * MIB }),
  RELAY_POSTAUTH_BYTE_BURST: Object.freeze({ key: "postAuthByteBurst", defaultValue: 12 * MIB, min: 1, max: 64 * MIB }),
  RELAY_POSTAUTH_BYTES_PER_MINUTE: Object.freeze({ key: "postAuthBytesPerMinute", defaultValue: 64 * MIB, min: 1, max: 1024 * MIB }),
  RELAY_MAX_CHUNK_INFLIGHT: Object.freeze({ key: "maxChunkInflight", defaultValue: 4, min: 1, max: 32 }),
  RELAY_CHUNK_TIMEOUT_MS: Object.freeze({ key: "chunkTimeoutMs", defaultValue: 30_000, min: 1000, max: 300_000 }),
  RELAY_HARD_BACKPRESSURE_BYTES: Object.freeze({ key: "hardBackpressureBytes", defaultValue: 32 * MIB, min: 1024, max: 64 * MIB }),
  RELAY_ERROR_RESPONSES_PER_MINUTE: Object.freeze({ key: "errorResponseRatePerMinute", defaultValue: 16, min: 1, max: 10_000 }),
  RELAY_ERROR_RESPONSE_BURST: Object.freeze({ key: "errorResponseBurst", defaultValue: 8, min: 1, max: 10_000 }),
});

export const RELAY_GUARD_REQUIRED_VARS = Object.freeze([
  "RELAY_GUARD_MODE",
  "RELAY_ACCEPT_NEW_SESSIONS",
  ...Object.keys(RELAY_GUARD_NUMERIC_FIELDS),
]);

function configIssue(variable, reason) {
  return Object.freeze({ variable, reason });
}

function boundedInt(env, variable, spec, issues, requireExplicit) {
  const raw = env[variable];
  if (raw === undefined || raw === null || String(raw).trim() === "") {
    if (requireExplicit) issues.push(configIssue(variable, "missing"));
    return spec.defaultValue;
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) {
    issues.push(configIssue(variable, "not_an_integer"));
    return spec.defaultValue;
  }
  if (parsed < spec.min || parsed > spec.max) {
    issues.push(configIssue(variable, "out_of_range"));
    return spec.defaultValue;
  }
  return parsed;
}

export function relayGuard(env = {}, { requireExplicit = false } = {}) {
  const issues = [];
  const modeRaw = env.RELAY_GUARD_MODE;
  let mode = "enforce";
  if (modeRaw === undefined || modeRaw === null || String(modeRaw).trim() === "") {
    if (requireExplicit) issues.push(configIssue("RELAY_GUARD_MODE", "missing"));
  } else {
    const requestedMode = String(modeRaw).trim().toLowerCase();
    if (GUARD_MODES.has(requestedMode)) mode = requestedMode;
    else issues.push(configIssue("RELAY_GUARD_MODE", "invalid"));
  }

  const acceptRaw = env.RELAY_ACCEPT_NEW_SESSIONS;
  let acceptNewSessions = true;
  if (acceptRaw === undefined || acceptRaw === null || String(acceptRaw).trim() === "") {
    if (requireExplicit) {
      issues.push(configIssue("RELAY_ACCEPT_NEW_SESSIONS", "missing"));
    }
  } else {
    const normalized = String(acceptRaw).trim().toLowerCase();
    if (TRUE_VALUES.has(normalized)) acceptNewSessions = true;
    else if (FALSE_VALUES.has(normalized)) acceptNewSessions = false;
    else issues.push(configIssue("RELAY_ACCEPT_NEW_SESSIONS", "invalid"));
  }

  const numeric = {};
  for (const [variable, spec] of Object.entries(RELAY_GUARD_NUMERIC_FIELDS)) {
    numeric[spec.key] = boundedInt(
      env,
      variable,
      spec,
      issues,
      requireExplicit,
    );
  }

  if (numeric.backpressureBytes > numeric.hardBackpressureBytes) {
    issues.push(configIssue("BACKPRESSURE_BYTES", "exceeds_hard_backpressure"));
  }
  if (numeric.maxFrameBytes > numeric.postAuthByteBurst) {
    issues.push(configIssue("RELAY_POSTAUTH_BYTE_BURST", "below_frame_limit"));
  }
  if (numeric.postAuthByteBurst > numeric.postAuthBytesPerMinute) {
    issues.push(configIssue("RELAY_POSTAUTH_BYTES_PER_MINUTE", "below_byte_burst"));
  }

  return Object.freeze({
    mode,
    enforce: mode === "enforce",
    acceptNewSessions,
    ...numeric,
    valid: issues.length === 0,
    issues: Object.freeze(issues),
  });
}

export function validateRelayGuardEnvironment(env = {}) {
  const guard = relayGuard(env, { requireExplicit: true });
  const issues = [...guard.issues];
  if (!env.RELAY_UPGRADE_LIMITER ||
      typeof env.RELAY_UPGRADE_LIMITER.limit !== "function") {
    issues.push(configIssue("RELAY_UPGRADE_LIMITER", "missing_or_invalid"));
  }
  return Object.freeze({
    guard,
    valid: issues.length === 0,
    issues: Object.freeze(issues),
  });
}

export function consumeTokenBucket(
  buckets,
  key,
  cost,
  { capacity, refillPerSecond },
  now = Date.now(),
) {
  const safeCapacity = Math.max(1, Number(capacity) || 1);
  const safeRefill = Math.max(0, Number(refillPerSecond) || 0);
  const safeCost = Math.max(0, Number(cost) || 0);
  const current = buckets[key] || { tokens: safeCapacity, updated_at: now };
  const elapsedMs = Math.max(0, now - (Number(current.updated_at) || now));
  const tokens = Math.min(
    safeCapacity,
    Math.max(0, Number(current.tokens) || 0) +
      elapsedMs * safeRefill / 1000,
  );
  const allowed = safeCost <= tokens;
  buckets[key] = {
    tokens: allowed ? tokens - safeCost : tokens,
    updated_at: now,
  };
  return allowed;
}

export function isHandshakeExpired(deadline, now = Date.now()) {
  const value = Number(deadline);
  return Number.isFinite(value) && value > 0 && value <= now;
}

export function isChunkTransferExpired(transfer, now, timeoutMs) {
  const lastActivity = Number(transfer?.last_at || transfer?.started_at || 0);
  const timeout = Math.max(1, Number(timeoutMs) || 1);
  return Number.isFinite(lastActivity) && now - lastActivity > timeout;
}

export function isSamplePoint(count) {
  const n = Number(count);
  return Number.isSafeInteger(n) && n > 0 && (n & (n - 1)) === 0;
}

export function wouldExceedBackpressure(bufferedBytes, outboundBytes, limit) {
  const buffered = Math.max(0, Number(bufferedBytes) || 0);
  const outbound = Math.max(0, Number(outboundBytes) || 0);
  const ceiling = Math.max(1, Number(limit) || 1);
  return buffered + outbound > ceiling;
}
