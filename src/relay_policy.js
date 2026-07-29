const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);
const PRIVATE_MODES = new Set(["dev", "private", "local"]);

const PLAINTEXT_APP_TYPES = new Set(["FRAME", "BATCH"]);
const E2E_TYPES = new Set([
  "E2E_HELLO",
  "E2E_READY",
  "E2E_FRAME",
  "E2E_CHUNK",
]);
const PEER_ROUTED_TYPES = new Set([
  "PC_READY",
  "MOBILE_READY",
  "FRAME",
  "BATCH",
  "E2E_HELLO",
  "E2E_READY",
  "E2E_FRAME",
  "E2E_CHUNK",
  "RECONNECT_RESUME",
  "DISCONNECT",
]);

export const E2E_CHUNK_VERSION = 1;
export const E2E_CHUNK_MAX_FRAME_BYTES = 48 * 1024;
export const E2E_CHUNK_MAX_CIPHERTEXT_CHARS = 40 * 1024;
export const E2E_CHUNK_MAX_TOTAL_BYTES = 8 * 1024 * 1024;
export const E2E_CHUNK_MAX_COUNT = 256;

const CHUNK_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const CRYPTO_KID_RE = /^[A-Za-z0-9_-]{22}$/;
const CRYPTO_NONCE_RE = /^[A-Za-z0-9_-]{16}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{4,128}$/;
const CIPHERTEXT_CHUNK_RE = /^[A-Za-z0-9_-]+$/;
const E2E_PRIORITIES = new Set(["critical", "normal", "droppable"]);
const E2E_CHUNK_V1_FIELDS = new Set([
  "v",
  "type",
  "role",
  "pair_id",
  "device_id",
  "session_id",
  "seq",
  "ack",
  "e2e_version",
  "alg",
  "kid",
  "from",
  "to",
  "to_session_id",
  "frame_seq",
  "priority",
  "final",
  "nonce",
  "chunk_id",
  "chunk_index",
  "chunk_count",
  "total_bytes",
  "ciphertext_chunk",
]);
const E2E_CHUNK_V2_FIELDS = new Set([
  "v",
  "type",
  "role",
  "pair_id",
  "seq",
  "ack",
  "e2e_version",
  "alg",
  "kid",
  "frame_seq",
  "priority",
  "final",
  "nonce",
  "chunk_id",
  "chunk_index",
  "chunk_count",
  "total_bytes",
  "ciphertext_chunk",
]);

const UTF8_ENCODER = new TextEncoder();

const LOG_DENY_KEYS = new Set([
  "auth_hash",
  "authorization",
  "callback_id",
  "callback_url",
  "code",
  "cookie",
  "device",
  "device_id",
  "error_description",
  "chunk",
  "chunk_body",
  "chunk_id",
  "chunk_id_prefix",
  "ciphertext",
  "ciphertext_chunk",
  "client_request_id",
  "config",
  "content",
  "conversation_id",
  "frame",
  "frames",
  "flow_ref",
  "from",
  "generation",
  "instructions",
  "kid",
  "memory",
  "nonce",
  "oauth_payload",
  "pair",
  "pair_id",
  "pair_proof",
  "payload",
  "secret",
  "relay_secret",
  "session",
  "session_id",
  "settings",
  "state",
  "title",
  "token",
  "to",
  "target_session",
  "to_session_id",
  "turn_id",
  "url",
  "request_url",
  "query",
  "query_string",
]);

function isSafeNonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isSafePositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function truthy(value) {
  return TRUE_VALUES.has(String(value || "").trim().toLowerCase());
}

export function relayPolicy(env = {}) {
  const mode = String(env.RELAY_MODE || "public").trim().toLowerCase() || "public";
  const privateMode = PRIVATE_MODES.has(mode);
  return {
    mode,
    publicMode: !privateMode,
    allowPlaintextAppFrames: privateMode && truthy(env.RELAY_ALLOW_PLAINTEXT),
  };
}

export function isPlaintextAppType(type) {
  return PLAINTEXT_APP_TYPES.has(String(type || ""));
}

export function isE2eRelayType(type) {
  return E2E_TYPES.has(String(type || ""));
}

export function isPeerRoutedRelayType(type) {
  return PEER_ROUTED_TYPES.has(String(type || ""));
}

export function utf8ByteLength(value) {
  return UTF8_ENCODER.encode(String(value)).byteLength;
}

export function e2eChunkCapabilities(maxRelayFrameBytes) {
  const relayLimit = Number.isFinite(maxRelayFrameBytes) &&
      maxRelayFrameBytes > 0
    ? Math.floor(maxRelayFrameBytes)
    : E2E_CHUNK_MAX_FRAME_BYTES;
  return {
    e2e_chunk_version: E2E_CHUNK_VERSION,
    e2e_chunk_max_frame_bytes: Math.min(
      E2E_CHUNK_MAX_FRAME_BYTES,
      relayLimit,
    ),
    e2e_chunk_max_ciphertext_chars: E2E_CHUNK_MAX_CIPHERTEXT_CHARS,
    e2e_chunk_max_total_bytes: E2E_CHUNK_MAX_TOTAL_BYTES,
    e2e_chunk_max_count: E2E_CHUNK_MAX_COUNT,
  };
}

export function validateE2eChunkEnvelope(msg, {
  serializedBytes,
  protocolVersion = Number(msg?.v),
} = {}) {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
    return "invalid_object";
  }
  if (!isSafeNonNegativeInteger(serializedBytes) ||
      serializedBytes > E2E_CHUNK_MAX_FRAME_BYTES) {
    return "serialized_size";
  }
  const allowedFields = protocolVersion === 2
    ? E2E_CHUNK_V2_FIELDS
    : E2E_CHUNK_V1_FIELDS;
  for (const field of Object.keys(msg)) {
    if (!allowedFields.has(field)) return "unexpected_field";
  }
  if (msg.type !== "E2E_CHUNK" || msg.e2e_version !== E2E_CHUNK_VERSION ||
      msg.alg !== "CHACHA20-POLY1305") {
    return "unsupported_chunk_version";
  }
  if (!isSafePositiveInteger(msg.seq) || !isSafeNonNegativeInteger(msg.ack) ||
      !isSafePositiveInteger(msg.frame_seq)) {
    return "invalid_sequence";
  }
  if (protocolVersion === 1 &&
      (msg.from !== msg.device_id || !ID_RE.test(String(msg.from || "")) ||
        !ID_RE.test(String(msg.to || "")) ||
        !ID_RE.test(String(msg.to_session_id || "")))) {
    return "invalid_route";
  }
  if (!CRYPTO_KID_RE.test(String(msg.kid || "")) ||
      !CRYPTO_NONCE_RE.test(String(msg.nonce || ""))) {
    return "invalid_crypto_metadata";
  }
  if (!E2E_PRIORITIES.has(msg.priority) || typeof msg.final !== "boolean") {
    return "invalid_delivery_metadata";
  }
  if (!CHUNK_ID_RE.test(String(msg.chunk_id || "")) ||
      !Number.isInteger(msg.chunk_index) ||
      !Number.isInteger(msg.chunk_count) ||
      msg.chunk_count < 1 || msg.chunk_count > E2E_CHUNK_MAX_COUNT ||
      msg.chunk_index < 0 || msg.chunk_index >= msg.chunk_count) {
    return "invalid_chunk_position";
  }
  if (msg.frame_seq > Number.MAX_SAFE_INTEGER - msg.chunk_index ||
      msg.seq !== msg.frame_seq + msg.chunk_index) {
    return "invalid_sequence";
  }
  if (!isSafePositiveInteger(msg.total_bytes) ||
      msg.total_bytes > E2E_CHUNK_MAX_TOTAL_BYTES) {
    return "invalid_total_size";
  }
  if (typeof msg.ciphertext_chunk !== "string" ||
      msg.ciphertext_chunk.length === 0 ||
      msg.ciphertext_chunk.length > E2E_CHUNK_MAX_CIPHERTEXT_CHARS ||
      !CIPHERTEXT_CHUNK_RE.test(msg.ciphertext_chunk)) {
    return "invalid_ciphertext_chunk";
  }
  const expectedCount = Math.ceil(
    msg.total_bytes / E2E_CHUNK_MAX_CIPHERTEXT_CHARS,
  );
  const expectedChunkLength = msg.chunk_index < msg.chunk_count - 1
    ? E2E_CHUNK_MAX_CIPHERTEXT_CHARS
    : msg.total_bytes -
      E2E_CHUNK_MAX_CIPHERTEXT_CHARS * (msg.chunk_count - 1);
  if (msg.chunk_count !== expectedCount ||
      msg.ciphertext_chunk.length !== expectedChunkLength) {
    return "inconsistent_total_size";
  }
  return "";
}

export function buildE2eChunkLogData(msg, meta, serializedBytes) {
  const role = String(meta?.role || "");
  return {
    protocol_version: Number(meta?.protocol_version) || 1,
    envelope_type: "E2E_CHUNK",
    bytes: serializedBytes,
    source_role: role,
    target_role: role === "pc" ? "mobile" : "pc",
    chunk_index: msg?.chunk_index,
    chunk_count: msg?.chunk_count,
    priority: String(msg?.priority || ""),
    final: msg?.final === true,
  };
}

export function shouldRejectPlaintextAppFrame({
  policy,
  sourceE2eSeen = false,
  peerE2eSeen = false,
} = {}) {
  if (!policy?.allowPlaintextAppFrames) {
    return "e2e_required";
  }
  if (sourceE2eSeen || peerE2eSeen) {
    return "downgrade_rejected";
  }
  return "";
}

export function sanitizeRelayLogData(data = {}) {
  const safe = {};
  for (const [key, value] of Object.entries(data)) {
    if (LOG_DENY_KEYS.has(key.toLowerCase())) {
      safe[`${key}_redacted`] = true;
      continue;
    }
    if (typeof value === "string") {
      safe[key] = value.length > 160 ? `${value.slice(0, 160)}...` : value;
      continue;
    }
    if (Array.isArray(value)) {
      safe[key] = value.map((item) =>
        item && typeof item === "object"
          ? sanitizeRelayLogData(item)
          : (typeof item === "string" && item.length > 160
              ? `${item.slice(0, 160)}...`
              : item));
      continue;
    }
    if (value && typeof value === "object") {
      safe[key] = sanitizeRelayLogData(value);
      continue;
    }
    safe[key] = value;
  }
  return safe;
}
