import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  isCriticalFrame,
  isDroppableFrame,
  isFinalFrame,
} from "../src/relay_priority.js";
import {
  buildForwardPlan,
  selectE2eChunkTarget,
} from "../src/relay_ordering.js";
import {
  buildE2eChunkLogData,
  E2E_CHUNK_MAX_CIPHERTEXT_CHARS,
  E2E_CHUNK_MAX_COUNT,
  E2E_CHUNK_MAX_FRAME_BYTES,
  E2E_CHUNK_MAX_TOTAL_BYTES,
  e2eChunkCapabilities,
  isE2eRelayType,
  isPeerRoutedRelayType,
  isPlaintextAppType,
  relayPolicy,
  sanitizeRelayLogData,
  shouldRejectPlaintextAppFrame,
  utf8ByteLength,
  validateE2eChunkEnvelope,
} from "../src/relay_policy.js";
import {
  consumeTokenBucket,
  isChunkTransferExpired,
  isHandshakeExpired,
  isSamplePoint,
  RELAY_GUARD_NUMERIC_FIELDS,
  RELAY_GUARD_REQUIRED_VARS,
  relayGuard,
  validateRelayGuardEnvironment,
  wouldExceedBackpressure,
} from "../src/relay_guard.js";

const RELAY_CONFIG_TEXT = readFileSync(
  new URL("../wrangler.relay.toml", import.meta.url),
  "utf8",
);

function tomlString(variable) {
  const match = RELAY_CONFIG_TEXT.match(
    new RegExp(`^${variable}\\s*=\\s*"([^"]*)"\\s*$`, "m"),
  );
  return match?.[1];
}

function productionGuardEnv() {
  return Object.fromEntries(
    RELAY_GUARD_REQUIRED_VARS.map((variable) => [variable, tomlString(variable)]),
  );
}

function relayBatch(frames) {
  return {
    v: 1,
    type: "BATCH",
    role: "pc",
    pair_id: "pair",
    device_id: "pc-device",
    session_id: "session",
    seq: 7,
    ack: 6,
    payload: { frames },
  };
}

function e2eFrame({ priority = "normal", final = false } = {}) {
  return {
    v: 1,
    type: "E2E_FRAME",
    role: "pc",
    pair_id: "pair",
    device_id: "pc-device",
    session_id: "session",
    seq: 8,
    ack: 7,
    e2e_version: 1,
    alg: "CHACHA20-POLY1305",
    kid: "kid",
    from: "pc-device",
    to: "mobile-device",
    priority,
    final,
    nonce: "nonce",
    ciphertext: "ciphertext",
  };
}

function e2eChunk(overrides = {}) {
  return {
    v: 1,
    type: "E2E_CHUNK",
    role: "pc",
    pair_id: "a".repeat(64),
    device_id: "pc-device",
    session_id: "pc-session-1234",
    seq: 8,
    ack: 7,
    e2e_version: 1,
    alg: "CHACHA20-POLY1305",
    kid: "K".repeat(22),
    from: "pc-device",
    to: "mobile-device",
    to_session_id: "mobile-session-1234",
    frame_seq: 8,
    priority: "normal",
    final: false,
    nonce: "N".repeat(16),
    chunk_id: "C".repeat(22),
    chunk_index: 0,
    chunk_count: 1,
    total_bytes: 10,
    ciphertext_chunk: "X".repeat(10),
    ...overrides,
  };
}

function frameTypes(messages) {
  return messages.map((msg) => {
    if (msg.type === "FRAME") return msg.payload.frame.type;
    return msg.payload.frames.map((frame) => frame.type);
  });
}

test("final frames are critical and never droppable", () => {
  const finals = [
    { type: "status", content: "done" },
    { type: "status", status: "error" },
    { type: "response_done" },
    { type: "turn_complete" },
    { type: "done" },
    { type: "error" },
    { type: "conversation_busy_changed", busy: false },
  ];

  for (const frame of finals) {
    assert.equal(isFinalFrame(frame), true, JSON.stringify(frame));
    assert.equal(isCriticalFrame(frame), true, JSON.stringify(frame));
    assert.equal(isDroppableFrame(frame), false, JSON.stringify(frame));
  }
});

test("non-final status frames remain droppable under backpressure", () => {
  const frame = { type: "status", content: "thinking" };

  assert.equal(isFinalFrame(frame), false);
  assert.equal(isCriticalFrame(frame), false);
  assert.equal(isDroppableFrame(frame), true);
});

test("busy true still blocks but is not a final release frame", () => {
  const frame = { type: "conversation_busy_changed", busy: true };

  assert.equal(isFinalFrame(frame), false);
  assert.equal(isCriticalFrame(frame), true);
  assert.equal(isDroppableFrame(frame), false);
});

test("turn ack and status frames are critical under backpressure", () => {
  const frames = [
    { type: "turn_accepted", client_request_id: "req-1" },
    { type: "turn_status", client_request_id: "req-1", status: "running" },
    { type: "cron_notification", title: "Daily private task" },
  ];

  for (const frame of frames) {
    assert.equal(isFinalFrame(frame), false);
    assert.equal(isCriticalFrame(frame), true);
    assert.equal(isDroppableFrame(frame), false);
  }
});

test("terminal turn status is final and non-droppable", () => {
  const frame = { type: "turn_status", client_request_id: "req-1", status: "done" };

  assert.equal(isFinalFrame(frame), true);
  assert.equal(isCriticalFrame(frame), true);
  assert.equal(isDroppableFrame(frame), false);
});

test("content and final frames from one batch preserve order", () => {
  const plan = buildForwardPlan(relayBatch([
    { type: "response_chunk", content: "hello" },
    { type: "status", content: "done" },
  ]));

  assert.deepEqual(frameTypes(plan.messages), ["response_chunk", "status"]);
  assert.equal(plan.dropped.length, 0);
});

test("final frame forces pending batch flush before final", () => {
  const plan = buildForwardPlan(relayBatch([
    { type: "response_chunk", content: "hello" },
    { type: "response", content: "hello world" },
    { type: "status", content: "done" },
  ]));

  assert.deepEqual(frameTypes(plan.messages), [
    ["response_chunk", "response"],
    "status",
  ]);
  assert.equal(plan.messages[1].type, "FRAME");
});

test("final frames do not overtake previous content under backpressure", () => {
  const plan = buildForwardPlan(relayBatch([
    { type: "mcp_status" },
    { type: "response_chunk", content: "kept" },
    { type: "conversation_busy_changed", busy: false },
  ]), { underBackpressure: true });

  assert.deepEqual(frameTypes(plan.messages), [
    "response_chunk",
    "conversation_busy_changed",
  ]);
  assert.deepEqual(plan.dropped.map((frame) => frame.type), ["mcp_status"]);
});

test("turn ack does not drop or overtake content under backpressure", () => {
  const plan = buildForwardPlan(relayBatch([
    { type: "response_chunk", content: "kept" },
    { type: "turn_accepted", client_request_id: "req-1" },
  ]), { underBackpressure: true });

  assert.deepEqual(frameTypes(plan.messages), [
    ["response_chunk", "turn_accepted"],
  ]);
  assert.equal(plan.dropped.length, 0);
});

test("final frame is not droppable under backpressure", () => {
  const plan = buildForwardPlan({
    type: "FRAME",
    payload: {
      frame: { type: "status", content: "done" },
    },
  }, { underBackpressure: true });

  assert.equal(plan.messages.length, 1);
  assert.equal(plan.dropped.length, 0);
  assert.equal(plan.messages[0].payload.frame.content, "done");
});

test("encrypted frames are forwarded opaquely without payload inspection", () => {
  const msg = e2eFrame({ priority: "critical", final: false });
  const plan = buildForwardPlan(msg, { underBackpressure: true });

  assert.deepEqual(plan.messages, [msg]);
  assert.deepEqual(plan.dropped, []);
});

test("encrypted droppable frames use outer priority under backpressure", () => {
  const msg = e2eFrame({ priority: "droppable", final: false });
  const plan = buildForwardPlan(msg, { underBackpressure: true });

  assert.deepEqual(plan.messages, []);
  assert.deepEqual(plan.dropped, [{
    encrypted: true,
    priority: "droppable",
    final: false,
  }]);
});

test("encrypted final frames are never dropped under backpressure", () => {
  const msg = e2eFrame({ priority: "droppable", final: true });
  const plan = buildForwardPlan(msg, { underBackpressure: true });

  assert.deepEqual(plan.messages, [msg]);
  assert.deepEqual(plan.dropped, []);
});

test("encrypted chunks are forwarded opaquely in arrival order", () => {
  const chunks = [0, 1, 2].map((chunkIndex) => e2eChunk({
    seq: 8 + chunkIndex,
    chunk_index: chunkIndex,
    chunk_count: 3,
    total_bytes: 30,
  }));

  const forwarded = chunks.flatMap((chunk) => {
    const plan = buildForwardPlan(chunk);
    assert.deepEqual(plan.dropped, []);
    return plan.messages;
  });

  assert.deepEqual(forwarded, chunks);
  assert.deepEqual(forwarded.map((chunk) => chunk.chunk_index), [0, 1, 2]);
});

test("encrypted chunk backpressure uses only outer priority and final", () => {
  const hiddenBody = "critical-final-plaintext-must-not-be-inspected";
  const normal = e2eChunk({ ciphertext_chunk: hiddenBody });
  const droppable = e2eChunk({
    priority: "droppable",
    ciphertext_chunk: "opaque",
  });
  const final = e2eChunk({
    priority: "droppable",
    final: true,
    ciphertext_chunk: "opaque",
  });

  assert.deepEqual(
    buildForwardPlan(normal, { underBackpressure: true }).messages,
    [normal],
  );
  assert.deepEqual(
    buildForwardPlan(droppable, { underBackpressure: true }).messages,
    [],
  );
  assert.deepEqual(
    buildForwardPlan(final, { underBackpressure: true }).messages,
    [final],
  );
});

test("valid E2E chunk metadata is accepted within all bounds", () => {
  const msg = e2eChunk();
  const serializedBytes = utf8ByteLength(JSON.stringify(msg));

  assert.ok(serializedBytes < E2E_CHUNK_MAX_FRAME_BYTES);
  assert.equal(validateE2eChunkEnvelope(msg, { serializedBytes }), "");
  assert.equal(validateE2eChunkEnvelope(msg, {
    serializedBytes: E2E_CHUNK_MAX_FRAME_BYTES,
  }), "");

  const maxId = "I".repeat(128);
  const largestMetadataChunk = e2eChunk({
    device_id: maxId,
    session_id: maxId,
    seq: Number.MAX_SAFE_INTEGER,
    ack: Number.MAX_SAFE_INTEGER,
    from: maxId,
    to: maxId,
    to_session_id: maxId,
    frame_seq: Number.MAX_SAFE_INTEGER,
    chunk_count: 2,
    total_bytes: E2E_CHUNK_MAX_CIPHERTEXT_CHARS + 1,
    ciphertext_chunk: "X".repeat(E2E_CHUNK_MAX_CIPHERTEXT_CHARS),
  });
  const largestMetadataBytes = utf8ByteLength(
    JSON.stringify(largestMetadataChunk),
  );
  assert.ok(largestMetadataBytes < E2E_CHUNK_MAX_FRAME_BYTES);
  assert.equal(validateE2eChunkEnvelope(largestMetadataChunk, {
    serializedBytes: largestMetadataBytes,
  }), "");
});

test("PAIR_CONFIRM chunk capability fields advertise fixed safe limits", () => {
  assert.deepEqual(e2eChunkCapabilities(65536), {
    e2e_chunk_version: 1,
    e2e_chunk_max_frame_bytes: 49152,
    e2e_chunk_max_ciphertext_chars: 40960,
    e2e_chunk_max_total_bytes: 8388608,
    e2e_chunk_max_count: 256,
  });
  assert.equal(
    e2eChunkCapabilities(32768).e2e_chunk_max_frame_bytes,
    32768,
  );
});

test("oversized individual E2E chunks are rejected", () => {
  const msg = e2eChunk();

  assert.equal(validateE2eChunkEnvelope(msg, {
    serializedBytes: E2E_CHUNK_MAX_FRAME_BYTES + 1,
  }), "serialized_size");
  assert.equal(validateE2eChunkEnvelope(e2eChunk({
    chunk_count: 2,
    total_bytes: E2E_CHUNK_MAX_CIPHERTEXT_CHARS + 1,
    ciphertext_chunk: "X".repeat(E2E_CHUNK_MAX_CIPHERTEXT_CHARS + 1),
  }), { serializedBytes: E2E_CHUNK_MAX_FRAME_BYTES }),
  "invalid_ciphertext_chunk");
});

test("E2E chunk declared totals, counts, ids, and routes are bounded", () => {
  const maxTotalCount = Math.ceil(
    E2E_CHUNK_MAX_TOTAL_BYTES / E2E_CHUNK_MAX_CIPHERTEXT_CHARS,
  );
  const maxTotalFinalLength = E2E_CHUNK_MAX_TOTAL_BYTES -
    E2E_CHUNK_MAX_CIPHERTEXT_CHARS * (maxTotalCount - 1);
  const validAtTotalLimit = e2eChunk({
    seq: 8 + maxTotalCount - 1,
    chunk_index: maxTotalCount - 1,
    chunk_count: maxTotalCount,
    total_bytes: E2E_CHUNK_MAX_TOTAL_BYTES,
    ciphertext_chunk: "X".repeat(maxTotalFinalLength),
  });
  assert.equal(validateE2eChunkEnvelope(validAtTotalLimit, {
    serializedBytes: 1024,
  }), "");

  const invalidCases = [
    [e2eChunk({ total_bytes: E2E_CHUNK_MAX_TOTAL_BYTES + 1 }),
      "invalid_total_size"],
    [e2eChunk({ chunk_count: E2E_CHUNK_MAX_COUNT + 1 }),
      "invalid_chunk_position"],
    [e2eChunk({ chunk_index: 2 }), "invalid_chunk_position"],
    [e2eChunk({ chunk_id: "short" }), "invalid_chunk_position"],
    [e2eChunk({ from: "another-device" }), "invalid_route"],
    [e2eChunk({ to_session_id: "bad" }), "invalid_route"],
    [e2eChunk({ priority: "secret-inner-priority" }),
      "invalid_delivery_metadata"],
    [e2eChunk({ nonce: "short" }), "invalid_crypto_metadata"],
    [e2eChunk({ seq: 9 }), "invalid_sequence"],
    [e2eChunk({ total_bytes: 100000 }), "inconsistent_total_size"],
    [e2eChunk({ conversation_id: "must-not-be-routed" }), "unexpected_field"],
  ];

  for (const [candidate, expected] of invalidCases) {
    assert.equal(validateE2eChunkEnvelope(candidate, {
      serializedBytes: 1024,
    }), expected, expected);
  }
});

test("E2E chunk shape requires canonical full pieces and one exact final piece", () => {
  const totalBytes = E2E_CHUNK_MAX_CIPHERTEXT_CHARS + 1;
  const first = e2eChunk({
    chunk_index: 0,
    chunk_count: 2,
    total_bytes: totalBytes,
    ciphertext_chunk: "X".repeat(E2E_CHUNK_MAX_CIPHERTEXT_CHARS),
  });
  const final = e2eChunk({
    seq: 9,
    chunk_index: 1,
    chunk_count: 2,
    total_bytes: totalBytes,
    ciphertext_chunk: "X",
  });

  assert.equal(validateE2eChunkEnvelope(first, {
    serializedBytes: utf8ByteLength(JSON.stringify(first)),
  }), "");
  assert.equal(validateE2eChunkEnvelope(final, {
    serializedBytes: utf8ByteLength(JSON.stringify(final)),
  }), "");
  assert.equal(validateE2eChunkEnvelope(e2eChunk({
    chunk_index: 0,
    chunk_count: 2,
    total_bytes: totalBytes,
    ciphertext_chunk: "X".repeat(E2E_CHUNK_MAX_CIPHERTEXT_CHARS - 1),
  }), { serializedBytes: 1024 }), "inconsistent_total_size");
  assert.equal(validateE2eChunkEnvelope(e2eChunk({
    seq: 9,
    chunk_index: 1,
    chunk_count: 2,
    total_bytes: totalBytes,
    ciphertext_chunk: "XX",
  }), { serializedBytes: 1024 }), "inconsistent_total_size");
  assert.equal(validateE2eChunkEnvelope(e2eChunk({
    chunk_index: 0,
    chunk_count: 256,
    total_bytes: 256,
    ciphertext_chunk: "X",
  }), { serializedBytes: 1024 }), "inconsistent_total_size");
});

test("serialized relay size is measured in UTF-8 bytes", () => {
  assert.equal(utf8ByteLength("ascii"), 5);
  assert.equal(utf8ByteLength("é"), 2);
  assert.equal(utf8ByteLength("🙂"), 4);
  assert.equal(utf8ByteLength("X".repeat(65536)), 65536);
  assert.equal(utf8ByteLength("X".repeat(65537)) > 65536, true);
});

test("E2E chunks select only the newest exact authenticated target session", () => {
  const exactMeta = {
    authenticated: true,
    pair_id: "pair-a",
    role: "mobile",
    device_id: "mobile-device",
    session_id: "mobile-session",
  };
  const candidates = [
    { socket: "source", source: true, open: true, meta: exactMeta },
    { socket: "closed", open: false, meta: exactMeta },
    { socket: "unauthenticated", open: true, meta: {
      ...exactMeta,
      authenticated: false,
    } },
    { socket: "wrong-device", open: true, meta: {
      ...exactMeta,
      device_id: "other-device",
      joined_at: 99,
    } },
    { socket: "wrong-session", open: true, meta: {
      ...exactMeta,
      session_id: "stale-session",
      joined_at: 99,
    } },
    { socket: "older-exact", open: true, meta: {
      ...exactMeta,
      joined_at: 10,
    } },
    { socket: "newest-exact", open: true, meta: {
      ...exactMeta,
      joined_at: 20,
    } },
  ];

  const selected = selectE2eChunkTarget(candidates, {
    pairId: "pair-a",
    targetRole: "mobile",
    targetDeviceId: "mobile-device",
    targetSessionId: "mobile-session",
  });
  assert.equal(selected.socket, "newest-exact");
  assert.equal(selectE2eChunkTarget(candidates, {
    pairId: "pair-a",
    targetRole: "mobile",
    targetDeviceId: "mobile-device",
    targetSessionId: "missing-session",
  }), null);
});

test("public relay policy rejects plaintext app envelopes by default", () => {
  const policy = relayPolicy({});

  assert.equal(policy.mode, "public");
  assert.equal(policy.allowPlaintextAppFrames, false);
  assert.equal(isPlaintextAppType("FRAME"), true);
  assert.equal(isPlaintextAppType("BATCH"), true);
  assert.equal(isE2eRelayType("E2E_HELLO"), true);
  assert.equal(isE2eRelayType("E2E_READY"), true);
  assert.equal(isE2eRelayType("E2E_FRAME"), true);
  assert.equal(isE2eRelayType("E2E_CHUNK"), true);
  assert.equal(isPlaintextAppType("E2E_CHUNK"), false);
  assert.equal(shouldRejectPlaintextAppFrame({ policy }), "e2e_required");
});

test("public relay routes handshake controls and opaque E2E frames", () => {
  for (const type of [
    "PC_READY",
    "MOBILE_READY",
    "E2E_HELLO",
    "E2E_READY",
    "E2E_FRAME",
    "E2E_CHUNK",
    "RECONNECT_RESUME",
    "DISCONNECT",
  ]) {
    assert.equal(isPeerRoutedRelayType(type), true, type);
  }
  assert.equal(isPeerRoutedRelayType("PAIR_START"), false);
  assert.equal(isPeerRoutedRelayType("PING"), false);
  assert.equal(isPeerRoutedRelayType("PONG"), false);
});

test("private legacy plaintext requires explicit opt-in and still rejects downgrade", () => {
  const defaultPrivate = relayPolicy({ RELAY_MODE: "private" });
  const optedIn = relayPolicy({
    RELAY_MODE: "private",
    RELAY_ALLOW_PLAINTEXT: "true",
  });

  assert.equal(defaultPrivate.allowPlaintextAppFrames, false);
  assert.equal(shouldRejectPlaintextAppFrame({ policy: defaultPrivate }),
    "e2e_required");
  assert.equal(optedIn.allowPlaintextAppFrames, true);
  assert.equal(shouldRejectPlaintextAppFrame({ policy: optedIn }), "");
  assert.equal(shouldRejectPlaintextAppFrame({
    policy: optedIn,
    sourceE2eSeen: true,
  }), "downgrade_rejected");
  assert.equal(shouldRejectPlaintextAppFrame({
    policy: optedIn,
    peerE2eSeen: true,
  }), "downgrade_rejected");
});

test("relay log sanitizer redacts payloads, ciphertext, ids, and secrets", () => {
  const safe = sanitizeRelayLogData({
    payload: { frame: { content: "private" } },
    ciphertext: "abc123",
    ciphertext_chunk: "opaque-private-chunk",
    chunk: "opaque-private-chunk",
    chunk_body: "opaque-private-chunk",
    chunk_id: "full-private-chunk-id",
    client_request_id: "req-private",
    conversation_id: "conv-private",
    turn_id: "turn-private",
    secret: "secret",
    title: "private cron",
    pair_id: "stable-pair",
    device_id: "stable-device",
    session_id: "session-id",
    kid: "key-id",
    nonce: "nonce",
    url: "https://relay.invalid/ws?pair_id=secret",
    generation: 7,
    envelope_type: "E2E_FRAME",
    priority: "critical",
  });

  assert.deepEqual(safe, {
    payload_redacted: true,
    ciphertext_redacted: true,
    ciphertext_chunk_redacted: true,
    chunk_redacted: true,
    chunk_body_redacted: true,
    chunk_id_redacted: true,
    client_request_id_redacted: true,
    conversation_id_redacted: true,
    turn_id_redacted: true,
    secret_redacted: true,
    title_redacted: true,
    pair_id_redacted: true,
    device_id_redacted: true,
    session_id_redacted: true,
    kid_redacted: true,
    nonce_redacted: true,
    url_redacted: true,
    generation_redacted: true,
    envelope_type: "E2E_FRAME",
    priority: "critical",
  });
});

test("accepted E2E chunk log metadata cannot contain ciphertext or app ids", () => {
  const msg = e2eChunk({
    ciphertext_chunk: "PRIVATECIPHERTEXT",
    conversation_id: "private-conversation",
    client_request_id: "private-request",
  });
  const data = buildE2eChunkLogData(msg, {
    pair_id: "a".repeat(64),
    role: "pc",
    device_id: "pc-device-private-suffix",
    session_id: "pc-session-private-suffix",
  }, 1234);
  const encoded = JSON.stringify(data);

  assert.deepEqual(data, {
    protocol_version: 1,
    envelope_type: "E2E_CHUNK",
    bytes: 1234,
    source_role: "pc",
    target_role: "mobile",
    chunk_index: 0,
    chunk_count: 1,
    priority: "normal",
    final: false,
  });
  assert.equal(encoded.includes("PRIVATECIPHERTEXT"), false);
  assert.equal(encoded.includes("private-conversation"), false);
  assert.equal(encoded.includes("private-request"), false);
  assert.equal(Object.hasOwn(data, "ciphertext_chunk"), false);
  assert.equal(Object.hasOwn(data, "chunk_id"), false);
});

test("v2 E2E chunks require no device or session routing identity", () => {
  const msg = e2eChunk({
    v: 2,
  });
  delete msg.device_id;
  delete msg.session_id;
  delete msg.from;
  delete msg.to;
  delete msg.to_session_id;

  assert.equal(validateE2eChunkEnvelope(msg, {
    serializedBytes: utf8ByteLength(JSON.stringify(msg)),
    protocolVersion: 2,
  }), "");
  assert.equal(validateE2eChunkEnvelope({
    ...msg,
    session_id: "legacy-session",
  }, {
    serializedBytes: 1024,
    protocolVersion: 2,
  }), "unexpected_field");
});

test("relay abuse guard defaults fail safe and preserve every rollback mode", () => {
  const defaults = relayGuard();
  const production = productionGuardEnv();
  const disabled = relayGuard({ ...production, RELAY_ACCEPT_NEW_SESSIONS: "false" }, {
    requireExplicit: true,
  });
  const invalid = relayGuard({ RELAY_GUARD_MODE: "strict" });

  assert.equal(defaults.mode, "enforce");
  assert.equal(defaults.enforce, true);
  assert.equal(defaults.acceptNewSessions, true);
  assert.equal(disabled.mode, "enforce");
  assert.equal(disabled.enforce, true);
  assert.equal(disabled.acceptNewSessions, false);
  assert.equal(invalid.mode, "enforce");
  assert.equal(invalid.valid, false);

  for (const [mode, enforce] of [["enforce", true], ["observe", false], ["off", false]]) {
    const guard = relayGuard({ ...production, RELAY_GUARD_MODE: mode }, {
      requireExplicit: true,
    });
    assert.equal(guard.valid, true, mode);
    assert.equal(guard.mode, mode);
    assert.equal(guard.enforce, enforce);
  }
});

test("production relay configuration is explicit, enforcing, and identity-stable", () => {
  const env = productionGuardEnv();
  const parsed = relayGuard(env, { requireExplicit: true });

  assert.equal(parsed.valid, true, JSON.stringify(parsed.issues));
  assert.equal(parsed.mode, "enforce");
  assert.equal(parsed.acceptNewSessions, true);
  assert.deepEqual({
    maxFrameBytes: parsed.maxFrameBytes,
    backpressureBytes: parsed.backpressureBytes,
    maxBatchItems: parsed.maxBatchItems,
    handshakeTimeoutMs: parsed.handshakeTimeoutMs,
    preAuthMessageRate: parsed.preAuthMessageRate,
    preAuthMessageBurst: parsed.preAuthMessageBurst,
    preAuthByteRate: parsed.preAuthByteRate,
    preAuthByteBurst: parsed.preAuthByteBurst,
    postAuthMessageRate: parsed.postAuthMessageRate,
    postAuthMessageBurst: parsed.postAuthMessageBurst,
    postAuthByteRate: parsed.postAuthByteRate,
    postAuthByteBurst: parsed.postAuthByteBurst,
    postAuthBytesPerMinute: parsed.postAuthBytesPerMinute,
    maxChunkInflight: parsed.maxChunkInflight,
    chunkTimeoutMs: parsed.chunkTimeoutMs,
    hardBackpressureBytes: parsed.hardBackpressureBytes,
    errorResponseRatePerMinute: parsed.errorResponseRatePerMinute,
    errorResponseBurst: parsed.errorResponseBurst,
  }, {
    maxFrameBytes: 65_536,
    backpressureBytes: 262_144,
    maxBatchItems: 32,
    handshakeTimeoutMs: 10_000,
    preAuthMessageRate: 1,
    preAuthMessageBurst: 4,
    preAuthByteRate: 4_096,
    preAuthByteBurst: 16_384,
    postAuthMessageRate: 200,
    postAuthMessageBurst: 512,
    postAuthByteRate: 2_097_152,
    postAuthByteBurst: 12_582_912,
    postAuthBytesPerMinute: 67_108_864,
    maxChunkInflight: 4,
    chunkTimeoutMs: 30_000,
    hardBackpressureBytes: 33_554_432,
    errorResponseRatePerMinute: 16,
    errorResponseBurst: 8,
  });
  assert.match(RELAY_CONFIG_TEXT, /^name\s*=\s*"osia-relay"\s*$/m);
  assert.match(RELAY_CONFIG_TEXT, /^main\s*=\s*"src\/relay\.js"\s*$/m);
  assert.match(RELAY_CONFIG_TEXT, /^workers_dev\s*=\s*false\s*$/m);
  assert.match(RELAY_CONFIG_TEXT, /^preview_urls\s*=\s*false\s*$/m);
  assert.match(RELAY_CONFIG_TEXT, /name\s*=\s*"RELAY_UPGRADE_LIMITER"[\s\S]*namespace_id\s*=\s*"12101"[\s\S]*limit\s*=\s*600[\s\S]*period\s*=\s*60/);
  assert.match(RELAY_CONFIG_TEXT, /name\s*=\s*"RELAY_SESSION"\s*\r?\nclass_name\s*=\s*"RelaySession"/);
  assert.match(RELAY_CONFIG_TEXT, /tag\s*=\s*"relay-v1"\s*\r?\nnew_sqlite_classes\s*=\s*\["RelaySession"\]/);
  assert.match(RELAY_CONFIG_TEXT, /pattern\s*=\s*"relay\.osia\.space"\s*\r?\ncustom_domain\s*=\s*true/);
});

test("strict guard parsing detects every missing, malformed, and bounded numeric value", () => {
  const production = productionGuardEnv();
  for (const variable of RELAY_GUARD_REQUIRED_VARS) {
    const candidate = { ...production };
    delete candidate[variable];
    const parsed = relayGuard(candidate, { requireExplicit: true });
    assert.equal(parsed.valid, false, variable);
    assert.ok(parsed.issues.some((issue) => issue.variable === variable), variable);
  }

  for (const [variable, spec] of Object.entries(RELAY_GUARD_NUMERIC_FIELDS)) {
    for (const [label, value, valid] of [
      ["below", spec.min - 1, false],
      ["minimum", spec.min, true],
      ["maximum", spec.max, true],
      ["above", spec.max + 1, false],
      ["negative", -1, false],
      ["malformed", "not-a-number", false],
    ]) {
      const parsed = relayGuard({ ...production, [variable]: String(value) }, {
        requireExplicit: true,
      });
      const hasNumericIssue = parsed.issues.some((issue) =>
        issue.variable === variable &&
        ["not_an_integer", "out_of_range"].includes(issue.reason));
      assert.equal(hasNumericIssue, !valid, `${variable}:${label}`);
    }
  }
});

test("predeployment validation detects a missing or malformed upgrade limiter", () => {
  const production = productionGuardEnv();
  const missing = validateRelayGuardEnvironment(production);
  const malformed = validateRelayGuardEnvironment({
    ...production,
    RELAY_UPGRADE_LIMITER: {},
  });
  const valid = validateRelayGuardEnvironment({
    ...production,
    RELAY_UPGRADE_LIMITER: { limit: async () => ({ success: true }) },
  });

  assert.equal(missing.valid, false);
  assert.equal(malformed.valid, false);
  assert.equal(valid.valid, true);
  assert.ok(missing.issues.some((issue) =>
    issue.variable === "RELAY_UPGRADE_LIMITER"));
});

test("token buckets bound message and byte bursts with deterministic refill", () => {
  const buckets = {};
  const spec = { capacity: 4, refillPerSecond: 2 };

  assert.equal(consumeTokenBucket(buckets, "messages", 4, spec, 1_000), true);
  assert.equal(consumeTokenBucket(buckets, "messages", 1, spec, 1_000), false);
  assert.equal(consumeTokenBucket(buckets, "messages", 1, spec, 1_499), false);
  assert.equal(consumeTokenBucket(buckets, "messages", 1, spec, 1_500), true);
  assert.equal(consumeTokenBucket(buckets, "messages", 5, spec, 10_000), false);
});

test("every production token capacity is enforced immediately below, at, and above", () => {
  const guard = relayGuard(productionGuardEnv(), { requireExplicit: true });
  const capacities = [
    ["preauth_messages", guard.preAuthMessageBurst, guard.preAuthMessageRate],
    ["preauth_bytes", guard.preAuthByteBurst, guard.preAuthByteRate],
    ["postauth_messages", guard.postAuthMessageBurst, guard.postAuthMessageRate],
    ["postauth_bytes", guard.postAuthByteBurst, guard.postAuthByteRate],
    ["postauth_minute", guard.postAuthBytesPerMinute, guard.postAuthBytesPerMinute / 60],
    ["errors", guard.errorResponseBurst, guard.errorResponseRatePerMinute / 60],
  ];
  for (const [key, capacity, refillPerSecond] of capacities) {
    const spec = { capacity, refillPerSecond };
    const cumulative = {};
    assert.equal(consumeTokenBucket(cumulative, key, capacity - 1, spec, 1_000), true, `${key}:below`);
    assert.equal(consumeTokenBucket(cumulative, key, 1, spec, 1_000), true, `${key}:at`);
    assert.equal(consumeTokenBucket(cumulative, key, 1, spec, 1_000), false, `${key}:above`);
    assert.equal(consumeTokenBucket({}, key, capacity + 1, spec, 1_000), false, `${key}:single-above`);
  }
});

test("handshake and incomplete-transfer deadlines have exact boundaries", () => {
  assert.equal(isHandshakeExpired(10_000, 9_999), false);
  assert.equal(isHandshakeExpired(10_000, 10_000), true);
  assert.equal(isHandshakeExpired(10_000, 10_001), true);

  const transfer = { last_at: 10_000 };
  assert.equal(isChunkTransferExpired(transfer, 39_999, 30_000), false);
  assert.equal(isChunkTransferExpired(transfer, 40_000, 30_000), false);
  assert.equal(isChunkTransferExpired(transfer, 40_001, 30_000), true);
});

test("sample points grow logarithmically instead of logging every rejection", () => {
  const sampled = [];
  for (let count = 1; count <= 20; count++) {
    if (isSamplePoint(count)) sampled.push(count);
  }
  assert.deepEqual(sampled, [1, 2, 4, 8, 16]);
});

test("hard backpressure accounts for queued and next outbound bytes", () => {
  const limit = 32 * 1024 * 1024;
  assert.equal(wouldExceedBackpressure(limit - 101, 100, limit), false);
  assert.equal(wouldExceedBackpressure(limit - 100, 100, limit), false);
  assert.equal(wouldExceedBackpressure(limit - 100, 101, limit), true);
});
