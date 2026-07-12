import { DurableObject } from "cloudflare:workers";
import {
  buildForwardPlan,
  selectE2eChunkTarget,
} from "./relay_ordering.js";
import {
  buildE2eChunkLogData,
  e2eChunkCapabilities,
  isE2eRelayType,
  isPeerRoutedRelayType,
  isPlaintextAppType,
  relayPolicy,
  sanitizeRelayLogData,
  shouldRejectPlaintextAppFrame,
  utf8ByteLength,
  validateE2eChunkEnvelope,
} from "./relay_policy.js";
import {
  consumeTokenBucket,
  isChunkTransferExpired,
  isHandshakeExpired,
  isSamplePoint,
  relayGuard,
  wouldExceedBackpressure,
} from "./relay_guard.js";

const VERSION_V1 = 1;
const VERSION_V2 = 2;
const ROLE_PC = "pc";
const ROLE_MOBILE = "mobile";
const TYPE_PAIR_START = "PAIR_START";
const TYPE_PAIR_CONFIRM = "PAIR_CONFIRM";
const TYPE_PC_READY = "PC_READY";
const TYPE_MOBILE_READY = "MOBILE_READY";
const TYPE_PING = "PING";
const TYPE_PONG = "PONG";
const TYPE_DISCONNECT = "DISCONNECT";
const TYPE_ERROR = "ERROR";
const TYPE_RECONNECT_RESUME = "RECONNECT_RESUME";
const TYPE_E2E_CHUNK = "E2E_CHUNK";

const PAIR_ID_RE = /^[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{4,128}$/;
const MAX_SECRET_LEN = 256;
const CLOSE_UNSUPPORTED_DATA = 1003;
const CLOSE_POLICY_VIOLATION = 1008;
const CLOSE_MESSAGE_TOO_LARGE = 1009;
const CLOSE_TRY_AGAIN_LATER = 1013;
const CLOSE_SESSION_SUPERSEDED = 4001;
const CLOSE_UPDATE_REQUIRED = 4002;

const V1_QUERY_KEYS = new Set([
  "role",
  "pair_id",
  "device_id",
  "session_id",
]);
const V2_QUERY_KEYS = new Set(["pair_id"]);
const V2_PAIR_START_FIELDS = new Set([
  "v",
  "type",
  "role",
  "pair_id",
  "seq",
  "ack",
  "payload",
]);
const V2_FORBIDDEN_IDENTITY_FIELDS = new Set([
  "device_id",
  "session_id",
  "from",
  "to",
  "to_session_id",
]);

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function log(level, event, data = {}) {
  const safe = {
    level,
    event,
    ts: new Date().toISOString(),
    ...sanitizeRelayLogData(data),
  };
  console.log(JSON.stringify(safe));
}

function envelope(type, meta, payload = {}, extra = {}) {
  if (meta.protocol_version === VERSION_V2) {
    return {
      v: VERSION_V2,
      type,
      role: meta.role,
      pair_id: meta.pair_id,
      seq: 0,
      ack: meta.last_seq || 0,
      payload,
      ...extra,
    };
  }
  return {
    v: VERSION_V1,
    type,
    role: meta.role,
    pair_id: meta.pair_id,
    device_id: meta.device_id,
    session_id: meta.session_id,
    seq: 0,
    ack: meta.last_seq || 0,
    payload,
    ...extra,
  };
}

function errorEnvelope(protocolVersion, lastSeq, code, message) {
  return {
    v: protocolVersion === VERSION_V2 ? VERSION_V2 : VERSION_V1,
    type: TYPE_ERROR,
    seq: 0,
    ack: lastSeq || 0,
    payload: { code, message },
  };
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function readMeta(ws) {
  const meta = ws.deserializeAttachment() || {};
  if (meta.protocol_version === undefined &&
      (meta.role === ROLE_PC || meta.role === ROLE_MOBILE) &&
      PAIR_ID_RE.test(String(meta.pair_id || "")) &&
      ID_RE.test(String(meta.device_id || "")) &&
      ID_RE.test(String(meta.session_id || ""))) {
    // Attachments created by the production v1 Worker predate the explicit
    // protocol marker. Treat only the complete legacy shape as v1 so a Worker
    // rollout doesn't break already-upgraded, hibernating sockets.
    return {
      ...meta,
      protocol_version: VERSION_V1,
      authoritative: false,
      superseded: false,
      blocked: false,
      generation: null,
    };
  }
  return meta;
}

function writeMeta(ws, meta) {
  ws.serializeAttachment(meta);
}

function peerRole(role) {
  return role === ROLE_PC ? ROLE_MOBILE : ROLE_PC;
}

function sameKeySet(keys, expected) {
  if (keys.length !== expected.size) return false;
  return keys.every((key) => expected.has(key));
}

export function classifyRelayUrl(urlLike) {
  let url;
  try {
    url = urlLike instanceof URL ? urlLike : new URL(urlLike);
  } catch {
    return { error: "invalid_request_shape" };
  }

  if (url.hash || url.username || url.password) {
    return { error: "invalid_request_shape" };
  }

  const keys = [...url.searchParams.keys()];
  if (keys.some((key) => url.searchParams.getAll(key).length !== 1)) {
    return { error: "invalid_request_shape" };
  }

  const pairId = url.searchParams.get("pair_id") || "";
  if (!PAIR_ID_RE.test(pairId)) {
    return { error: "invalid_pair_route" };
  }

  if (sameKeySet(keys, V2_QUERY_KEYS)) {
    return {
      error: "",
      protocolVersion: VERSION_V2,
      pairId,
      role: null,
      deviceId: null,
      sessionId: null,
    };
  }

  if (!sameKeySet(keys, V1_QUERY_KEYS)) {
    return { error: "invalid_request_shape" };
  }

  const role = url.searchParams.get("role") || "";
  const deviceId = url.searchParams.get("device_id") || "";
  const sessionId = url.searchParams.get("session_id") || "";
  if (role !== ROLE_PC && role !== ROLE_MOBILE) return { error: "invalid_role" };
  if (!ID_RE.test(deviceId)) return { error: "invalid_device_id" };
  if (!ID_RE.test(sessionId)) return { error: "invalid_session_id" };
  return {
    error: "",
    protocolVersion: VERSION_V1,
    pairId,
    role,
    deviceId,
    sessionId,
  };
}

function safeClose(ws, code, reason) {
  try {
    ws.close(code, reason);
  } catch {
    // The socket may already be closing or closed.
  }
}

export class RelaySession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.policy = relayPolicy(env);
    this.guard = relayGuard(env);
    this.maxFrameBytes = this.guard.maxFrameBytes;
    this.backpressureBytes = this.guard.backpressureBytes;
    this.maxBatchItems = this.guard.maxBatchItems;
    this.roleBudgets = new Map();
    this.logCounts = new Map();
  }

  sampledLog(level, event, data = {}) {
    const count = (this.logCounts.get(event) || 0) + 1;
    this.logCounts.set(event, count);
    if (isSamplePoint(count)) log(level, event, { ...data, occurrences: count });
  }

  chargeBuckets(buckets, prefix, messageBytes, now) {
    const authenticated = prefix === "postauth";
    const messageRate = authenticated
      ? this.guard.postAuthMessageRate
      : this.guard.preAuthMessageRate;
    const messageBurst = authenticated
      ? this.guard.postAuthMessageBurst
      : this.guard.preAuthMessageBurst;
    const byteRate = authenticated
      ? this.guard.postAuthByteRate
      : this.guard.preAuthByteRate;
    const byteBurst = authenticated
      ? this.guard.postAuthByteBurst
      : this.guard.preAuthByteBurst;
    const messagesAllowed = consumeTokenBucket(
      buckets,
      `${prefix}_messages`,
      1,
      { capacity: messageBurst, refillPerSecond: messageRate },
      now,
    );
    const bytesAllowed = consumeTokenBucket(
      buckets,
      `${prefix}_bytes`,
      messageBytes,
      { capacity: byteBurst, refillPerSecond: byteRate },
      now,
    );
    let minuteAllowed = true;
    if (authenticated) {
      minuteAllowed = consumeTokenBucket(
        buckets,
        `${prefix}_minute_bytes`,
        messageBytes,
        {
          capacity: this.guard.postAuthBytesPerMinute,
          refillPerSecond: this.guard.postAuthBytesPerMinute / 60,
        },
        now,
      );
    }
    return messagesAllowed && bytesAllowed && minuteAllowed;
  }

  chargeSocketBudget(ws, meta, messageBytes, now) {
    if (this.guard.mode === "off") return true;
    meta.guard_buckets ||= {};
    const allowed = this.chargeBuckets(
      meta.guard_buckets,
      meta.authenticated === true ? "postauth" : "preauth",
      messageBytes,
      now,
    );
    writeMeta(ws, meta);
    if (!allowed) {
      this.sampledLog("warn", "relay_socket_budget_exceeded", {
        protocol_version: meta.protocol_version,
        role: meta.role,
        authenticated: meta.authenticated === true,
      });
    }
    return allowed || !this.guard.enforce;
  }

  chargeRoleBudget(meta, messageBytes, now) {
    if (this.guard.mode === "off" || meta.protocol_version !== VERSION_V2 ||
        meta.authenticated !== true || !meta.role) {
      return true;
    }
    const buckets = this.roleBudgets.get(meta.role) || {};
    this.roleBudgets.set(meta.role, buckets);
    const allowed = this.chargeBuckets(buckets, "postauth", messageBytes, now);
    if (!allowed) {
      this.sampledLog("warn", "relay_role_budget_exceeded", {
        protocol_version: meta.protocol_version,
        role: meta.role,
      });
    }
    return allowed || !this.guard.enforce;
  }

  rejectBudget(ws, meta) {
    this.sendError(
      ws,
      "rate_limited",
      "relay traffic budget exceeded",
      { force: true },
    );
    safeClose(
      ws,
      meta.authenticated === true
        ? CLOSE_TRY_AGAIN_LATER
        : CLOSE_POLICY_VIOLATION,
      "rate_limited",
    );
  }

  async refreshHandshakeAlarm() {
    if (!this.guard.enforce) return;
    let earliest = null;
    for (const socket of this.ctx.getWebSockets()) {
      const meta = readMeta(socket);
      const deadline = Number(meta.handshake_deadline);
      if (meta.authenticated !== true && Number.isFinite(deadline) &&
          deadline > 0) {
        earliest = earliest === null ? deadline : Math.min(earliest, deadline);
      }
    }
    const current = await this.ctx.storage.getAlarm();
    if (earliest === null) {
      if (current !== null) await this.ctx.storage.deleteAlarm();
    } else if (current === null || current !== earliest) {
      await this.ctx.storage.setAlarm(earliest);
    }
  }

  async alarm() {
    if (!this.guard.enforce) return;
    const now = Date.now();
    for (const socket of this.ctx.getWebSockets()) {
      const meta = readMeta(socket);
      const deadline = Number(meta.handshake_deadline);
      if (meta.authenticated === true || !isHandshakeExpired(deadline, now)) {
        continue;
      }
      this.sendError(
        socket,
        "handshake_timeout",
        "relay handshake timed out",
        { force: true },
      );
      meta.handshake_deadline = null;
      writeMeta(socket, meta);
      safeClose(socket, CLOSE_POLICY_VIOLATION, "handshake_timeout");
    }
    await this.refreshHandshakeAlarm();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const classification = classifyRelayUrl(url);
    if (classification.error) {
      return json({ ok: false, error: classification.error }, 400);
    }

    const [client, server] = Object.values(new WebSocketPair());
    const meta = {
      protocol_version: classification.protocolVersion,
      role: classification.role,
      pair_id: classification.pairId,
      device_id: classification.deviceId,
      session_id: classification.sessionId,
      authenticated: false,
      e2e_seen: false,
      authoritative: false,
      superseded: false,
      blocked: false,
      generation: null,
      joined_at: Date.now(),
      last_seq: 0,
      handshake_deadline: this.guard.enforce
        ? Date.now() + this.guard.handshakeTimeoutMs
        : null,
      guard_buckets: {},
      chunk_transfers: [],
    };

    this.ctx.acceptWebSocket(server);
    writeMeta(server, meta);
    await this.refreshHandshakeAlarm();

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    const meta = readMeta(ws);
    const now = Date.now();
    const messageBytes = typeof message === "string"
      ? utf8ByteLength(message)
      : Number(message?.byteLength) || this.maxFrameBytes + 1;
    if (messageBytes > this.maxFrameBytes) {
      this.sendError(ws, "frame_too_large", "frame exceeds relay limit");
      this.sampledLog("warn", "relay_frame_rejected_size", {
        protocol_version: meta.protocol_version,
        role: meta.role,
        bytes: messageBytes,
      });
      if (this.guard.enforce) {
        safeClose(ws, CLOSE_MESSAGE_TOO_LARGE, "frame_too_large");
      }
      return;
    }
    if (!this.chargeSocketBudget(ws, meta, messageBytes, now)) {
      this.rejectBudget(ws, meta);
      return;
    }
    if (typeof message !== "string") {
      this.sendError(ws, "binary_not_supported", "binary frames are not supported");
      if (this.guard.enforce) {
        safeClose(ws, CLOSE_UNSUPPORTED_DATA, "binary_not_supported");
      }
      return;
    }

    let msg;
    try {
      msg = JSON.parse(message);
    } catch {
      this.sendError(ws, "invalid_json", "invalid JSON");
      return;
    }

    if (meta.protocol_version === VERSION_V2 && !meta.authenticated) {
      if (msg?.type !== TYPE_PAIR_START) {
        this.sendError(ws, "not_paired", "PAIR_START must be the first message");
        safeClose(ws, CLOSE_POLICY_VIOLATION, "PAIR_START required");
        return;
      }
      await this.handlePairStart(ws, meta, msg);
      return;
    }

    if (!this.validateEnvelope(ws, meta, msg)) return;

    if (msg.type === TYPE_PAIR_START) {
      await this.handlePairStart(ws, meta, msg);
      return;
    }

    if (!meta.authenticated) {
      this.sendError(ws, "not_paired", "PAIR_START required");
      return;
    }

    if (meta.blocked) return;

    if (meta.protocol_version === VERSION_V2 &&
        !this.isAuthoritativeV2Socket(ws, meta)) {
      this.supersedeSocket(ws, meta);
      return;
    }

    if (!this.chargeRoleBudget(meta, messageBytes, now)) {
      this.rejectBudget(ws, meta);
      return;
    }
    this.expireChunkTransfers(ws, meta, now);

    if (meta.protocol_version === VERSION_V2 &&
        msg.type === TYPE_RECONNECT_RESUME) {
      this.sendError(
        ws,
        "resume_not_supported",
        "Reconnect with a new socket and E2E handshake",
      );
      return;
    }

    if (msg.type === TYPE_E2E_CHUNK) {
      const chunkError = validateE2eChunkEnvelope(msg, {
        serializedBytes: messageBytes,
        protocolVersion: meta.protocol_version,
      });
      if (chunkError) {
        const sizeError = chunkError === "serialized_size";
        this.sendError(
          ws,
          sizeError ? "frame_too_large" : "chunk_transfer_failed",
          sizeError
            ? "chunk frame exceeds relay limit"
            : "invalid encrypted chunk envelope",
        );
        this.sampledLog("warn", "relay_e2e_chunk_rejected", {
          protocol_version: meta.protocol_version,
          envelope_type: TYPE_E2E_CHUNK,
          bytes: messageBytes,
          role: meta.role,
          reason: chunkError,
        });
        if (this.guard.enforce) {
          safeClose(ws, CLOSE_POLICY_VIOLATION, "chunk_transfer_failed");
        }
        return;
      }
    }

    if (!this.acceptSequence(ws, meta, msg)) return;

    if (msg.type === TYPE_E2E_CHUNK &&
        !this.trackChunkTransfer(ws, meta, msg, now)) {
      return;
    }

    if (isE2eRelayType(msg.type) && !meta.e2e_seen) {
      meta.e2e_seen = true;
      writeMeta(ws, meta);
    }

    if (isPlaintextAppType(msg.type)) {
      const rejectReason = shouldRejectPlaintextAppFrame({
        policy: this.policy,
        sourceE2eSeen: meta.e2e_seen === true,
        peerE2eSeen: this.peerE2eSeen(ws, meta),
      });
      if (rejectReason) {
        this.rejectPlaintextAppFrame(ws, meta, msg.type, rejectReason);
        return;
      }
    }

    if (isPeerRoutedRelayType(msg.type)) {
      const routed = this.routeToPeer(ws, meta, msg);
      if (msg.type === TYPE_E2E_CHUNK && routed > 0) {
        this.sampledLog("info", "relay_e2e_chunk_accepted", {
          ...buildE2eChunkLogData(msg, meta, messageBytes),
          targets: routed,
        });
      }
      return;
    }

    switch (msg.type) {
      case TYPE_PING:
        ws.send(JSON.stringify(envelope(TYPE_PONG, meta, { t: Date.now() })));
        return;
      case TYPE_PONG:
        return;
      default:
        this.sendError(ws, "unknown_type", "unknown relay message type");
    }
  }

  async handlePairStart(ws, meta, msg) {
    if (meta.authenticated) {
      this.sendError(ws, "already_paired", "socket is already paired");
      return;
    }

    if (meta.protocol_version === VERSION_V2) {
      const startError = this.validateV2PairStart(meta, msg);
      if (startError) {
        this.sendError(ws, startError, "invalid v2 PAIR_START");
        safeClose(ws, CLOSE_POLICY_VIOLATION, startError);
        return;
      }
    }

    const secret = msg?.payload?.secret;
    if (typeof secret !== "string" || secret.length === 0 ||
        secret.length > MAX_SECRET_LEN) {
      this.sendError(ws, "invalid_secret", "invalid pairing proof");
      safeClose(ws, CLOSE_POLICY_VIOLATION, "invalid pairing proof");
      return;
    }

    const authHash = await sha256Hex(secret);
    if (authHash !== meta.pair_id) {
      this.sendError(ws, "pair_proof_mismatch", "pairing proof does not match route");
      safeClose(ws, CLOSE_POLICY_VIOLATION, "pair_proof_mismatch");
      return;
    }

    const stored = await this.ctx.storage.get("auth_hash");
    if (stored !== authHash) {
      // A route-bound proof is authoritative over legacy unbound state.
      await this.ctx.storage.put("auth_hash", authHash);
    }

    if (meta.protocol_version === VERSION_V2) {
      meta.role = msg.role;
      meta.generation = this.nextV2Generation();
      meta.authoritative = true;
      meta.superseded = false;
      this.supersedeOlderV2Sockets(ws, meta);
    }
    meta.authenticated = true;
    meta.handshake_deadline = null;
    meta.last_seq = meta.protocol_version === VERSION_V2
      ? 1
      : (Number(msg.seq) || 0);
    writeMeta(ws, meta);
    await this.refreshHandshakeAlarm();

    if (this.rejectMixedProtocolPeers()) return;

    ws.send(JSON.stringify(envelope(TYPE_PAIR_CONFIRM, meta, {
      max_frame_bytes: this.maxFrameBytes,
      max_batch_items: this.maxBatchItems,
      ...e2eChunkCapabilities(this.maxFrameBytes),
      ...(meta.protocol_version === VERSION_V2
        ? {
            relay_protocol_version: VERSION_V2,
            identity_mode: "role_authority",
          }
        : {}),
    })));

    const readyType = meta.role === ROLE_PC ? TYPE_PC_READY : TYPE_MOBILE_READY;
    this.routeToPeer(ws, meta, envelope(readyType, meta, {}), { system: true });
    this.sampledLog("info", "relay_pair_confirmed", {
      protocol_version: meta.protocol_version,
      role: meta.role,
      connections: this.ctx.getWebSockets().length,
      policy: this.policy.mode,
    });
  }

  validateV2PairStart(meta, msg) {
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
      return "invalid_pair_route";
    }
    for (const field of Object.keys(msg)) {
      if (!V2_PAIR_START_FIELDS.has(field)) return "invalid_pair_route";
    }
    const payload = msg.payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload) ||
        Object.keys(payload).length !== 1 ||
        !Object.hasOwn(payload, "secret")) {
      return "invalid_pair_route";
    }
    if (msg.v !== VERSION_V2 || msg.type !== TYPE_PAIR_START ||
        msg.pair_id !== meta.pair_id || msg.seq !== 1 || msg.ack !== 0) {
      return "invalid_pair_route";
    }
    if (msg.role !== ROLE_PC && msg.role !== ROLE_MOBILE) {
      return "invalid_role";
    }
    return "";
  }

  validateEnvelope(ws, meta, msg) {
    if (msg?.v !== meta.protocol_version) {
      this.sendError(ws, "unsupported_version", "unsupported relay version");
      return false;
    }
    const identityMismatch = msg.role !== meta.role ||
      msg.pair_id !== meta.pair_id ||
      (meta.protocol_version === VERSION_V1 &&
        (msg.device_id !== meta.device_id ||
          msg.session_id !== meta.session_id));
    if (identityMismatch) {
      this.sendError(ws, "identity_mismatch", "envelope identity mismatch");
      return false;
    }
    if (meta.protocol_version === VERSION_V2) {
      for (const field of V2_FORBIDDEN_IDENTITY_FIELDS) {
        if (Object.hasOwn(msg, field)) {
          this.sendError(ws, "identity_mismatch", "legacy identity fields are not allowed");
          return false;
        }
      }
    }
    if (typeof msg.type !== "string") {
      this.sendError(ws, "invalid_type", "missing relay message type");
      return false;
    }
    return true;
  }

  acceptSequence(ws, meta, msg) {
    const seq = Number(msg.seq) || 0;
    if (meta.protocol_version === VERSION_V2 &&
        (!Number.isSafeInteger(msg.seq) || msg.seq <= 0 ||
          !Number.isSafeInteger(msg.ack) || msg.ack < 0)) {
      this.sendError(ws, "invalid_sequence", "invalid relay sequence");
      return false;
    }
    if (seq > 0 && meta.last_seq > 0 && seq <= meta.last_seq) {
      this.sendError(ws, "replay_rejected", "non-monotonic sequence");
      this.sampledLog("warn", "relay_replay_rejected", {
        protocol_version: meta.protocol_version,
        role: meta.role,
        seq,
        last_seq: meta.last_seq,
      });
      return false;
    }
    if (seq > 0) {
      meta.last_seq = seq;
      writeMeta(ws, meta);
    }
    return true;
  }

  trackChunkTransfer(ws, meta, msg, now) {
    if (this.guard.mode === "off") return true;
    const active = Array.isArray(meta.chunk_transfers)
      ? meta.chunk_transfers
      : [];
    let transfer = active.find((candidate) => candidate.id === msg.chunk_id);
    if (!transfer) {
      if (active.length >= this.guard.maxChunkInflight) {
        this.sampledLog("warn", "relay_chunk_inflight_exceeded", {
          protocol_version: meta.protocol_version,
          role: meta.role,
        });
        if (this.guard.enforce) {
          this.sendError(
            ws,
            "chunk_transfer_failed",
            "too many incomplete chunk transfers",
            { force: true },
          );
          safeClose(ws, CLOSE_POLICY_VIOLATION, "chunk_transfer_failed");
          return false;
        }
        return true;
      }
      if (msg.chunk_index !== 0) {
        this.sampledLog("warn", "relay_chunk_transfer_conflict", {
          protocol_version: meta.protocol_version,
          role: meta.role,
        });
        if (this.guard.enforce) {
          this.sendError(
            ws,
            "chunk_transfer_failed",
            "chunk transfer must start at its first piece",
            { force: true },
          );
          safeClose(ws, CLOSE_POLICY_VIOLATION, "chunk_transfer_failed");
          return false;
        }
        return true;
      }
      transfer = {
        id: msg.chunk_id,
        count: msg.chunk_count,
        total: msg.total_bytes,
        frame_seq: msg.frame_seq,
        kid: msg.kid,
        nonce: msg.nonce,
        priority: msg.priority,
        final: msg.final,
        next_index: 0,
        received: 0,
        chars: 0,
        started_at: now,
        last_at: now,
      };
      active.push(transfer);
    }
    const consistent = transfer.count === msg.chunk_count &&
      transfer.total === msg.total_bytes &&
      transfer.frame_seq === msg.frame_seq && transfer.kid === msg.kid &&
      transfer.nonce === msg.nonce && transfer.priority === msg.priority &&
      transfer.final === msg.final;
    const ordered = transfer.next_index === msg.chunk_index;
    const nextChars = transfer.chars + msg.ciphertext_chunk.length;
    if (!consistent || !ordered || nextChars > transfer.total) {
      this.sampledLog("warn", "relay_chunk_transfer_conflict", {
        protocol_version: meta.protocol_version,
        role: meta.role,
      });
      if (this.guard.enforce) {
        this.sendError(
          ws,
          "chunk_transfer_failed",
          "inconsistent chunk transfer",
          { force: true },
        );
        safeClose(ws, CLOSE_POLICY_VIOLATION, "chunk_transfer_failed");
        return false;
      }
      return true;
    }
    transfer.next_index++;
    transfer.received++;
    transfer.chars = nextChars;
    transfer.last_at = now;
    if (transfer.received === transfer.count) {
      const complete = transfer.chars === transfer.total;
      active.splice(active.indexOf(transfer), 1);
      if (!complete && this.guard.enforce) {
        this.sendError(
          ws,
          "chunk_transfer_failed",
          "incomplete chunk transfer",
          { force: true },
        );
        safeClose(ws, CLOSE_POLICY_VIOLATION, "chunk_transfer_failed");
        return false;
      }
    }
    meta.chunk_transfers = active;
    writeMeta(ws, meta);
    return true;
  }

  expireChunkTransfers(ws, meta, now) {
    if (this.guard.mode === "off") return 0;
    const transfers = Array.isArray(meta.chunk_transfers)
      ? meta.chunk_transfers
      : [];
    const active = transfers.filter((transfer) =>
      !isChunkTransferExpired(transfer, now, this.guard.chunkTimeoutMs));
    const expired = transfers.length - active.length;
    if (expired > 0) {
      meta.chunk_transfers = active;
      writeMeta(ws, meta);
      this.sampledLog("warn", "relay_chunk_transfer_expired", {
        protocol_version: meta.protocol_version,
        role: meta.role,
        expired,
      });
    }
    return expired;
  }

  nextV2Generation() {
    let maxGeneration = 0;
    for (const candidate of this.ctx.getWebSockets()) {
      const generation = Number(readMeta(candidate).generation);
      if (Number.isSafeInteger(generation) && generation > maxGeneration) {
        maxGeneration = generation;
      }
    }
    return maxGeneration + 1;
  }

  selectCurrentV2Socket(role) {
    let selected = null;
    let selectedGeneration = -1;
    for (const candidate of this.ctx.getWebSockets()) {
      if (candidate.readyState !== WebSocket.OPEN) continue;
      const meta = readMeta(candidate);
      const generation = Number(meta.generation);
      if (meta.protocol_version !== VERSION_V2 ||
          meta.authenticated !== true || meta.authoritative !== true ||
          meta.superseded === true || meta.blocked === true ||
          meta.role !== role || !Number.isSafeInteger(generation)) {
        continue;
      }
      if (selected === null || generation > selectedGeneration) {
        selected = candidate;
        selectedGeneration = generation;
      }
    }
    return selected;
  }

  isAuthoritativeV2Socket(ws, meta = readMeta(ws)) {
    return meta.protocol_version === VERSION_V2 &&
      meta.authenticated === true && meta.authoritative === true &&
      meta.superseded !== true && meta.blocked !== true &&
      this.selectCurrentV2Socket(meta.role) === ws;
  }

  supersedeSocket(ws, meta = readMeta(ws)) {
    if (meta.superseded !== true) {
      meta.superseded = true;
      meta.authoritative = false;
      writeMeta(ws, meta);
      this.sendError(ws, "session_superseded", "a newer connection is authoritative");
    }
    safeClose(ws, CLOSE_SESSION_SUPERSEDED, "session_superseded");
  }

  supersedeOlderV2Sockets(currentWs, currentMeta) {
    for (const candidate of this.ctx.getWebSockets()) {
      if (candidate === currentWs) continue;
      const meta = readMeta(candidate);
      if (meta.protocol_version === VERSION_V2 &&
          meta.authenticated === true && meta.role === currentMeta.role &&
          meta.blocked !== true) {
        this.supersedeSocket(candidate, meta);
      }
    }
  }

  rejectMixedProtocolPeers() {
    const sockets = this.ctx.getWebSockets().filter((candidate) => {
      const meta = readMeta(candidate);
      return candidate.readyState === WebSocket.OPEN &&
        meta.authenticated === true && meta.blocked !== true;
    });
    const pcVersions = new Set();
    const mobileVersions = new Set();
    for (const candidate of sockets) {
      const meta = readMeta(candidate);
      if (meta.role === ROLE_PC) pcVersions.add(meta.protocol_version);
      if (meta.role === ROLE_MOBILE) mobileVersions.add(meta.protocol_version);
    }
    const mixed = [...pcVersions].some((version) =>
      [...mobileVersions].some((peerVersion) => peerVersion !== version));
    if (!mixed) return false;

    for (const candidate of sockets) {
      const meta = readMeta(candidate);
      meta.blocked = true;
      if (meta.protocol_version === VERSION_V2) meta.authoritative = false;
      writeMeta(candidate, meta);
      this.sendError(
        candidate,
        "update_required",
        "Both relay endpoints must use the same protocol version",
      );
    }
    for (const candidate of sockets) {
      safeClose(candidate, CLOSE_UPDATE_REQUIRED, "update_required");
    }
    this.sampledLog("warn", "relay_protocol_mismatch", {
      error_code: "update_required",
      connections: sockets.length,
    });
    return true;
  }

  routeToPeer(sourceWs, sourceMeta, msg, options = {}) {
    if (sourceMeta.blocked === true) return 0;
    if (!options.system && this.rejectMixedProtocolPeers()) return 0;
    if (!options.system && sourceMeta.protocol_version === VERSION_V2 &&
        !this.isAuthoritativeV2Socket(sourceWs, sourceMeta)) {
      this.supersedeSocket(sourceWs, sourceMeta);
      return 0;
    }

    let targets;
    if (sourceMeta.protocol_version === VERSION_V2) {
      const selected = this.selectCurrentV2Socket(peerRole(sourceMeta.role));
      targets = selected ? [selected] : [];
    } else if (msg?.type === TYPE_E2E_CHUNK) {
      const selected = selectE2eChunkTarget(
        this.ctx.getWebSockets().map((candidate) => {
          const meta = readMeta(candidate);
          return {
            socket: candidate,
            source: candidate === sourceWs,
            open: candidate.readyState === WebSocket.OPEN &&
              meta.protocol_version === VERSION_V1 && meta.blocked !== true,
            meta,
          };
        }),
        {
          pairId: sourceMeta.pair_id,
          targetRole: peerRole(sourceMeta.role),
          targetDeviceId: msg.to,
          targetSessionId: msg.to_session_id,
        },
      );
      targets = selected ? [selected.socket] : [];
    } else {
      targets = this.ctx.getWebSockets().filter((candidate) => {
        if (candidate === sourceWs || candidate.readyState !== WebSocket.OPEN) {
          return false;
        }
        const meta = readMeta(candidate);
        return meta.authenticated &&
          meta.protocol_version === VERSION_V1 && meta.blocked !== true &&
          meta.pair_id === sourceMeta.pair_id &&
          meta.role === peerRole(sourceMeta.role);
      });
    }

    if (targets.length === 0) {
      if (!options.system) {
        this.sendError(sourceWs, "peer_unavailable", "paired peer is offline");
      }
      return 0;
    }

    for (const target of targets) {
      this.forwardToTarget(sourceWs, sourceMeta, target, msg);
    }
    return targets.length;
  }

  peerE2eSeen(sourceWs, sourceMeta) {
    const candidates = sourceMeta.protocol_version === VERSION_V2
      ? [this.selectCurrentV2Socket(peerRole(sourceMeta.role))]
      : this.ctx.getWebSockets();
    return candidates.some((candidate) => {
      if (!candidate) return false;
      if (candidate === sourceWs || candidate.readyState !== WebSocket.OPEN) {
        return false;
      }
      const meta = readMeta(candidate);
      return meta.authenticated &&
        meta.protocol_version === sourceMeta.protocol_version &&
        meta.blocked !== true &&
        meta.pair_id === sourceMeta.pair_id &&
        meta.role === peerRole(sourceMeta.role) &&
        meta.e2e_seen === true;
    });
  }

  rejectPlaintextAppFrame(ws, meta, type, reason) {
    this.sendError(
      ws,
      "e2e_required",
      "Update required: E2E encryption is required for relay app frames",
    );
    this.sampledLog("warn", "relay_plaintext_app_frame_rejected", {
      protocol_version: meta.protocol_version,
      role: meta.role,
      envelope_type: String(type || ""),
      policy: this.policy.mode,
      reason,
    });
  }

  forwardToTarget(sourceWs, sourceMeta, target, msg) {
    const buffered = Number(target.bufferedAmount || 0);
    const plan = buildForwardPlan(msg, {
      maxBatchItems: this.maxBatchItems,
      underBackpressure: buffered > this.backpressureBytes,
    });

    if (plan.error === "batch_too_large") {
      this.sendError(sourceWs, "batch_too_large", "too many frames in batch");
      return;
    }

    for (const frame of plan.dropped) {
      const encrypted = frame?.encrypted === true;
      this.sampledLog("warn", encrypted
        ? (msg?.type === TYPE_E2E_CHUNK
            ? "relay_e2e_chunk_dropped_backpressure"
            : "relay_e2e_frame_dropped_backpressure")
        : "relay_frame_dropped_backpressure", {
        protocol_version: sourceMeta.protocol_version,
        source_role: sourceMeta.role,
        target_role: peerRole(sourceMeta.role),
        buffered,
        ...(encrypted
          ? {
              priority: ["critical", "normal", "droppable"].includes(
                frame?.priority,
              ) ? frame.priority : "invalid",
              final: frame?.final === true,
            }
          : { legacy_app_frame: true }),
      });
    }

    for (const outbound of plan.messages) {
      const serialized = JSON.stringify(outbound);
      const outboundBytes = utf8ByteLength(serialized);
      if (wouldExceedBackpressure(
        target.bufferedAmount,
        outboundBytes,
        this.guard.hardBackpressureBytes,
      )) {
        this.sampledLog("warn", "relay_hard_backpressure", {
          protocol_version: sourceMeta.protocol_version,
          source_role: sourceMeta.role,
          target_role: peerRole(sourceMeta.role),
          buffered: Number(target.bufferedAmount || 0),
        });
        if (this.guard.enforce) {
          safeClose(target, CLOSE_TRY_AGAIN_LATER, "slow_peer");
          this.sendError(
            sourceWs,
            "peer_backpressure",
            "paired peer is not accepting relay traffic",
            { force: true },
          );
          return;
        }
      }
      target.send(serialized);
    }
  }

  sendError(ws, code, message, { force = false } = {}) {
    const meta = readMeta(ws);
    if (!force && this.guard.mode !== "off") {
      meta.guard_buckets ||= {};
      const allowed = consumeTokenBucket(
        meta.guard_buckets,
        "error_responses",
        1,
        {
          capacity: this.guard.errorResponseBurst,
          refillPerSecond: this.guard.errorResponseRatePerMinute / 60,
        },
      );
      writeMeta(ws, meta);
      if (!allowed) {
        this.sampledLog("warn", "relay_error_response_suppressed", {
          protocol_version: meta.protocol_version,
          role: meta.role,
          error_code: code,
        });
        if (this.guard.enforce) {
          safeClose(ws, CLOSE_POLICY_VIOLATION, "too_many_errors");
          return false;
        }
      }
    }
    const body = errorEnvelope(
      meta.protocol_version,
      meta.last_seq,
      code,
      message,
    );
    try {
      ws.send(JSON.stringify(body));
      return true;
    } catch {
      // Socket is already gone; nothing useful to do.
      return false;
    }
  }

  async webSocketClose(ws, code, reason) {
    const meta = readMeta(ws);
    if (meta.authenticated === true) {
      this.sampledLog("info", "relay_socket_close", {
        protocol_version: meta.protocol_version,
        role: meta.role,
        code,
        reason_present: String(reason || "").length > 0,
        connections: this.ctx.getWebSockets().length,
      });
    }
    if (meta.authenticated !== true || meta.blocked === true ||
        meta.superseded === true ||
        (meta.protocol_version === VERSION_V2 &&
          meta.authoritative !== true)) {
      if (meta.authenticated !== true) await this.refreshHandshakeAlarm();
      return;
    }
    if (meta.protocol_version === VERSION_V2) {
      const current = this.selectCurrentV2Socket(meta.role);
      if (current !== null && current !== ws) return;
    }
    this.routeToPeer(ws, meta, envelope(TYPE_DISCONNECT, meta, { code }), {
      system: true,
    });
    // The runtime has already closed this socket. Re-closing here is invalid,
    // and reserved peer-observed codes such as 1005/1006 raise
    // InvalidAccessError before Durable Object cleanup can finish.
  }

  async webSocketError(ws, error) {
    const meta = readMeta(ws);
    if (meta.authenticated !== true) return;
    this.sampledLog("error", "relay_socket_error", {
      protocol_version: meta.protocol_version,
      role: meta.role,
      error_type: error instanceof Error ? error.name : "WebSocketError",
    });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "osia-relay" });
    }

    if (request.method !== "GET" || url.pathname !== "/ws") {
      return json({ ok: false, error: "not_found" }, 404);
    }

    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json({ ok: false, error: "upgrade_required" }, 426, {
        upgrade: "websocket",
      });
    }

    const classification = classifyRelayUrl(url);
    if (classification.error) {
      return json({ ok: false, error: classification.error }, 400);
    }

    const guard = relayGuard(env, { requireExplicit: true });
    if (guard.enforce && !guard.valid) {
      return json({ ok: false, error: "relay_configuration_invalid" }, 503, {
        "retry-after": "60",
      });
    }

    if (!guard.acceptNewSessions) {
      return json({ ok: false, error: "new_sessions_disabled" }, 503, {
        "retry-after": "60",
      });
    }

    if (guard.mode !== "off" && env.RELAY_UPGRADE_LIMITER) {
      const limiterKey = request.headers.get("CF-Connecting-IP")?.trim();
      if (limiterKey) {
        try {
          const { success } = await env.RELAY_UPGRADE_LIMITER.limit({
            key: limiterKey,
          });
          if (!success && guard.enforce) {
            return json({ ok: false, error: "upgrade_rate_limited" }, 429, {
              "retry-after": "60",
            });
          }
        } catch {
          // Preserve connectivity if the optional edge limiter is unavailable.
          // Per-socket Durable Object budgets remain active in enforce mode.
        }
      }
    }

    const stub = env.RELAY_SESSION.getByName(classification.pairId);
    return stub.fetch(request);
  },
};
