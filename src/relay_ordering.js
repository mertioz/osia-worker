import {
  isCriticalEnvelope,
  isCriticalFrame,
  isDroppableEnvelope,
  isDroppableFrame,
  isFinalFrame,
} from "./relay_priority.js";

const TYPE_FRAME = "FRAME";
const TYPE_BATCH = "BATCH";
const TYPE_E2E_FRAME = "E2E_FRAME";
const TYPE_E2E_CHUNK = "E2E_CHUNK";

function cleanPayload(msg) {
  const payload = msg?.payload;
  const clean = payload && typeof payload === "object" && !Array.isArray(payload)
    ? { ...payload }
    : {};
  delete clean.frame;
  delete clean.frames;
  return clean;
}

function frameEnvelope(msg, frame) {
  return {
    ...msg,
    type: TYPE_FRAME,
    payload: {
      ...cleanPayload(msg),
      frame,
    },
  };
}

function batchEnvelope(msg, frames) {
  return {
    ...msg,
    type: TYPE_BATCH,
    payload: {
      ...cleanPayload(msg),
      frames,
    },
  };
}

function flushPending(messages, msg, pending) {
  if (pending.length === 0) return;
  if (pending.length === 1) {
    messages.push(frameEnvelope(msg, pending[0]));
  } else {
    messages.push(batchEnvelope(msg, pending.slice()));
  }
  pending.length = 0;
}

export function buildForwardPlan(msg, {
  maxBatchItems = 32,
  underBackpressure = false,
} = {}) {
  const messages = [];
  const dropped = [];

  if (msg?.type === TYPE_E2E_FRAME || msg?.type === TYPE_E2E_CHUNK) {
    if (underBackpressure && isDroppableEnvelope(msg) && !isCriticalEnvelope(msg)) {
      dropped.push({
        encrypted: true,
        priority: String(msg?.priority || ""),
        final: msg?.final === true,
      });
    } else {
      messages.push(msg);
    }
    return { messages, dropped };
  }

  if (msg?.type !== TYPE_BATCH) {
    const frame = msg?.payload?.frame;
    const critical = isCriticalFrame(frame);
    const droppable = isDroppableFrame(frame);
    if (underBackpressure && droppable && !critical) {
      dropped.push(frame);
    } else {
      messages.push(msg);
    }
    return { messages, dropped };
  }

  const frames = Array.isArray(msg?.payload?.frames) ? msg.payload.frames : [];
  if (frames.length > maxBatchItems) {
    return { messages, dropped, error: "batch_too_large" };
  }

  const pending = [];
  for (const frame of frames) {
    const critical = isCriticalFrame(frame);
    const droppable = isDroppableFrame(frame);
    if (underBackpressure && droppable && !critical) {
      dropped.push(frame);
      continue;
    }

    if (isFinalFrame(frame)) {
      flushPending(messages, msg, pending);
      messages.push(frameEnvelope(msg, frame));
      continue;
    }

    pending.push(frame);
    if (pending.length >= maxBatchItems) {
      flushPending(messages, msg, pending);
    }
  }

  flushPending(messages, msg, pending);
  return { messages, dropped };
}

export function selectE2eChunkTarget(candidates, {
  pairId,
  targetRole,
  targetDeviceId,
  targetSessionId,
} = {}) {
  let selected = null;
  let selectedJoinedAt = -1;

  for (const candidate of candidates || []) {
    const meta = candidate?.meta || {};
    if (candidate?.source === true || candidate?.open !== true ||
        meta.authenticated !== true || meta.pair_id !== pairId ||
        meta.role !== targetRole || meta.device_id !== targetDeviceId ||
        meta.session_id !== targetSessionId) {
      continue;
    }

    const joinedAt = Number(meta.joined_at) || 0;
    if (selected === null || joinedAt >= selectedJoinedAt) {
      selected = candidate;
      selectedJoinedAt = joinedAt;
    }
  }

  return selected;
}
