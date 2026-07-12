export function isFinalFrame(frame) {
  const type = String(frame?.type || "");
  if (type === "status") {
    const content = String(frame?.content || frame?.status || "");
    return content === "done" || content === "error";
  }
  if (type === "turn_status") {
    const status = String(frame?.status || "");
    return status === "done" || status === "error";
  }
  if (type === "conversation_busy_changed") {
    return frame?.busy === false;
  }
  return type === "response_done" ||
    type === "turn_complete" ||
    type === "done" ||
    type === "error";
}

export function isCriticalFrame(frame) {
  const type = String(frame?.type || "");
  if (isFinalFrame(frame)) return true;
  return type === "response" ||
    type === "turn_accepted" ||
    type === "turn_status" ||
    type === "conversation_busy" ||
    type === "conversation_busy_changed" ||
    type === "active_conversation" ||
    type === "conversation_history" ||
    type === "cron_notification";
}

export function isDroppableFrame(frame) {
  const type = String(frame?.type || "");
  return type === "heartbeat_data" ||
    type === "mcp_status" ||
    (type === "status" && !isCriticalFrame(frame));
}

export function isFinalEnvelope(msg) {
  return msg?.final === true;
}

export function isCriticalEnvelope(msg) {
  return isFinalEnvelope(msg) || String(msg?.priority || "") === "critical";
}

export function isDroppableEnvelope(msg) {
  return String(msg?.priority || "") === "droppable" && !isCriticalEnvelope(msg);
}
