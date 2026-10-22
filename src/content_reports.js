// Voluntary, user-reviewed reports only. This service never receives pairing
// credentials or canonical conversation state and has no public read endpoint.
export const REPORT_RETENTION_SECONDS = 30 * 24 * 60 * 60;
const MAX_BODY_BYTES = 20 * 1024;
const CATEGORIES = new Set(['harmful', 'sexual', 'violence', 'deceptive', 'other']);
const FIELDS = ['schema_version', 'category', 'text', 'details'];

function reply(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

async function boundedJson(request) {
  const reader = request.body?.getReader();
  if (!reader) return null;
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === '/health' && request.method === 'GET') {
      return reply({ service: 'osia-content-reports', schema_version: 1 });
    }
    if (path !== '/v1/reports' || request.method !== 'POST') {
      return reply({ error: 'not_found' }, 404);
    }
    const origin = request.headers.get('origin');
    if (origin && origin !== 'https://osia.space') {
      return reply({ error: 'origin_not_allowed' }, 403);
    }
    if (request.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') {
      return reply({ error: 'json_required' }, 415);
    }
    try {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const perIp = await env.REPORT_LIMITER.limit({ key: ip });
      const global = await env.REPORT_GLOBAL_LIMITER.limit({ key: 'reports' });
      if (!perIp.success || !global.success) return reply({ error: 'rate_limited' }, 429);
      const body = await boundedJson(request);
      if (!body || Array.isArray(body) || typeof body !== 'object' ||
          Object.keys(body).length !== FIELDS.length ||
          !FIELDS.every(key => Object.hasOwn(body, key)) ||
          body.schema_version !== 1 || !CATEGORIES.has(body.category) ||
          typeof body.text !== 'string' || !body.text.trim() || body.text.length > 3000 ||
          typeof body.details !== 'string' || body.details.length > 500) {
        return reply({ error: 'invalid_report' }, 400);
      }
      const reportId = crypto.randomUUID();
      const receivedAt = new Date().toISOString();
      await env.CONTENT_REPORTS.put(`report:${reportId}`, JSON.stringify({
        ...body, report_id: reportId, received_at: receivedAt,
      }), {
        expirationTtl: REPORT_RETENTION_SECONDS,
        metadata: { received_at: receivedAt, category: body.category },
      });
      return reply({ received: true, report_id: reportId }, 201);
    } catch {
      // No content, IP, exception text or credentials in application logs.
      return reply({ error: 'temporarily_unavailable' }, 503);
    }
  },
};
