import { HttpError, ID, STATUSES, filters, requireThat, smallJson, type Status } from './contracts';
import { authenticate, checkMutation, configured, secure } from './security';
export { ModerationInbox } from './inbox';

const json = (body: unknown, status = 200) => Response.json(body, { status });
function value<T>(result: { ok: true; value: T } | { ok: false; error: string; status: number }): T {
  if (!result.ok) throw new HttpError(result.status, result.error);
  return result.value;
}
export default {
  async fetch(request, env): Promise<Response> {
    try {
      requireThat(configured(env), 503, 'admin_not_configured');
      const url = new URL(request.url);
      requireThat(url.origin === env.ADMIN_ORIGIN, 403, 'origin_denied');
      requireThat(!request.headers.has('origin') || request.headers.get('origin') === env.ADMIN_ORIGIN, 403, 'origin_denied');
      // Access returns from a different site. Permit its top-level shell GET;
      // JWT/owner checks still apply, and no API or mutation uses this exception.
      const shellNavigation = request.method === 'GET' && url.pathname === '/reports' &&
        request.headers.get('sec-fetch-mode') === 'navigate' && request.headers.get('sec-fetch-dest') === 'document';
      requireThat(shellNavigation || !['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site') || ''), 403, 'origin_denied');
      const limit = await env.ADMIN_EDGE_LIMITER.limit({ key: request.headers.get('cf-connecting-ip') || 'unknown' });
      requireThat(limit.success, 429, 'rate_limited');
      const identity = await authenticate(request, env);
      const inbox = env.MODERATION.getByName('owner-inbox-v1');
      requireThat(await inbox.authorizeCall(identity.actor), 429, 'rate_limited');
      const path = url.pathname;
      let response: Response;
      if (path === '/api/session' && request.method === 'GET') {
        response = json({ csrf: identity.csrf, expires: identity.expires, server_time: Date.now() });
      } else if (path === '/api/reports' && request.method === 'GET') {
        const result = value(await inbox.list(filters(url), identity.actor));
        response = json(result, result.ready ? 200 : 202);
      } else if (/^\/api\/reports\/[^/]+$/.test(path)) {
        const id = path.slice('/api/reports/'.length);
        requireThat(ID.test(id) && !url.search, 404, 'not_found');
        if (request.method === 'GET') response = json(value(await inbox.detail(id, identity.actor)));
        else if (request.method === 'PATCH') {
          checkMutation(request, env, identity.csrf);
          const body = await smallJson(request);
          requireThat(Object.keys(body).length === 2 && STATUSES.includes(body.status as Status) &&
            Number.isSafeInteger(body.version) && Number(body.version) > 0, 400, 'invalid_body');
          response = json(value(await inbox.change(id, body.status as Status, Number(body.version), identity.actor)));
        } else throw new HttpError(405, 'method_not_allowed');
      } else if (request.method === 'GET' && ['/reports', '/admin.css', '/admin.js', '/favicon.svg'].includes(path)) {
        const asset = new URL(path === '/reports' ? '/index.html' : path, env.ADMIN_ORIGIN);
        response = await env.ADMIN_ASSETS.fetch(new Request(asset));
      } else throw new HttpError(404, 'not_found');
      return secure(response);
    } catch (error) {
      // Expected RPC failures are typed results. Never reflect exception text.
      const code = error instanceof HttpError ? error.code : 'temporarily_unavailable';
      const status = error instanceof HttpError ? error.status : 503;
      const response = json({ error: code }, status);
      if (status === 429 || status === 503) response.headers.set('retry-after', status === 429 ? '60' : '5');
      return secure(response);
    }
  },
  async scheduled(_event, env) {
    // Only the existing KV namespace's metadata is scanned. Ingestion unaffected.
    await env.MODERATION.getByName('owner-inbox-v1').maintenance();
  },
} satisfies ExportedHandler<Env>;
