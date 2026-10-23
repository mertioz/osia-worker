// Local synthetic QA ONLY. This gateway injects a test JWT outside the built
// Worker. It cannot use live KV, real Access identities, or public interfaces.
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const origin = 'https://admin.osia.space', issuer = 'https://test-only.cloudflareaccess.com';
const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
const jwks = { keys: [{ ...await exportJWK(publicKey), alg: 'RS256', use: 'sig', kid: 'test-only-preview' }] };
const jwt = await new SignJWT({ type: 'app', email: 'owner@example.com' }).setProtectedHeader({ alg: 'RS256', kid: 'test-only-preview' })
  .setSubject('test-only-owner').setIssuer(issuer).setAudience('a'.repeat(64)).setIssuedAt().setExpirationTime('1h').sign(privateKey);
const mf = new Miniflare(convertV4MiniflareOptions({
  modules: true, scriptPath: resolve(root, 'dist/admin/index.js'),
  compatibilityDate: '2026-10-23', compatibilityFlags: ['nodejs_compat'],
  bindings: { ADMIN_ORIGIN: origin, ACCESS_ISSUER: issuer, ACCESS_AUD: 'a'.repeat(64), ADMIN_EMAIL: 'owner@example.com', ADMIN_SUB: 'test-only-owner' },
  kvNamespaces: ['CONTENT_REPORTS'], durableObjects: { MODERATION: { className: 'ModerationInbox', useSQLite: true } },
  ratelimits: { ADMIN_EDGE_LIMITER: { namespace_id: '12105', simple: { limit: 1000, period: 60 } } },
  serviceBindings: { ADMIN_ASSETS: async request => {
    const name = new URL(request.url).pathname;
    if (!['/index.html', '/admin.js', '/admin.css', '/favicon.svg'].includes(name)) return new Response('', { status: 404 });
    return new Response(await readFile(resolve(root, 'admin/public' + name)), { headers: {
      'content-type': name.endsWith('.html') ? 'text/html; charset=utf-8' : name.endsWith('.js') ? 'text/javascript' : name.endsWith('.svg') ? 'image/svg+xml' : 'text/css',
    } });
  } },
  outboundService: request => {
    if (request.url === issuer + '/cdn-cgi/access/certs') return Response.json(jwks);
    return new Response('', { status: 502 });
  },
}));
const kv = await mf.getKVNamespace('CONTENT_REPORTS');
const now = Date.now();
const categories = ['harmful', 'deceptive', 'violence', 'other', 'sexual'];
for (let n = 1; n <= 32; n++) {
  const id = `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
  const received = new Date(now - n * 4000000).toISOString(), category = categories[(n - 1) % 5];
  await kv.put('report:' + id, JSON.stringify({ schema_version: 1, report_id: id, received_at: received, category,
    text: n === 1 ? 'Synthetic QA report — selected reply only.\n\n<img src=x onerror="window.xss=true">\nThis markup must remain plain text.' : `Synthetic QA report ${n}. Only the reviewed reply is submitted.`,
    details: n === 1 ? 'Synthetic note: the suggested response needs review.' : '',
  }), { expirationTtl: 2592000, metadata: { received_at: received, category } });
}
// Seed realistic statuses through the same compiled moderation implementation.
// RPC is exercised via HTTP below; no SQL fixtures bypass status rules.
async function dispatch(path, options = {}) {
  const headers = new Headers(options.headers);
  headers.set('cf-access-jwt-assertion', jwt);
  return mf.dispatchFetch(origin + path, { ...options, headers, redirect: 'manual' });
}
const first = await dispatch('/api/reports');
if (first.status !== 200) throw new Error('Compiled Worker preview initialization failed: ' + first.status);
const csrf = (await (await dispatch('/api/session')).json()).csrf;
for (const n of [3, 5, 7, 9, 11]) {
  const path = '/api/reports/00000000-0000-4000-8000-' + String(n).padStart(12, '0');
  const options = status => ({ method: 'PATCH', headers: { origin, 'content-type': 'application/json', 'x-osia-csrf': csrf }, body: JSON.stringify({ status, version: status === 'in_progress' ? 1 : 2 }) });
  if ((await dispatch(path, options('in_progress'))).status !== 200) throw new Error('Synthetic status setup failed');
  if (n % 3 !== 0 && (await dispatch(path, options('processed'))).status !== 200) throw new Error('Synthetic status setup failed');
}
const server = createServer(async (request, response) => {
  try {
    if (request.headers.host !== '127.0.0.1:8790') { response.writeHead(403).end(); return; }
    const headers = new Headers();
    for (const [key, value] of Object.entries(request.headers)) if (typeof value === 'string' && !['host', 'connection', 'cookie', 'cf-access-jwt-assertion'].includes(key)) headers.set(key, value);
    // Translate loopback browser Origin to the isolated Worker's configured origin.
    if (headers.get('origin') === 'http://127.0.0.1:8790') headers.set('origin', origin);
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const result = await dispatch(request.url, { method: request.method, headers, ...(chunks.length ? { body: Buffer.concat(chunks) } : {}) });
    const responseHeaders = new Headers(result.headers);
    const location = responseHeaders.get('location');
    if (location) {
      const target = new URL(location, origin);
      if (target.origin !== origin) throw new Error('Unexpected synthetic preview redirect');
      responseHeaders.set('location', 'http://127.0.0.1:8790' + target.pathname + target.search);
    }
    response.writeHead(result.status, Object.fromEntries(responseHeaders)); response.end(Buffer.from(await result.arrayBuffer()));
  } catch { response.writeHead(503).end('Synthetic preview unavailable'); }
});
server.listen(8790, '127.0.0.1', () => console.log('Synthetic compiled Worker preview: http://127.0.0.1:8790/reports'));
async function stop() { server.close(); await mf.dispose(); process.exit(0); }
process.on('SIGINT', stop); process.on('SIGTERM', stop);
