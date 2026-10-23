import { createRemoteJWKSet, jwtVerify } from 'jose';
import { timingSafeEqual } from 'node:crypto';
import { requireThat } from './contracts';

// Cache public verification keys only; never JWTs, identities or report data.
let keyCache: { issuer: string; keys: ReturnType<typeof createRemoteJWKSet> } | undefined;
export async function digest(value: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))),
    b => b.toString(16).padStart(2, '0')).join('');
}
export function configured(env: Env): boolean {
  return /^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.ACCESS_ISSUER) &&
    /^[a-f0-9]{64}$/.test(env.ACCESS_AUD) && /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(env.ADMIN_EMAIL) &&
    /^[A-Za-z0-9_-]{1,128}$/.test(env.ADMIN_SUB) &&
    /^https:\/\/[a-z0-9.-]+$/.test(env.ADMIN_ORIGIN);
}
export async function authenticate(request: Request, env: Env) {
  const token = request.headers.get('cf-access-jwt-assertion');
  requireThat(token && token.length <= 16000, 401, 'authentication_required');
  if (keyCache?.issuer !== env.ACCESS_ISSUER) keyCache = {
    issuer: env.ACCESS_ISSUER,
    keys: createRemoteJWKSet(new URL(`${env.ACCESS_ISSUER}/cdn-cgi/access/certs`), { timeoutDuration: 5000 }),
  };
  let payload;
  try {
    ({ payload } = await jwtVerify(token, keyCache.keys, {
      algorithms: ['RS256'], issuer: env.ACCESS_ISSUER, audience: env.ACCESS_AUD,
      requiredClaims: ['exp', 'iat', 'sub', 'email', 'type'],
    }));
  } catch { requireThat(false, 401, 'authentication_required'); }
  requireThat(payload.type === 'app' && payload.sub === env.ADMIN_SUB &&
    typeof payload.email === 'string' && payload.email.toLowerCase() === env.ADMIN_EMAIL.toLowerCase() &&
    typeof payload.iat === 'number' && payload.iat <= Date.now() / 1000, 403, 'owner_required');
  return { actor: await digest(payload.sub), csrf: await digest(`osia-admin-csrf-v1:${token}`), expires: payload.exp! * 1000 };
}
export function checkMutation(request: Request, env: Env, csrf: string) {
  requireThat(request.headers.get('origin') === env.ADMIN_ORIGIN &&
    (!request.headers.has('sec-fetch-site') || request.headers.get('sec-fetch-site') === 'same-origin'), 403, 'origin_denied');
  const received = request.headers.get('x-osia-csrf') || '';
  requireThat(/^[a-f0-9]{64}$/.test(received) && timingSafeEqual(new TextEncoder().encode(received),
    new TextEncoder().encode(csrf)), 403, 'csrf_denied');
}
export function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const key of ['access-control-allow-origin', 'etag', 'last-modified']) headers.delete(key);
  const policy: Record<string, string> = {
    'cache-control': 'private, no-store, max-age=0', 'cdn-cache-control': 'no-store',
    'cloudflare-cdn-cache-control': 'no-store', 'pragma': 'no-cache', 'expires': '0',
    'vary': 'Cf-Access-Jwt-Assertion, Cookie', 'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', 'x-robots-tag': 'noindex, nofollow, noarchive',
    'strict-transport-security': 'max-age=31536000', 'cross-origin-resource-policy': 'same-origin',
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  };
  Object.entries(policy).forEach(([key, value]) => headers.set(key, value));
  return new Response(response.body, { status: response.status, headers });
}
