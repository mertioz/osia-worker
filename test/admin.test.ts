import { env } from 'cloudflare:workers';
import { runInDurableObject, evictDurableObject, reset } from 'cloudflare:test';
import { beforeAll, afterEach, describe, it, expect, vi } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker from '../src/admin/index';
import { filters, RETENTION_MS } from '../src/admin/contracts';

const origin = 'https://admin.osia.space';
const issuer = 'https://test-only.cloudflareaccess.com';
const audience = 'a'.repeat(64), ownerSub = 'test-only-owner', actor = 'b'.repeat(64);
const configuredEnv = () => ({ ...env, ADMIN_ORIGIN: origin, ACCESS_ISSUER: issuer, ACCESS_AUD: audience, ADMIN_EMAIL: 'owner@example.com', ADMIN_SUB: ownerSub });
let privateKey: CryptoKey, publicKey: CryptoKey, jwt: string;
const rawInbox = () => env.MODERATION.getByName('owner-inbox-v1');
const unwrap = async (promise) => { const result = await promise; if (!result.ok) throw new Error(result.error); return result.value; };
const inbox = () => ({
  list: (...args) => unwrap(rawInbox().list(...args)),
  detail: (...args) => unwrap(rawInbox().detail(...args)),
  change: (...args) => unwrap(rawInbox().change(...args)),
  authorizeCall: (...args) => rawInbox().authorizeCall(...args),
  synchronize: () => rawInbox().synchronize(),
  maintenance: () => rawInbox().maintenance(),
});
const id = (n: number) => `00000000-0000-4000-8000-${n.toString().padStart(12, '0')}`;
const f = (query = '') => filters(new URL(origin + '/api/reports?' + query));

async function token(claims = {}, options: { issuer?: string; audience?: string; expires?: number; key?: CryptoKey } = {}) {
  return new SignJWT({ type: 'app', email: 'owner@example.com', ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'test-only-key' })
    .setIssuer(options.issuer ?? issuer).setAudience(options.audience ?? audience).setSubject((claims as { sub?: string }).sub ?? ownerSub)
    .setIssuedAt().setExpirationTime(options.expires ?? Math.floor(Date.now() / 1000) + 3600).sign(options.key ?? privateKey);
}
async function call(path = '/api/reports', options: { method?: string; headers?: Record<string, string>; body?: string; token?: string | null; env?: Env } = {}) {
  return worker.fetch(new Request(origin + path, {
    method: options.method ?? 'GET', headers: { ...(options.token === null ? {} : { 'cf-access-jwt-assertion': options.token ?? jwt }), ...options.headers }, body: options.body,
  }), options.env ?? configuredEnv());
}
async function seed(n: number, received = Date.now() - n * 1000, category = 'other', additions = {}) {
  const report = { schema_version: 1, report_id: id(n), received_at: new Date(received).toISOString(), category,
    text: `Synthetic selected reply ${n}`, details: 'Synthetic note', ...additions };
  await env.CONTENT_REPORTS.put('report:' + id(n), JSON.stringify(report), {
    expirationTtl: 2592000, metadata: { received_at: report.received_at, category },
  });
  return report;
}
async function scan() { await inbox().synchronize(); }
async function csrf() { return (await (await call('/api/session')).json() as { csrf: string }).csrf; }
async function change(n: number, status: string, version = 1, extra = {}) {
  return call('/api/reports/' + id(n), { method: 'PATCH', headers: {
    origin, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json', 'x-osia-csrf': await csrf(), ...extra,
  }, body: JSON.stringify({ status, version }) });
}
beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true })); jwt = await token();
});
afterEach(async () => { vi.restoreAllMocks(); await reset(); });
// The real verifier consumes locally signed tokens and real WebCrypto. Only
// the external public-key HTTP response is stubbed, never authorization.
function mockKeys() {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async request => {
    expect(String(request)).toBe(issuer + '/cdn-cgi/access/certs');
    return Response.json({ keys: [{ ...await exportJWK(publicKey), alg: 'RS256', use: 'sig', kid: 'test-only-key' }] });
  });
}

describe('origin and API authorization', () => {
  it('fails closed without owner configuration, including page and assets', async () => {
    for (const path of ['/reports', '/admin.js', '/admin.css', '/favicon.svg', '/api/session', '/api/reports', '/api/reports/' + id(1)]) {
      expect((await call(path, { env: env as Env })).status).toBe(503);
    }
  });
  it('requires signed Access identity on every page, asset, direct read and write', async () => {
    mockKeys();
    for (const tokenValue of [null, 'spoofed-header', await token({ sub: 'stranger', email: 'stranger@example.com' })]) {
      for (const path of ['/reports', '/admin.js', '/admin.css', '/favicon.svg', '/api/session', '/api/reports', '/api/reports/' + id(1)]) {
        const response = await call(path, { token: tokenValue });
        expect(response.status).toBe(tokenValue?.includes('.') ? 403 : 401);
        expect(await response.text()).not.toContain('Synthetic');
        expect(response.headers.get('cache-control')).toContain('no-store');
      }
      const response = await call('/api/reports/' + id(1), { method: 'PATCH', token: tokenValue, body: '{}' });
      expect([401, 403]).toContain(response.status);
    }
  });
  it('rejects wrong issuer/audience, expired/future tokens, bad signatures, service tokens and mismatched owner claims', async () => {
    mockKeys();
    const other = await generateKeyPair('RS256');
    for (const invalid of [await token({}, { issuer: 'https://attacker.example' }), await token({}, { audience: 'wrong' }),
      await token({}, { expires: Math.floor(Date.now() / 1000) - 1 }), await token({ nbf: Math.floor(Date.now() / 1000) + 60 }),
      await token({}, { key: other.privateKey }), await token({ type: 'service' }), await token({ email: 'other@example.com' }),
      await token({ sub: 'other' })]) expect([401, 403]).toContain((await call('/api/reports', { token: invalid })).status);
  });
  it('never trusts email headers, rejects alternate host and cross-site reads', async () => {
    mockKeys();
    expect((await call('/api/reports', { token: null, headers: { 'cf-access-authenticated-user-email': 'owner@example.com' } })).status).toBe(401);
    expect((await call('/api/reports', { headers: { origin: 'https://osia.space' } })).status).toBe(403);
    expect((await call('/api/reports', { headers: { 'sec-fetch-site': 'same-site' } })).status).toBe(403);
    expect((await worker.fetch(new Request('https://alternate.workers.dev/api/reports', { headers: { 'cf-access-jwt-assertion': jwt } }), configuredEnv())).status).toBe(403);
  });
  it('rejects workers.dev, version previews and alternative origins even with the valid owner JWT', async () => {
    mockKeys();
    for (const alternate of ['https://osia-reports-admin.example.workers.dev',
      'https://version-osia-reports-admin.example.workers.dev', 'https://osia.space',
      'https://relay.osia.space', 'http://admin.osia.space', 'https://admin.osia.space:8443']) {
      for (const path of ['/reports', '/admin.js', '/admin.css', '/favicon.svg', '/api/session',
        '/api/reports', '/api/reports/' + id(1)]) {
        for (const method of ['GET', 'PATCH', 'OPTIONS', 'HEAD']) {
          const response = await worker.fetch(new Request(alternate + path, { method, headers: {
            'cf-access-jwt-assertion': jwt, host: 'admin.osia.space',
            'x-forwarded-host': 'admin.osia.space', 'x-forwarded-proto': 'https',
          } }), configuredEnv());
          expect(response.status).toBe(403);
          expect(response.headers.get('cache-control')).toContain('no-store');
          expect(await response.text()).not.toContain('Synthetic');
        }
      }
    }
  });
  it('allows the authenticated Access return navigation only to the shell, never APIs or mutations', async () => {
    mockKeys();
    for (const site of ['cross-site', 'same-site']) {
      const headers = { 'sec-fetch-site': site, 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
      expect((await call('/reports', { headers })).status).toBe(200);
      expect((await call('/reports', { headers, token: null })).status).toBe(401);
      expect((await call('/reports', { headers, token: await token({ sub: 'stranger' }) })).status).toBe(403);
      expect((await call('/reports', { headers: { ...headers, origin: 'https://attacker.example' } })).status).toBe(403);
      for (const path of ['/api/session', '/api/reports', '/api/reports/' + id(1), '/admin.js', '/index.html'])
        expect((await call(path, { headers })).status).toBe(403);
      expect((await call('/reports', { method: 'PATCH', headers })).status).toBe(403);
      expect((await call('/reports', { headers: { ...headers, 'sec-fetch-mode': 'cors' } })).status).toBe(403);
      expect((await call('/reports', { headers: { ...headers, 'sec-fetch-dest': 'iframe' } })).status).toBe(403);
    }
  });
  it('does not authorize another account member or a matching owner email with a different subject', async () => {
    mockKeys();
    for (const claims of [{ email: 'member@example.com', sub: 'test-only-member' },
      { email: 'owner@example.com', sub: 'test-only-member' },
      { email: 'member@example.com', sub: ownerSub }]) {
      const signed = await token(claims);
      for (const method of ['GET', 'PATCH', 'OPTIONS']) {
        expect((await call('/api/reports/' + id(1), { method, token: signed })).status).toBe(403);
      }
    }
    // A service credential or copied email header cannot substitute for Access.
    const response = await call('/api/reports', { token: null, headers: {
      'cf-access-authenticated-user-email': 'owner@example.com',
      'cf-access-client-id': 'test-only-service', 'cf-access-client-secret': 'test-only-secret',
    } });
    expect(response.status).toBe(401);
  });
  it('serves authenticated shell with restrictive headers and no content or credentials', async () => {
    mockKeys();
    const response = await call('/reports'); expect(response.status).toBe(200);
    const html = await response.text(); expect(html).toContain('Content reports'); expect(html).not.toContain(jwt);
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('cdn-cache-control')).toBe('no-store');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect((await call('/index.html')).status).toBe(404);
  });
  it('requires origin, CSRF, JSON and an exact bounded status body', async () => {
    mockKeys(); await seed(1); await scan();
    const path = '/api/reports/' + id(1), valid = await csrf();
    for (const headers of [{}, { origin }, { origin, 'x-osia-csrf': 'x'.repeat(64) },
      { origin: 'https://attacker.example', 'x-osia-csrf': valid },
      { origin, 'x-osia-csrf': valid, 'sec-fetch-site': 'cross-site' }]) {
      expect((await call(path, { method: 'PATCH', headers, body: '{}' })).status).toBe(403);
    }
    const headers = { origin, 'x-osia-csrf': valid, 'content-type': 'application/json' };
    expect((await call(path, { method: 'PATCH', headers: { ...headers, 'content-type': 'text/plain' }, body: '{}' })).status).toBe(415);
    for (const body of ['{', '[]', '{}', '{"status":"in_progress","version":1,"text":"new content"}', '{"status":"in_progress","version":-1}'])
      expect((await call(path, { method: 'PATCH', headers, body })).status).toBe(400);
    expect((await call(path, { method: 'PATCH', headers, body: ' '.repeat(1025) })).status).toBe(413);
    expect((await change(1, 'in_progress')).status).toBe(200);
  });
  it('applies edge and globally consistent owner rate limits', async () => {
    mockKeys();
    const limited = { ...configuredEnv(), ADMIN_EDGE_LIMITER: { limit: async () => ({ success: false }) } };
    const response = await call('/api/reports', { env: limited as Env });
    expect(response.status).toBe(429); expect(response.headers.get('retry-after')).toBe('60');
    for (let i = 0; i < 120; i++) expect(await inbox().authorizeCall(actor)).toBe(true);
    expect(await inbox().authorizeCall(actor)).toBe(false);
  });
});

describe('private index and moderation', () => {
  it('orders by receipt then ID descending; paginates server-side without bodies', async () => {
    mockKeys(); const now = Date.now();
    await seed(1, now - 100); await seed(2, now - 100); await seed(3, now - 1000, 'harmful');
    const first = await inbox().list(f('limit=1'), actor);
    expect(first.ready).toBe(true); expect(first.reports?.map(r => r.id)).toEqual([id(2)]);
    expect(first.counts).toEqual({ new: 3, in_progress: 0, processed: 0 });
    expect(JSON.stringify(first)).not.toContain('Synthetic');
    const second = await inbox().list(f('limit=1&cursor=' + first.next_cursor), actor);
    expect(second.reports?.map(r => r.id)).toEqual([id(1)]);
    const third = await inbox().list(f('limit=1&cursor=' + second.next_cursor), actor);
    expect(third.reports?.map(r => r.id)).toEqual([id(3)]); expect(third.next_cursor).toBeNull();
  });
  it('filters category, local-day UTC boundaries and status with accurate scoped counts', async () => {
    const now = Date.now(); await seed(1, now - 1000, 'harmful'); await seed(2, now - 2000, 'other');
    await seed(3, now - 86400000, 'harmful'); await scan();
    await inbox().change(id(1), 'in_progress', 1, actor);
    const query = `category=harmful&status=new&from=${new Date(now - 5000).toISOString()}&to=${new Date(now).toISOString()}`;
    const result = await inbox().list(f(query), actor);
    expect(result.reports).toEqual([]); expect(result.counts).toEqual({ new: 0, in_progress: 1, processed: 0 });
    for (const query of ['limit=51', 'limit=0', 'category=unknown', 'status=read', 'from=2026-02-30T00:00:00.000Z', 'token=x', 'status=new&status=processed'])
      expect(() => f(query)).toThrow();
  });
  it('isolates requested report, allowlists metadata and renders no hidden extra data', async () => {
    await seed(1, Date.now() - 1000, 'other', { text: '<img src=x onerror=alert(1)>', api_key: 'test-only-extra', history: ['test-only-history'] });
    await seed(2); await scan();
    const result = await inbox().detail(id(1), actor);
    expect(result.report.text).toBe('<img src=x onerror=alert(1)>');
    expect(JSON.stringify(result)).not.toContain('test-only-extra'); expect(JSON.stringify(result)).not.toContain('test-only-history');
    expect(result.report.status).toBe('new'); expect(result.report.read_at).toBeNull();
    await expect(inbox().detail(id(99), actor)).rejects.toThrow('report_not_found');
    await env.CONTENT_REPORTS.put('report:' + id(1), JSON.stringify({ schema_version: 1, report_id: id(2) }));
    await expect(inbox().detail(id(1), actor)).rejects.toThrow('invalid_report');
  });
  it('requires explicit read before processed and rejects concurrent stale updates', async () => {
    await seed(1); await scan();
    await expect(inbox().change(id(1), 'processed', 1, actor)).rejects.toThrow('invalid_transition');
    const results = await Promise.allSettled([inbox().change(id(1), 'in_progress', 1, actor), inbox().change(id(1), 'in_progress', 1, actor)]);
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(r => r.status === 'rejected')).toHaveLength(1);
    const processed = await inbox().change(id(1), 'processed', 2, actor);
    expect(processed.report.version).toBe(3); expect(processed.report.read_at).not.toBeNull();
    expect(processed.report.processed_at).not.toBeNull();
    await evictDurableObject(rawInbox());
    expect((await inbox().detail(id(1), actor)).report.status).toBe('processed');
    expect((await inbox().change(id(1), 'in_progress', 3, actor)).report.processed_at).toBeNull();
  });
  it('rejects stale/filter-mismatched cursors after inbox status changes', async () => {
    await seed(1); await seed(2); const result = await inbox().list(f('limit=1'), actor);
    await expect(inbox().list(f('limit=1&category=harmful&cursor=' + result.next_cursor), actor)).rejects.toThrow('invalid_cursor');
    await inbox().change(id(1), 'in_progress', 1, actor);
    await expect(inbox().list(f('limit=1&cursor=' + result.next_cursor), actor)).rejects.toThrow('inbox_changed');
    await expect(inbox().list(f('cursor=garbage'), actor)).rejects.toThrow('invalid_cursor');
  });
  it('removes expired reports and private audit records; processing never extends KV TTL', async () => {
    const received = Date.now() - RETENTION_MS + 100000;
    await seed(1, received); await seed(2, received - 200000); await scan();
    const before = (await env.CONTENT_REPORTS.list()).keys.find(k => k.name === 'report:' + id(1))!.expiration;
    await inbox().change(id(1), 'in_progress', 1, actor);
    await inbox().change(id(1), 'processed', 2, actor);
    const after = (await env.CONTENT_REPORTS.list()).keys.find(k => k.name === 'report:' + id(1))!.expiration;
    expect(after).toBe(before);
    expect((await inbox().list(f(), actor)).reports?.map(r => r.id)).toEqual([id(1)]);
    const original = Date.now; vi.spyOn(Date, 'now').mockImplementation(() => original() + 200000);
    await inbox().maintenance();
    expect((await inbox().list(f(), actor)).reports).toEqual([]);
    await expect(inbox().detail(id(1), actor)).rejects.toThrow('report_not_found');
    await runInDurableObject(rawInbox(), (_instance, state) => {
      expect(state.storage.sql.exec('SELECT * FROM reports').toArray()).toEqual([]);
      expect(state.storage.sql.exec("SELECT * FROM audit WHERE report_id IS NOT NULL").toArray()).toEqual([]);
    });
  });
  it('handles early KV deletion, malformed metadata and missing bodies safely', async () => {
    await seed(1); await env.CONTENT_REPORTS.put('report:invalid', '{}', { metadata: { received_at: 'invalid', category: 'other' } });
    await scan(); expect((await inbox().list(f(), actor)).invalid_records).toBe(1);
    await env.CONTENT_REPORTS.delete('report:' + id(1));
    await expect(inbox().detail(id(1), actor)).rejects.toThrow('report_not_found');
    expect((await inbox().list(f(), actor)).counts?.new).toBe(0);
  });
  it('stores audit facts only and never copies submitted bodies into SQLite', async () => {
    await seed(1); await scan(); await inbox().detail(id(1), actor); await inbox().change(id(1), 'in_progress', 1, actor);
    await runInDurableObject(rawInbox(), (_instance, state) => {
      const audits = state.storage.sql.exec('SELECT * FROM audit').toArray();
      expect(audits.map(r => r.action)).toEqual(['view', 'status']);
      expect(JSON.stringify(audits)).not.toContain('Synthetic');
      expect(JSON.stringify(audits)).not.toContain('owner@example.com');
      const columns = state.storage.sql.exec('PRAGMA table_info(reports)').toArray().map(r => r.name);
      expect(columns).not.toContain('text'); expect(columns).not.toContain('details');
    });
  });
  it('stages multi-invocation scans atomically, resumes the cursor and coalesces concurrent scans', async () => {
    await runInDurableObject(rawInbox(), async (instance, state) => {
      const original = instance.env.CONTENT_REPORTS;
      let calls = 0;
      instance.env.CONTENT_REPORTS = { list: async options => {
        const page = calls++;
        expect(options.cursor || '').toBe(page === 0 ? '' : String(page));
        return { keys: [{ name: 'report:' + id(page + 1), expiration: Math.floor(Date.now() / 1000) + 5000,
          metadata: { received_at: new Date(Date.now() - 1000).toISOString(), category: 'other' } }],
        list_complete: page === 5, cursor: String(page + 1) };
      } };
      try {
        await Promise.all([instance.synchronize(), instance.synchronize()]);
        expect(calls).toBe(5);
        expect(state.storage.sql.exec('SELECT completed FROM sync').one().completed).toBe(0);
        expect(state.storage.sql.exec('SELECT * FROM reports').toArray()).toHaveLength(0);
        expect(state.storage.sql.exec('SELECT * FROM scan').toArray()).toHaveLength(5);
        const result = await instance.list(f(), actor);
        expect(result.ok).toBe(true); expect(result.value.counts.new).toBe(6); expect(calls).toBe(6);
        expect(state.storage.sql.exec('SELECT * FROM scan').toArray()).toHaveLength(0);
      } finally { instance.env.CONTENT_REPORTS = original; }
    });
  });
  it('retains moderation status through disappearing and reappearing KV metadata', async () => {
    await seed(1); await scan(); await inbox().change(id(1), 'in_progress', 1, actor);
    await runInDurableObject(rawInbox(), async (instance, state) => {
      const original = instance.env.CONTENT_REPORTS;
      instance.env.CONTENT_REPORTS = { list: async () => ({ keys: [], list_complete: true }) };
      state.storage.sql.exec('UPDATE sync SET completed=0');
      try {
        await instance.synchronize();
        expect(state.storage.sql.exec('SELECT visible,status,version FROM reports').one()).toEqual({ visible: 0, status: 'in_progress', version: 2 });
      } finally { instance.env.CONTENT_REPORTS = original; }
      state.storage.sql.exec('UPDATE sync SET completed=0');
    });
    await scan(); expect((await inbox().detail(id(1), actor)).report.status).toBe('in_progress');
  });
  it('sanitizes sync failures and does not serve partial-success counts', async () => {
    await seed(1); await scan();
    await runInDurableObject(rawInbox(), async (instance, state) => {
      const original = instance.env.CONTENT_REPORTS;
      state.storage.sql.exec('UPDATE sync SET completed=0');
      instance.env.CONTENT_REPORTS = { list: async () => { throw new Error('test-only-private-exception'); } };
      try {
        expect(await instance.list(f(), actor)).toEqual({ ok: false, error: 'sync_unavailable', status: 503 });
        expect(state.storage.sql.exec('SELECT * FROM reports').toArray()).toHaveLength(1);
      } finally { instance.env.CONTENT_REPORTS = original; }
    });
  });
  it('rechecks retention after KV I/O before serving detail or committing a mutation', async () => {
    await seed(1, Date.now() - RETENTION_MS + 2000); await scan();
    await runInDurableObject(rawInbox(), async (instance) => {
      const original = instance.env.CONTENT_REPORTS, clock = Date.now;
      instance.env.CONTENT_REPORTS = { get: async key => {
        const value = await original.get(key);
        vi.spyOn(Date, 'now').mockImplementation(() => clock() + 3000);
        return value;
      } };
      try { expect(await instance.detail(id(1), actor)).toEqual({ ok: false, error: 'report_not_found', status: 404 }); }
      finally { vi.restoreAllMocks(); instance.env.CONTENT_REPORTS = original; }
    });
  });
});
