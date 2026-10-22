import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { REPORT_RETENTION_SECONDS } from '../src/content_reports.js';

function harness({ limited = false, failure = false } = {}) {
  const writes = [];
  return { writes, env: {
    REPORT_LIMITER: { limit: async () => ({ success: !limited }) },
    REPORT_GLOBAL_LIMITER: { limit: async () => ({ success: true }) },
    CONTENT_REPORTS: { put: async (...args) => {
      if (failure) throw new Error('private storage context must not be echoed');
      writes.push(args);
    } },
  } };
}
const sample = { schema_version: 1, category: 'other', text: 'Synthetic report', details: '' };
function request(body = sample, headers = {}) {
  return new Request('https://reports.example/v1/reports', {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

test('acknowledges only stored selected text, with expiry and a private receipt', async () => {
  const { env, writes } = harness();
  const response = await worker.fetch(request(), env);
  assert.equal(response.status, 201);
  const receipt = await response.json();
  assert.equal(receipt.received, true);
  assert.match(receipt.report_id, /^[0-9a-f-]{36}$/);
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], `report:${receipt.report_id}`);
  assert.deepEqual(JSON.parse(writes[0][1]), {
    ...sample, report_id: receipt.report_id, received_at: writes[0][2].metadata.received_at,
  });
  assert.equal(writes[0][2].expirationTtl, REPORT_RETENTION_SECONDS);
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('rejects malformed, oversized and unexpected sensitive fields without storing', async () => {
  for (const body of [null, [], '{', { ...sample, token: 'test-only-unexpected' },
    { ...sample, text: '' }, { ...sample, text: 'x'.repeat(3001) },
    { ...sample, details: 'x'.repeat(501) }, { ...sample, category: 'unknown' },
    { ...sample, schema_version: 2 }, 'x'.repeat(21 * 1024)]) {
    const { env, writes } = harness();
    assert.equal((await worker.fetch(request(body), env)).status, 400);
    assert.equal(writes.length, 0);
  }
});

test('bounds chunked input even without content-length', async () => {
  const { env, writes } = harness();
  const stream = new ReadableStream({ start(controller) {
    controller.enqueue(new Uint8Array(12 * 1024));
    controller.enqueue(new Uint8Array(12 * 1024));
    controller.close();
  } });
  const response = await worker.fetch(new Request('https://reports.example/v1/reports', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: stream, duplex: 'half',
  }), env);
  assert.equal(response.status, 400);
  assert.equal(writes.length, 0);
});

test('storage failure and rate limit never fabricate receipt or echo content', async () => {
  for (const [options, status] of [[{ limited: true }, 429], [{ failure: true }, 503]]) {
    const { env, writes } = harness(options);
    const response = await worker.fetch(request(), env);
    assert.equal(response.status, status);
    const result = await response.json();
    assert.equal(result.received, undefined);
    assert.equal(result.report_id, undefined);
    assert.equal(JSON.stringify(result).includes(sample.text), false);
    assert.equal(writes.length, 0);
  }
});

test('reports cannot be read publicly and unsolicited browser origins are rejected', async () => {
  const { env, writes } = harness();
  assert.equal((await worker.fetch(new Request('https://reports.example/v1/reports'), env)).status, 404);
  assert.equal((await worker.fetch(request(sample, { origin: 'https://unrelated.example' }), env)).status, 403);
  assert.equal(writes.length, 0);
});
