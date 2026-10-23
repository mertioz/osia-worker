import { test, expect } from '@playwright/test';
const firstId = '00000000-0000-4000-8000-000000000001';

test('compiled Worker: root redirect, stable loading, chronological pagination and owner timezone', async ({ page }) => {
  const requests = [];
  page.on('request', request => { if (request.url().includes('/api/')) requests.push(request.url()); });
  await page.goto('/');
  await expect(page).toHaveURL('http://127.0.0.1:8790/reports');
  await expect(page.locator('#rows tr')).toHaveCount(25);
  await expect(page.locator('#count-new')).toHaveText('27');
  await expect(page.locator('#count-in_progress')).toHaveText('2');
  await expect(page.locator('#count-processed')).toHaveText('3');
  await expect(page.locator('#timezone')).toContainText('America/New_York');
  // Regression: an overflowing 30-day browser timeout previously reloaded in 1ms.
  await page.waitForTimeout(300); expect(requests).toHaveLength(2);
  const ids = await page.locator('#rows .reference').evaluateAll(nodes => nodes.map(n => n.title));
  expect(ids[0]).toBe(firstId); expect(ids.at(-1)).toMatch(/000000000025$/);
  await page.locator('#next').click(); await expect(page.locator('#rows tr')).toHaveCount(7);
  expect(await page.locator('#rows .reference').first().getAttribute('title')).toMatch(/000000000026$/);
  await expect(page.locator('#next')).toBeDisabled();
  await page.locator('#previous').click(); await expect(page.locator('#rows tr')).toHaveCount(25);
  await page.screenshot({ path: 'test-evidence/admin-desktop-en.png', fullPage: true });
});

test('French narrow viewport, filters, empty state and local date boundaries', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/reports'); await expect(page.locator('#rows tr')).toHaveCount(25);
  await page.locator('#language').selectOption('fr');
  await expect(page).toHaveTitle('OSIA · Signalements de contenu');
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
  await page.locator('#category').selectOption('sexual'); await page.locator('#status').selectOption('processed');
  await page.locator('#filters button[type=submit]').click(); await expect(page.locator('#rows tr')).toHaveCount(1);
  await expect(page.locator('#rows td:nth-child(2)')).toHaveText('Contenu sexuel');
  await expect(page.locator('#count-processed')).toHaveText('1');
  await page.locator('#from').fill('2099-01-01'); await page.locator('#to').fill('2099-01-02');
  const request = page.waitForRequest(r => r.url().includes('/api/reports?'));
  await page.locator('#filters button[type=submit]').click();
  const query = new URL((await request).url()).searchParams;
  expect(query.get('from')).toBe('2099-01-01T05:00:00.000Z');
  expect(query.get('to')).toBe('2099-01-03T05:00:00.000Z');
  await expect(page.locator('#state')).toContainText('Aucun signalement ici');
  await expect(page.locator('#rows tr')).toHaveCount(0);
  await expect(page.locator('#count-new')).toHaveText('0');
  await page.screenshot({ path: 'test-evidence/admin-mobile-empty-fr.png', fullPage: true });
});

test('plain submitted text, explicit read/process/reopen and correct counts', async ({ page }) => {
  await page.goto('/reports'); await page.locator('#rows tr:first-child button').click();
  await expect(page.locator('#detail .submitted').first()).toContainText('<img src=x onerror="window.xss=true">');
  await expect(page.locator('#detail img')).toHaveCount(0);
  expect(await page.evaluate(() => window.xss)).toBeUndefined();
  await expect(page.locator('#detail .status-new')).toBeVisible();
  await page.getByRole('button', { name: 'Mark read · start review', exact: true }).click();
  await expect(page.locator('#detail .status-in_progress')).toBeVisible();
  await expect(page.locator('#count-in_progress')).toHaveText('3');
  await page.getByRole('button', { name: 'Mark processed', exact: true }).click();
  await expect(page.locator('#detail .status-processed')).toBeVisible();
  await expect(page.locator('#count-processed')).toHaveText('4');
  await expect(page.locator('#detail .history li')).toHaveCount(2);
  await page.getByRole('button', { name: 'Reopen review', exact: true }).click();
  await expect(page.locator('#detail .status-in_progress')).toBeVisible();
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
  await page.screenshot({ path: 'test-evidence/admin-detail-mobile-en.png' });
  await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
  await expect(page.locator('#detail')).not.toBeVisible(); await expect(page.locator('#rows tr')).toHaveCount(0);
});

test('loading, sanitized error and retry states', async ({ page }) => {
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  await page.route('**/api/reports?*', async route => { await wait; await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"temporarily_unavailable"}' }); });
  await page.goto('/reports'); await expect(page.locator('#state')).toContainText('Loading reports');
  release(); await expect(page.locator('#alert')).toContainText('could not be loaded');
  await expect(page.getByRole('button', { name: 'Try again', exact: true })).toBeVisible();
  await page.unroute('**/api/reports?*');
  await page.getByRole('button', { name: 'Try again', exact: true }).click();
  await expect(page.locator('#rows tr')).toHaveCount(25); await expect(page.locator('#alert')).toBeHidden();
});

test('session failure clears private content and direct mutation requires CSRF', async ({ page, request }) => {
  const response = await request.patch('/api/reports/' + firstId, { data: { status: 'processed', version: 4 } });
  expect(response.status()).toBe(403); expect(response.headers()['cache-control']).toContain('no-store');
  await page.goto('/reports'); await expect(page.locator('#rows tr')).toHaveCount(25);
  await page.route('**/api/session', route => route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"authentication_required"}' }));
  await page.locator('#refresh').click(); await expect(page.locator('#alert')).toContainText('Your session has ended');
  await expect(page.locator('#rows tr')).toHaveCount(0); await expect(page.locator('#count-new')).toHaveText('—');
});

test('concurrent update prompts review of the current version', async ({ page, request }) => {
  await page.goto('/reports'); await expect(page.locator('#rows tr')).toHaveCount(25);
  await page.locator('#rows tr:nth-child(2) button').click();
  await expect(page.locator('#detail .status-new')).toBeVisible();
  const session = await (await request.get('/api/session')).json();
  const response = await request.patch('/api/reports/00000000-0000-4000-8000-000000000002', {
    headers: { origin: 'http://127.0.0.1:8790', 'x-osia-csrf': session.csrf }, data: { status: 'in_progress', version: 1 },
  });
  expect(response.status()).toBe(200);
  await page.getByRole('button', { name: 'Mark read · start review', exact: true }).click();
  await expect(page.locator('#detail .status-in_progress')).toBeVisible();
  await expect(page.locator('#alert')).toContainText('changed in another tab');
});
