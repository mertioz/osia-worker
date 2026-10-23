export const RETENTION_MS = 30 * 86400_000;
export const CATEGORIES = ['harmful', 'sexual', 'violence', 'deceptive', 'other'] as const;
export const STATUSES = ['new', 'in_progress', 'processed'] as const;
export type Category = typeof CATEGORIES[number];
export type Status = typeof STATUSES[number];
export const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export type ReportRow = {
  id: string; received: number; expires: number; category: Category;
  status: Status; version: number; read_at: number | null; processed_at: number | null;
};
export type Filters = { category: string; status: string; from: number; to: number; limit: number; cursor: string };
export class HttpError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}
export function requireThat(condition: unknown, status: number, code: string): asserts condition {
  if (!condition) throw new HttpError(status, code);
}
export function filters(url: URL): Filters {
  const q = url.searchParams;
  requireThat([...q.keys()].every(k => ['category', 'status', 'from', 'to', 'limit', 'cursor'].includes(k)) &&
    [...new Set(q.keys())].every(k => q.getAll(k).length === 1), 400, 'invalid_filters');
  const category = q.get('category') || '', status = q.get('status') || '';
  requireThat(!category || CATEGORIES.includes(category as Category), 400, 'invalid_filters');
  requireThat(!status || STATUSES.includes(status as Status), 400, 'invalid_filters');
  const date = (key: string, fallback: number) => {
    const value = q.get(key);
    if (!value) return fallback;
    requireThat(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value), 400, 'invalid_filters');
    const n = Date.parse(value);
    requireThat(Number.isFinite(n) && new Date(n).toISOString() === value, 400, 'invalid_filters');
    return n;
  };
  const from = date('from', 0), to = date('to', 8640000000000000);
  const limitText = q.get('limit') || '25', limit = Number(limitText);
  requireThat(from < to && /^(?:[1-9]|[1-4][0-9]|50)$/.test(limitText), 400, 'invalid_filters');
  const cursor = q.get('cursor') || '';
  requireThat(cursor.length <= 1500, 400, 'invalid_cursor');
  return { category, status, from, to, limit, cursor };
}
export async function smallJson(request: Request): Promise<Record<string, unknown>> {
  requireThat(request.headers.get('content-type')?.split(';')[0].trim() === 'application/json', 415, 'json_required');
  const reader = request.body?.getReader();
  requireThat(reader, 400, 'invalid_body');
  let text = '', size = 0;
  const decoder = new TextDecoder('utf-8', { fatal: true });
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1024) { await reader.cancel(); throw new HttpError(413, 'body_too_large'); }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    const body: unknown = JSON.parse(text);
    requireThat(body && typeof body === 'object' && !Array.isArray(body), 400, 'invalid_body');
    return body as Record<string, unknown>;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, 'invalid_body');
  } finally { reader.releaseLock(); }
}
