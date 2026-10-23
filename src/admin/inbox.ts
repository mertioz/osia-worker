import { DurableObject } from 'cloudflare:workers';
import { CATEGORIES, HttpError, ID, RETENTION_MS, requireThat, type Category, type Filters, type ReportRow, type Status } from './contracts';

type Sync = { revision: number; completed: number; started: number; cursor: string; scanning: number; invalid: number };
const columns = 'r.id, r.received, r.expires, r.category, r.status, r.version, r.read_at, r.processed_at';

// One coordination atom for the one operator's inbox. No submitted content is
// copied here. KV remains the only report body store and expiry authority.
export class ModerationInbox extends DurableObject<Env> {
  #syncing?: Promise<void>;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY, received INTEGER NOT NULL, expires INTEGER NOT NULL,
        category TEXT NOT NULL, visible INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'new', version INTEGER NOT NULL DEFAULT 1,
        read_at INTEGER, processed_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS timeline ON reports(visible, received DESC, id DESC);
      CREATE INDEX IF NOT EXISTS expiration ON reports(expires);
      CREATE TABLE IF NOT EXISTS scan (id TEXT PRIMARY KEY, received INTEGER, expires INTEGER, category TEXT);
      CREATE TABLE IF NOT EXISTS sync (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER DEFAULT 0,
        completed INTEGER DEFAULT 0, started INTEGER DEFAULT 0, cursor TEXT DEFAULT '',
        scanning INTEGER DEFAULT 0, invalid INTEGER DEFAULT 0
      );
      INSERT OR IGNORE INTO sync(singleton) VALUES(1);
      CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
        report_id TEXT, from_status TEXT, to_status TEXT, version INTEGER, expires INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS audit_expiration ON audit(expires);
      CREATE TABLE IF NOT EXISTS rate (minute INTEGER PRIMARY KEY, count INTEGER NOT NULL);
    `);
  }
  #state() { return this.ctx.storage.sql.exec<Sync>('SELECT * FROM sync WHERE singleton=1').one(); }
  #cleanup() {
    const now = Date.now();
    this.ctx.storage.sql.exec('DELETE FROM reports WHERE expires <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM scan WHERE expires <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM audit WHERE expires <= ?', now);
    this.ctx.storage.sql.exec('DELETE FROM rate WHERE minute < ?', Math.floor(now / 60000));
  }
  #audit(actor: string, action: string, row?: ReportRow, to?: Status) {
    const now = Date.now();
    this.ctx.storage.sql.exec(`INSERT INTO audit(at,actor,action,report_id,from_status,to_status,version,expires)
      VALUES(?,?,?,?,?,?,?,?)`, now, actor, action, row?.id ?? null, row?.status ?? null,
    to ?? null, row?.version ?? null, Math.min(now + RETENTION_MS, row?.expires ?? Infinity));
  }
  // Private methods aren't exposed over RPC. Only this Worker's binding can
  // reach public methods; no DO route or service binding is published.
  async authorizeCall(actor: string) {
    requireThat(/^[a-f0-9]{64}$/.test(actor), 403, 'owner_required');
    this.#cleanup();
    const minute = Math.floor(Date.now() / 60000);
    const row = this.ctx.storage.sql.exec<{ count: number }>(`INSERT INTO rate(minute,count) VALUES(?,1)
      ON CONFLICT(minute) DO UPDATE SET count=count+1 RETURNING count`, minute).one();
    return row.count <= 120;
  }
  async synchronize() {
    if (this.#syncing) return this.#syncing;
    this.#syncing = this.#syncStep();
    try { await this.#syncing; } finally { this.#syncing = undefined; }
  }
  async #syncStep() {
    this.#cleanup();
    let state = this.#state();
    if (!state.scanning && Date.now() - state.completed < 60000) return;
    // Staging persists across invocations; no half-scanned counts are served.
    if (!state.scanning) {
      this.ctx.storage.sql.exec('DELETE FROM scan');
      this.ctx.storage.sql.exec("UPDATE sync SET scanning=1, started=?, cursor='', invalid=0 WHERE singleton=1", Date.now());
      state = this.#state();
    }
    for (let page = 0; page < 5; page++) {
      let batch: KVNamespaceListResult<{ received_at?: string; category?: string }>;
      try {
        batch = await this.env.CONTENT_REPORTS.list({
          prefix: 'report:', limit: 1000, ...(state.cursor ? { cursor: state.cursor } : {}),
        });
      } catch {
        // A failed/invalid KV cursor must not strand the index indefinitely.
        // Discard staging only; completed metadata and moderation stay intact.
        this.ctx.storage.transactionSync(() => {
          this.ctx.storage.sql.exec('DELETE FROM scan');
          this.ctx.storage.sql.exec("UPDATE sync SET scanning=0,cursor='' WHERE singleton=1");
        });
        throw new HttpError(503, 'sync_unavailable');
      }
      const now = Date.now();
      this.ctx.storage.transactionSync(() => {
        let invalid = 0;
        for (const key of batch.keys) {
          const id = key.name.slice(7), received = Date.parse(key.metadata?.received_at || '');
          const category = key.metadata?.category as Category;
          const expires = Math.min(key.expiration ? key.expiration * 1000 : Infinity, received + RETENTION_MS);
          if (!ID.test(id) || !Number.isFinite(received) || received > now ||
              !CATEGORIES.includes(category) || !Number.isFinite(expires)) { invalid++; continue; }
          if (expires <= now) continue;
          this.ctx.storage.sql.exec('INSERT OR REPLACE INTO scan(id,received,expires,category) VALUES(?,?,?,?)',
            id, received, expires, category);
        }
        const cursor = batch.list_complete ? '' : batch.cursor;
        requireThat(batch.list_complete || (cursor && cursor !== state.cursor), 503, 'sync_unavailable');
        this.ctx.storage.sql.exec('UPDATE sync SET cursor=?, invalid=invalid+? WHERE singleton=1', cursor, invalid);
        if (batch.list_complete) {
          const changed = this.ctx.storage.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM (
            SELECT id,received,expires,category FROM scan EXCEPT SELECT id,received,expires,category FROM reports WHERE visible=1
          )`).one().n + this.ctx.storage.sql.exec<{ n: number }>(`SELECT COUNT(*) AS n FROM (
            SELECT id,received,expires,category FROM reports WHERE visible=1 EXCEPT SELECT id,received,expires,category FROM scan
          )`).one().n;
          this.ctx.storage.sql.exec('UPDATE reports SET visible=0');
          this.ctx.storage.sql.exec(`INSERT INTO reports(id,received,expires,category,visible)
            SELECT id,received,expires,category,1 FROM scan WHERE true
            ON CONFLICT(id) DO UPDATE SET visible=1, received=excluded.received,
            expires=MIN(reports.expires, excluded.expires), category=excluded.category`);
          this.ctx.storage.sql.exec(`UPDATE sync SET completed=?, scanning=0, cursor='', revision=revision+? WHERE singleton=1`,
            Date.now(), changed ? 1 : 0);
          this.ctx.storage.sql.exec('DELETE FROM scan');
        }
      });
      state = this.#state();
      if (!state.scanning) break;
    }
  }
  async #result<T>(operation: () => Promise<T>) {
    try { return { ok: true as const, value: await operation() }; }
    catch (error) {
      return { ok: false as const, error: error instanceof HttpError ? error.code : 'temporarily_unavailable',
        status: error instanceof HttpError ? error.status : 503 };
    }
  }
  async list(f: Filters, actor: string) { return this.#result(() => this.#list(f, actor)); }
  async #list(f: Filters, actor: string) {
    await this.synchronize();
    this.#cleanup();
    return this.ctx.storage.transactionSync(() => {
      const state = this.#state();
      if (!state.completed) return { ready: false, syncing: true };
      const fingerprint = JSON.stringify([f.category, f.status, f.from, f.to, f.limit]);
      let position: { received: number; id: string } | undefined;
      if (f.cursor) {
        let cursor;
        try { cursor = JSON.parse(atob(f.cursor.replace(/-/g, '+').replace(/_/g, '/'))); }
        catch { requireThat(false, 400, 'invalid_cursor'); }
        requireThat(cursor && Number.isSafeInteger(cursor.received) && ID.test(cursor.id) &&
          cursor.filter === fingerprint && Number.isSafeInteger(cursor.revision), 400, 'invalid_cursor');
        requireThat(cursor.revision === state.revision, 409, 'inbox_changed');
        position = cursor;
      }
      const where = 'r.visible=1 AND r.expires>? AND r.received>=? AND r.received<? AND (?=\'\' OR r.category=?)';
      const bindings = [Date.now(), f.from, f.to, f.category, f.category];
      const counts = { new: 0, in_progress: 0, processed: 0 };
      for (const row of this.ctx.storage.sql.exec<{ status: Status; n: number }>(
        `SELECT r.status,COUNT(*) AS n FROM reports r WHERE ${where} GROUP BY r.status`, ...bindings)) counts[row.status] = row.n;
      const rows = this.ctx.storage.sql.exec<ReportRow>(`SELECT ${columns} FROM reports r WHERE ${where}
        AND (?='' OR r.status=?) ${position ? 'AND (r.received<? OR (r.received=? AND r.id<?))' : ''}
        ORDER BY r.received DESC,r.id DESC LIMIT ?`, ...bindings, f.status, f.status,
      ...(position ? [position.received, position.received, position.id] : []), f.limit + 1).toArray();
      const more = rows.length > f.limit;
      if (more) rows.pop();
      const last = rows.at(-1);
      const next = more && last ? btoa(JSON.stringify({ received: last.received, id: last.id,
        revision: state.revision, filter: fingerprint })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : null;
      this.#audit(actor, 'list');
      return { ready: true, reports: rows, counts, next_cursor: next, synchronized_at: state.completed,
        syncing: !!state.scanning, invalid_records: state.invalid, revision: state.revision, server_time: Date.now() };
    });
  }
  #row(id: string) {
    const row = this.ctx.storage.sql.exec<ReportRow>(`SELECT ${columns} FROM reports r
      WHERE r.id=? AND r.visible=1 AND r.expires>?`, id, Date.now()).toArray()[0];
    requireThat(row, 404, 'report_not_found');
    return row;
  }
  async #body(id: string) {
    const row = this.#row(id);
    const raw = await this.env.CONTENT_REPORTS.get(`report:${id}`);
    // Recheck time/state after external I/O; never serve expired content.
    this.#row(id);
    if (raw === null) {
      this.ctx.storage.sql.exec('UPDATE reports SET visible=0 WHERE id=?', id);
      this.ctx.storage.sql.exec('UPDATE sync SET revision=revision+1 WHERE singleton=1');
      requireThat(false, 404, 'report_not_found');
    }
    requireThat(raw.length <= 20000, 503, 'invalid_report');
    let b;
    try { b = JSON.parse(raw); } catch { requireThat(false, 503, 'invalid_report'); }
    requireThat(b && b.schema_version === 1 && b.report_id === id &&
      Date.parse(b.received_at) === row.received && b.category === row.category &&
      typeof b.text === 'string' && b.text.trim() && b.text.length <= 3000 &&
      typeof b.details === 'string' && b.details.length <= 500, 503, 'invalid_report');
    // Deliberate allowlist: even corrupt/legacy extra fields cannot reach UI.
    return { text: b.text as string, details: b.details as string, schema_version: 1 };
  }
  async detail(id: string, actor: string) { return this.#result(() => this.#detail(id, actor)); }
  async #detail(id: string, actor: string) {
    const body = await this.#body(id);
    const row = this.#row(id);
    this.#audit(actor, 'view', row);
    const history = this.ctx.storage.sql.exec<{ at: number; action: string; to_status: string | null }>(
      `SELECT at,action,to_status FROM audit WHERE report_id=? AND action='status' AND expires>?
       ORDER BY seq DESC LIMIT 20`, id, Date.now()).toArray();
    return { report: { ...row, ...body }, history, server_time: Date.now() };
  }
  async change(id: string, status: Status, version: number, actor: string) {
    return this.#result(() => this.#change(id, status, version, actor));
  }
  async #change(id: string, status: Status, version: number, actor: string) {
    await this.#body(id);
    return this.ctx.storage.transactionSync(() => {
      const row = this.#row(id);
      requireThat(row.version === version, 409, 'report_changed');
      requireThat((row.status === 'new' && status === 'in_progress') ||
        (row.status === 'in_progress' && status === 'processed') ||
        (row.status === 'processed' && status === 'in_progress'), 409, 'invalid_transition');
      const now = Date.now();
      this.ctx.storage.sql.exec(`UPDATE reports SET status=?,version=version+1,read_at=COALESCE(read_at,?),processed_at=?
        WHERE id=? AND version=?`, status, now, status === 'processed' ? now : null, id, version);
      this.#audit(actor, 'status', { ...row, version: row.version + 1 }, status);
      this.ctx.storage.sql.exec('UPDATE sync SET revision=revision+1 WHERE singleton=1');
      return { report: this.#row(id) };
    });
  }
  async maintenance() { await this.synchronize(); this.#cleanup(); }
}
