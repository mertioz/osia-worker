# Owner-only report moderation

Implementation date: 23 October 2026. **NOT DEPLOYED — OPERATOR_PENDING** for
Access configuration, owner identity/MFA and final deployment approval.
Intended address: `https://admin.osia.space/reports`.

This is a separate Worker, `osia-reports-admin`, in the primary `osia-worker`
repository. It is independent of the static public site, Mobile versioning,
native builds and store submissions. There is no new public route, workers.dev
URL, preview URL, infrastructure purchase or production migration in this change.

## Observed existing contract

Primary `main`, freshly fetched, initially matched GitHub at
`a225aad3c525a922fc3cc1558c43ca07fd8aba94`. The deployed ingestion Worker
`osia-content-reports` uses version `0f30cdf4-786b-4630-a376-07bb9718c5b7`.
Its settings and private namespace **metadata only** were inspected. No real
submitted body was fetched, exported, logged, or used as a test fixture.

`src/content_reports.js` and `wrangler.reports.jsonc` remain unchanged:

| Item | Existing value |
| --- | --- |
| Private KV | `OSIA_CONTENT_REPORTS`, binding `CONTENT_REPORTS` |
| Key | `report:<random UUID v4>` |
| Body fields | `schema_version: 1`, `category`, `text`, `details`, `report_id`, `received_at` |
| Categories | `harmful`, `sexual`, `violence`, `deceptive`, `other` |
| User text/note | Up to 3,000 / 500 UTF-16 code units |
| Key metadata | `received_at`, `category` |
| Expiry | KV `expirationTtl: 2592000` (30 days) |
| Existing read API | No public list, detail or status API; authenticated Cloudflare namespace access only |

No conversation, provider, device, user, account, IP, file or credential field
is added to submission. The administrator sees only the selected submitted
text/note, category, receipt reference/time, schema and moderation timestamps.
Content can itself contain personal data voluntarily submitted by the sender.

## Why one small Durable Object

UUID keys have no chronological order. KV cannot atomically compare/update a
moderation version and loses concurrent writes through last-write-wins. Its
global reads/listing are eventually consistent. These are concrete limitations
of the actual schema, rather than a speculative need for another data store.
See [KV concurrent writes](https://developers.cloudflare.com/kv/api/write-key-value-pairs/#concurrent-writes-to-the-same-key)
and [KV listing](https://developers.cloudflare.com/kv/api/list-keys/).

`ModerationInbox`, SQLite storage, is one coordination atom for the one owner's
inbox. It stores receipt metadata, status/version, explicit read/processed
timestamps, a temporary metadata scan and minimal audit facts. **No submitted
text or notes are copied into SQLite.** D1, R2 copies, queues and ingestion
changes are unnecessary for this scope. SQL transactions serialize status
updates and publish a complete index atomically.
[Cloudflare storage guarantees](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).

The same private KV is bound to the new Worker; all access uses bindings.
The admin code contains no KV put/delete call and has no browser credentials
or privileged Cloudflare REST token. KV bindings do not offer a read-only
method-level capability: account/Worker code write access remains privileged.
Do not grant this namespace to other Workers or add a public DO service binding.

## Synchronization, counts and pagination

A minute cron and an authenticated list request advance the metadata scan.
Each invocation reads at most five pages of 1,000 keys, persisting its cursor
and staging between invocations. Concurrent scans coalesce. A scan completes
before publishing any of its rows. The first incomplete scan returns HTTP202
and an indexing state; a later scan leaves the previous complete index visible
with its synchronization time. Failed KV operations discard staging and return
a sanitized503; a fresh call can start again, preserving moderation status.

Counts are computed transactionally over the completed observed index with
current status and expiry. Date/category filters scope all three counters;
the status filter scopes the list. The interface states both the counter scope
and index synchronization time. **These are not instantaneous global ingestion
counts**: KV propagation and a large multi-invocation scan can delay visibility.
No estimate is displayed as a current live-ingestion fact.

Server pagination uses `(received DESC, id DESC)` and a maximum of50 rows
(UI25), without fetching bodies. Opaque base64url cursors bind the complete
filter tuple and index/status revision. They are navigation state, not an
authorization credential. Changing data/status invalidates old cursors with409;
the UI reloads the first page. No offsets, client-side full inbox download or
unsorted KV page concatenation are used. An unchanged sync preserves cursors.
Expired items disappear while paging, without extending their availability.

Browser `Intl` uses the administrator's actual IANA timezone. Date inputs
represent inclusive local calendar days; the UI sends an inclusive UTC `from`
and exclusive UTC `to` at the next local midnight, respecting DST.

## Workflow and retention

Opening detail records `view`, while status remains `new`. Explicitly marking
read moves `new → in_progress`, sets first-read time, and increments version.
Only `in_progress → processed` completes review. `processed → in_progress`
reopens review while retaining the first-read time. No decision automatically
deletes, hides, changes, retrains on, or sends submitted content anywhere.

Every mutation includes its expected version. The DO rechecks the body and
expiry after KV I/O, then performs compare/update/audit/revision in one SQL
transaction. Concurrent tabs yield one winner and409 for stale requests.
No automatic retry of a conflicting status change occurs.

Availability ends at the earlier of the existing KV expiration and receipt time
plus30 days. List, counts, detail and writes enforce this on every operation.
The existing KV TTL deletes bodies independently. The minute maintenance task
removes expired metadata/status/staging/audits from the live SQLite store even
without administrator visits; the API never relies on cron punctuality to deny
expired data. Processing never rewrites KV or extends retention. Early missing
bodies yield404 and remove that row from the visible index; temporary KV
omissions keep hidden status until expiry so reappearance cannot reset review.

Audit fields: time, SHA256 of verified Access subject, fixed action (`list`,
`view`, `status`), optional report ID/from/to/resulting version and expiration.
Report-linked audits expire with their report; aggregate list audits expire
after30 days. No JWT, email, IP, content, note, exception text, API key or user
history is logged. Cloudflare invocation logging is disabled. The application
creates no exports/backups; provider-managed recovery/backup retention is a
platform control, not a claim of instantaneous erasure of every recovery copy.

## Authorization and browser protections

Cloudflare Access must protect the **entire dedicated hostname**, including
`/api/*` and static assets. The Worker independently verifies the signed Access
JWT through `jose`: RS256 signature, pinned issuer/JWKS endpoint, exact audience,
expiry/nbf/issued-at, app-token type, and **both** exact operator email and Access
subject. Missing/malformed configuration fails closed with503. No email-header,
cookie-only, service-token, developer or local-auth bypass exists in production.
[Access origin validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/).

The Worker checks the configured origin, rejects cross-origin and same-site
cross-subdomain browser requests, and authorizes every supported route before
handling it. All static assets use `run_worker_first: true`. `index.html` is not
a directly routable public page. Unknown paths/methods do not bypass auth.

PATCH requires exact Origin, same-origin Fetch Metadata when supplied, JSON,
an actual streamed1KiB body bound, exact schema and a custom CSRF header. The
CSRF value is SHA256 of a domain-separated verified JWT, obtainable only from
the protected same-origin session API and bound to that session. It never
reveals the JWT; comparison uses constant-time crypto. No CORS allowlist or
access token is exposed to frontend JavaScript.

An edge per-IP60/min limiter applies before verification. A DO120/min limiter
applies after verification across locations for this one owner. The edge limit
is a local abuse control, not a global-consistency claim. Responses including
errors use private/no-store browser/CDN controls, no ETags, no-referrer,
nosniff, no framing, same-origin resource policy and a restrictive CSP.

Report/note rendering uses `textContent` and plain `pre` nodes. No HTML,
Markdown, auto-links, images, embeds, eval, external scripts/fonts, analytics,
service worker, localStorage or sessionStorage handles report data. Page hiding,
BFCache restoration and session/report expiry clear in-memory/DOM private data.
Long expiry timers are bounded to avoid the browser's 32-bit timer overflow.
The interface has EN/FR labels, keyboard-native controls, modal focus handling,
loading/indexing/empty/error/retry states and contained narrow-screen tables.

## Operator activation — explicit approval required

The checked-in manifest has blank `ACCESS_AUD`, `ADMIN_EMAIL`, `ADMIN_SUB`,
no routes and disabled workers.dev/preview URLs. This intentionally cannot serve
the inbox until the operator supplies identity and authorizes activation.
Do not infer that the authenticated Cloudflare account email is the chosen admin.

1. Confirm the **single operator email** and authorize configuring the dedicated
   Access app, one SQLite DO namespace/migration and custom hostname. Verify
   account plan/limits with the operator; do not buy or upgrade anything.
2. Create a self-hosted Access application for **all of `admin.osia.space`**,
   separate from current public-site Access applications. Default deny; exactly
   one email Include rule, no Everyone/domain-wide Include, Bypass, service
   authorization, reusable broad policies or alternate unprotected path.
3. Require strong MFA. Prefer independent WebAuthn/security key MFA, required
   each login, and a short application session (proposed1 hour). Inspect policy
   overrides: a policy that disables MFA can override the app setting. The
   inspected account currently exposes a Cloudflare IdP only; do not assume its
   MFA claims or another configured IdP. Operator enrollment/login is required.
   [Current independent MFA settings](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/mfa-requirements/).
4. Retrieve the dedicated app AUD and operator subject from a verified Access
   identity/login. Never paste JWTs into tickets, terminal output or browser
   application storage. Set issuer/AUD/email/subject in Worker configuration,
   using encrypted secret bindings for owner identity if preferred. Recheck
   all configuration and regenerate binding types. Account management tokens
   belong only in operator tooling, never in this Worker or its assets.
5. After final deployment approval, add **only** the custom domain route for
   `admin.osia.space` in `wrangler.admin.jsonc` (`custom_domain: true`) and deploy
   that manifest only. Keep workers.dev and preview URLs disabled. Do not deploy
   `wrangler.reports.jsonc`, relay, rendezvous, public site or any Mobile app.
   Record the source SHA, bundle hash, Worker version, Access app/policy IDs and
   actual binding metadata without secrets. Confirm unique rate namespace12105.
6. Before accepting live use, test signed-out, wrong-person, exact-owner/MFA,
   expired session, service-token, direct list/detail/PATCH, cross-origin/CSRF,
   workers.dev/preview denial and non-cacheability through the real hostname.
   Use only synthetic reports for probes, delete no real content, and verify
   ingestion version/bindings remain unchanged. Record results in Linear.

Until those steps run, live authentication/MFA, custom-domain behavior, cron
execution and production acceptance are **OPERATOR_PENDING**, not passed.
Rollback removes/disables the admin custom domain and Access app, with owner
approval as appropriate; retain the private moderation namespace for orderly
rollback and retention maintenance. Never delete or migrate ingestion KV, and
never restore an unprotected public fallback. Keep expiry maintenance active
until retained metadata expires, or explicitly purge admin-only state safely.

## Local checks and independent evidence

```text
npm ci
npm run types:admin
npm run typecheck:admin
npm run test:admin
npm run test:reports
node --test test/relay_priority.test.js
npx vitest run --no-file-parallelism test/relay_websocket.test.js test/oauth_callback.test.js
npm run test:admin:browser
npm audit --audit-level=low
python scripts/test_security_policy.py
python scripts/scan_secrets.py
```

The browser command uses installed Edge by default, or `OSIA_QA_BROWSER=chrome`
for an installed Chrome. It builds the actual production Worker, then runs an
isolated in-memory Miniflare with synthetic reports and an ephemeral test key.
The loopback-only test gateway injects test identity **outside** that unchanged
bundle, supplies a synthetic JWKS via the runtime outbound service, and denies
other outbound traffic. It never connects to Cloudflare KV. No private key or
JWT is persisted, printed, committed or sent to the browser. Preview/test code
is outside the deployed entrypoint/assets and is not a production auth mode.

Results on23 October2026:

| Check | Result |
| --- | --- |
| Admin Workers-runtime security/state suite | 19 pass |
| Independent compiled-Worker Edge browser suite | 6 pass |
| Existing ingestion | 5 pass |
| Existing relay priority | 37 pass |
| Existing relay Worker | 59 pass |
| Existing OAuth callback Worker | 27 pass |
| Repository security policy | 8 pass |
| TypeScript, generated bindings, JS syntax, Wrangler dry-run | Pass |
| Dependency audit | 0 vulnerabilities |
| Deterministic OSIA + pinned Gitleaks8.30.1 | Clean |

The final dry-run Worker bundle SHA256 is
`c41b4569443b712cba32865316eabb88a6fab56601e070f2f05dc14b8fa4110a`.
This is a local build hash, not a deployed Worker version. The existing two
relay/OAuth files pass with file parallelism disabled; a combined parallel run
also passed its86 assertions but emitted a tooling teardown RPC warning. The
documented sequential invocation completed without that teardown exception.

Coverage includes missing/forged/wrong/expired JWTs and headers, unauthorized
direct reads/writes/assets, owner isolation, origin/CSRF/body limits, rate limits,
stored XSS, no browser persistence, ordered cursor pagination, date/category/
status/count parity, atomic multi-invocation scan publication/recovery,
concurrent version conflicts, persistence after DO eviction, early KV deletion,
expiry during I/O, no TTL extension, audit privacy and deletion. Browser tests
exercise America/New_York calendar boundaries; manual synthetic inspection also
checked Europe/Paris and French. Tests caught and fixed the30-day browser timer
overflow and a table accessibility label escaping its narrow scroll container.

Call sites: admin `fetch` owns authorization and routing; the same Worker's cron
calls `maintenance`; dashboard calls session/list/detail/status only. Existing
Mobile→ingestion, Chat, provider/parser, WebSocket, browser automation and TTS
contracts are untouched. No PC/Mobile runtime regressions are implied by this
separate backend's tests. Tooling was refreshed to current pinned compatible
Wrangler/Vitest plugin versions; existing relay and OAuth suites were rerun.

Linear could not create a new issue because the workspace is over its free issue
limit. Dated progress and delivery evidence are recorded in permanent WOR-202;
it remains In Progress. No billing change was made. Generated bundles, screenshots,
profiles, local KV/DO state and test output remain ignored and uncommitted.
