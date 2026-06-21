/**
 * OSIA Rendezvous Worker (WOR-64)
 * =================================
 * Maps a *rendezvous key* -> a PC's current Cloudflare quick-tunnel URL, so a
 * phone holding the OSIA token can reach its OWN PC over the internet without
 * either side knowing the other's address ahead of time.
 *
 * ┌──────────────────────── KEY DERIVATION (shared by PC, phone & Worker) ───┐
 * │  proof          = HMAC_SHA256(key = token_utf8, msg = "osia-rdv-v1")     │
 * │                   -> 64-char LOWERCASE hex string                        │
 * │  rendezvous_key = SHA256( proof_hex_string )                             │
 * │                   -> 64-char LOWERCASE hex string                        │
 * │                                                                          │
 * │  CRITICAL: the SHA-256 for `rendezvous_key` is computed over the UTF-8   │
 * │  BYTES OF THE 64-CHAR HEX STRING of `proof` — NOT over the 32 raw bytes  │
 * │  that the hex encodes. Python (hmac/hashlib), mobile (Dart crypto) and   │
 * │  this Worker (Web Crypto) MUST all make this exact choice or they will   │
 * │  derive different keys and never meet. See README for the matching       │
 * │  Python and Dart snippets.                                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The Worker NEVER sees the raw token. It only ever receives `proof` (a
 * one-way HMAC of the token) and stores a key derived from it. An attacker who
 * compromises this service learns at most a set of opaque keys -> tunnel URLs;
 * they cannot recover any token.
 *
 * Endpoints
 *   POST /publish        body {proof, url}  -> {ok:true}    (PC publishes its URL)
 *   GET  /r/:key                            -> {url} | 404  (phone resolves it)
 *   GET  /oauth/cb/:key  ?code&state        -> relayed HTML (blind OAuth relay)
 *        Looks up the key's current quick-tunnel origin and forwards the
 *        provider's GET callback to <origin>/oauth/callback, relaying the PC
 *        server's close-tab HTML back. The Worker stays a blind relay: the
 *        relayed code is PKCE-locked + single-use and the verifier never leaves
 *        the PC, so the code is unredeemable here. (WOR-98)
 *   *    everything else                    -> 405
 */

// ─────────────────────────────────────────────────────────────────────────
// Configurable constants (top-of-file, per spec)
// ─────────────────────────────────────────────────────────────────────────

// Per-IP rate limits. The REAL enforcement values live in the [[ratelimits]]
// blocks of wrangler.toml (the binding reads limit/period from there). These
// constants document intent and feed the 429 responses below — keep them in
// sync with wrangler.toml. `period` may only be 10 or 60 on the binding.
const PUBLISH_RATE_LIMIT = 20;   // max POST /publish per IP per window  (strict — protects KV writes)
const GET_RATE_LIMIT     = 120;  // max GET  /r/:key per IP per window   (looser — reads are cheap)
const RATE_LIMIT_WINDOW  = 60;   // window length in seconds (must be 10 or 60)

// Default KV time-to-live (seconds) for a published URL. Overridable per
// deployment via the RENDEZVOUS_TTL_SECONDS var in wrangler.toml. KV enforces
// a 60s minimum; we clamp to that. A short TTL keeps stale tunnels from
// lingering and bounds how long any single key occupies storage.
const DEFAULT_TTL_SECONDS = 600;
const MIN_TTL_SECONDS     = 60;

// Reject oversized bodies before parsing. A valid publish body is ~150 bytes
// (a 64-char proof + a short URL); 1 KiB is a generous ceiling that cheaply
// shuts down memory-abuse attempts.
const MAX_BODY_BYTES = 1024;

// ─────────────────────────────────────────────────────────────────────────
// Validation patterns
// ─────────────────────────────────────────────────────────────────────────

// proof and rendezvous_key are both 64 lowercase hex characters.
const PROOF_RE = /^[0-9a-f]{64}$/;
const KEY_RE   = /^[0-9a-f]{64}$/;

// Only accept a bare Cloudflare quick-tunnel origin: https://<label>.trycloudflare.com
// with no port, path, query or fragment. This is exactly what `cloudflared`
// hands out, and refusing anything else stops the KV store being used as an
// open redirect / URL parking lot.
const URL_RE = /^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/;

// ─────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────

/** JSON response with no-store caching and a stable shape. */
function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  });
}

/** Per-IP rate-limit identity. CF-Connecting-IP is set by Cloudflare on every
 *  edge request; the 'unknown' fallback only matters in local `wrangler dev`. */
function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

/**
 * SHA-256 of a STRING, returned as lowercase hex.
 * Hashes the UTF-8 bytes of `input`. For rendezvous-key derivation we pass the
 * 64-char proof *hex string*, so this hashes those 64 ASCII bytes — matching
 * Python's `hashlib.sha256(proof_hex.encode()).hexdigest()` and Dart's
 * `sha256.convert(utf8.encode(proofHex)).toString()`.
 */
async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Resolve the configured TTL, clamped to KV's 60s minimum. */
function ttlSeconds(env) {
  const raw = Number(env.RENDEZVOUS_TTL_SECONDS);
  if (Number.isFinite(raw) && raw >= MIN_TTL_SECONDS) return Math.floor(raw);
  return DEFAULT_TTL_SECONDS;
}

/** 429 helper carrying a Retry-After hint. */
function rateLimited() {
  return json({ ok: false, error: 'rate_limited' }, 429, {
    'retry-after': String(RATE_LIMIT_WINDOW),
  });
}

// ─────────────────────────────────────────────────────────────────────────
// Route handlers
// ─────────────────────────────────────────────────────────────────────────

/** POST /publish — PC publishes its current quick-tunnel URL. */
async function handlePublish(request, env) {
  // 1) Per-IP rate limit FIRST — gate the expensive KV write and protect the
  //    free-tier 1000-writes/day quota before doing any other work.
  const { success } = await env.PUBLISH_LIMITER.limit({ key: clientIp(request) });
  if (!success) return rateLimited();

  // 2) Cheap size guard before reading the body.
  const declaredLen = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(declaredLen) && declaredLen > MAX_BODY_BYTES) {
    return json({ ok: false, error: 'payload_too_large' }, 413);
  }

  // 3) Parse JSON defensively.
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'invalid_json' }, 400);
  }

  const proof = body?.proof;
  const targetUrl = body?.url;

  // 4) Strict validation. Note we validate `proof` (an HMAC of the token), never
  //    the token itself — the raw token is never transmitted to the Worker.
  if (typeof proof !== 'string' || !PROOF_RE.test(proof)) {
    return json({ ok: false, error: 'invalid_proof' }, 400);
  }
  if (typeof targetUrl !== 'string' || !URL_RE.test(targetUrl)) {
    return json({ ok: false, error: 'invalid_url' }, 400);
  }

  // 5) Derive the rendezvous key: SHA-256 over the proof HEX STRING (see header).
  const rendezvousKey = await sha256Hex(proof);

  // 6) Store key -> url with a bounded TTL so stale tunnels self-expire.
  await env.KV_RENDEZVOUS.put(rendezvousKey, targetUrl, { expirationTtl: ttlSeconds(env) });

  return json({ ok: true });
}

/** GET /r/:rendezvous_key — phone resolves the current URL for its key. */
async function handleResolve(request, env, key) {
  // 1) Per-IP rate limit (looser than publish).
  const { success } = await env.GET_LIMITER.limit({ key: clientIp(request) });
  if (!success) return rateLimited();

  // 2) Validate key shape before touching KV (avoids junk lookups).
  if (!KEY_RE.test(key)) {
    return json({ ok: false, error: 'invalid_key' }, 400);
  }

  // 3) Resolve.
  const url = await env.KV_RENDEZVOUS.get(key);
  if (url === null) {
    return json({ ok: false, error: 'not_found' }, 404);
  }
  return json({ url });
}

/**
 * GET /oauth/cb/:rendezvous_key — blind relay of a provider OAuth callback (WOR-98).
 *
 * The mobile OAuth flow registers `https://<this-worker>/oauth/cb/<key>` as its
 * redirect_uri. When the provider redirects the browser here, we look up the
 * key's CURRENT quick-tunnel origin in KV and forward the callback to the PC's
 * local server at `<origin>/oauth/callback?<same query>` (the WOR-96 route),
 * then relay that server's close-tab HTML straight back to the browser.
 *
 * The Worker never redeems anything: the relayed `code` is PKCE-locked and
 * single-use, and the PKCE verifier never leaves the PC — so a code seen here is
 * unredeemable. We therefore (a) never log the query string (code/state),
 * (b) mark the response no-store, and (c) re-validate the KV value against
 * URL_RE on read so the forward destination can only ever be a bare
 * *.trycloudflare.com origin — it is KV-sourced, never request-controlled, which
 * closes off open-redirect / SSRF. No forward loop is possible: our inbound path
 * is /oauth/cb/ while the forwarded path is /oauth/callback, and KV only ever
 * holds trycloudflare origins (the publish regex), never this Worker's host.
 */
async function handleOauthCallback(request, env, key, search) {
  // 1) Per-IP rate limit — reuse the looser GET limiter (same as /r/:key).
  const { success } = await env.GET_LIMITER.limit({ key: clientIp(request) });
  if (!success) return rateLimited();

  // 2) Validate key shape before touching KV (avoids junk lookups).
  if (!KEY_RE.test(key)) {
    return json({ ok: false, error: 'bad_key' }, 400);
  }

  // 3) Resolve the current quick-tunnel origin for this key. Re-check URL_RE on
  //    read (belt-and-suspenders): the destination is KV-sourced and must remain
  //    a bare trycloudflare origin, so a malformed/stale value is treated as a miss.
  const target = await env.KV_RENDEZVOUS.get(key);
  if (target === null || !URL_RE.test(target)) {
    return json({ ok: false, error: 'not_found' }, 404);
  }

  // 4) Forward the callback to the PC's local /oauth/callback route, preserving
  //    the query verbatim. redirect:'manual' so we never auto-follow an upstream
  //    redirect (SSRF-chaining guard). NB: never log `search` (carries code/state).
  const fwd = target + '/oauth/callback' + search;
  let upstream;
  try {
    upstream = await fetch(fwd, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'user-agent': 'osia-rendezvous/1.0' },
    });
  } catch {
    return json({ ok: false, error: 'upstream_unreachable' }, 502);
  }

  // 5) Relay the server's response (close-tab HTML) back to the browser verbatim,
  //    uncacheable. Default content-type to HTML if the server omitted one.
  const relayBody = await upstream.text();
  return new Response(relayBody, {
    status: upstream.status,
    headers: {
      'content-type': upstream.headers.get('content-type') || 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────
// Worker entrypoint
// ─────────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const { method } = request;

    if (method === 'POST' && pathname === '/publish') {
      return handlePublish(request, env);
    }

    if (method === 'GET' && pathname.startsWith('/r/')) {
      // Path tail after '/r/' is the candidate rendezvous key (validated in handler).
      return handleResolve(request, env, pathname.slice('/r/'.length));
    }

    if (method === 'GET' && pathname.startsWith('/oauth/cb/')) {
      // Path tail after '/oauth/cb/' is the candidate rendezvous key (validated in
      // handler); url.search carries the provider's ?code&state, relayed verbatim.
      return handleOauthCallback(request, env, pathname.slice('/oauth/cb/'.length), url.search);
    }

    // Spec: all other routes/methods -> 405.
    return json({ ok: false, error: 'method_not_allowed' }, 405, {
      allow: 'POST /publish, GET /r/:rendezvous_key, GET /oauth/cb/:rendezvous_key',
    });
  },
};
