# OSIA Rendezvous Worker (WOR-64)

A tiny, security-first Cloudflare Worker that maps a **rendezvous key** → a PC's
**current Cloudflare quick-tunnel URL**. It lets a phone that holds the OSIA
token reach its **own** PC over the internet, even though the PC's tunnel URL
changes every time `cloudflared` restarts.

The Worker is a blind dead-drop:

- It **never sees the raw token.** It only ever receives `proof` (a one-way HMAC
  of the token) and stores a key derived from `proof`.
- Compromising the service leaks at most a set of opaque `key → tunnel URL`
  pairs. No token can be recovered, and tunnel URLs already expire on their own.

This is a **new standalone JavaScript project** (Worker + Wrangler), separate
from the Python `osia` repo.

---

## How the key is derived (PC ⇄ phone ⇄ Worker must agree byte-for-byte)

Both the PC and the phone independently compute the same two values from the
shared token:

```
proof          = HMAC_SHA256(key = token_utf8, msg = "osia-rdv-v1")   → 64-char lowercase hex
rendezvous_key = SHA256( proof_hex_string )                            → 64-char lowercase hex
```

### ⚠️ The one detail everyone must get right

`rendezvous_key` is `SHA256` of the **64-character hex *string*** of `proof` —
i.e. the SHA-256 is taken over the **UTF-8 bytes of the hex text**
(`"d1712a43…"`, 64 ASCII bytes), **NOT** over the 32 raw bytes that the hex
encodes. Hashing the raw bytes produces a *different* key and the two sides will
never meet.

- PC (Python): `hashlib.sha256(proof_hex.encode()).hexdigest()`
- Mobile (Dart): `sha256.convert(utf8.encode(proofHex)).toString()`
- Worker (Web Crypto): `crypto.subtle.digest('SHA-256', new TextEncoder().encode(proofHex))`

All three hash the **hex string**. This is verified against real values below.

### Python (PC side)

```python
import hmac, hashlib

def derive(token: str):
    proof = hmac.new(token.encode("utf-8"), b"osia-rdv-v1", hashlib.sha256).hexdigest()
    # sha256 over the HEX STRING of proof (its utf-8 bytes), NOT bytes.fromhex(proof)
    rendezvous_key = hashlib.sha256(proof.encode("utf-8")).hexdigest()
    return proof, rendezvous_key
```

### Dart (mobile side)

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';

(String proof, String rendezvousKey) derive(String token) {
  final proof = Hmac(sha256, utf8.encode(token))
      .convert(utf8.encode('osia-rdv-v1'))
      .toString(); // lowercase hex
  // sha256 over the HEX STRING of proof, NOT its raw bytes
  final rendezvousKey = sha256.convert(utf8.encode(proof)).toString();
  return (proof, rendezvousKey);
}
```

### JavaScript / Worker side (what `src/index.js` does)

```js
const proof = /* received from the PC; never derived here, Worker has no token */;
const rendezvousKey = await sha256Hex(proof); // sha256 over the proof hex string
```

### Reference vectors (use these to test your implementation)

```
token          = osia-demo-token
proof          = d1712a430e5899bbf339c30bf48806bc6898b9564204ddd03c71c515e7846ead
rendezvous_key = 866b67a00a0fe6d5f35206afc35c28c68bf30e311c18c759cc999843a177c5d2
```

If your Python and Dart both print that `rendezvous_key`, you're wired up
correctly. (Hashing the raw proof bytes instead would give
`da7c1a3f…` — that's the wrong variant.)

---

## API

| Method & path           | Body                  | Success            | Errors |
|-------------------------|-----------------------|--------------------|--------|
| `POST /publish`         | `{"proof","url"}`     | `200 {"ok":true}`  | `400` invalid proof/url/json, `413` body too large, `429` rate-limited |
| `GET  /r/:rendezvous_key` | —                   | `200 {"url":...}`  | `400` invalid key, `404` not found, `429` rate-limited |
| `GET  /oauth/cb/:rendezvous_key` | `?code&state` (relayed verbatim) | relayed close-tab HTML from the PC server | `400` bad key, `404` not found, `429` rate-limited, `502` upstream unreachable |
| anything else           | —                     | —                  | `405` |

**`GET /oauth/cb/:rendezvous_key` (WOR-98)** — the mobile OAuth flow registers
`https://<this-worker>/oauth/cb/<rendezvous_key>` as its `redirect_uri`. When the
provider redirects the browser here, the Worker resolves the key's current
quick-tunnel origin (same KV lookup as `/r/:key`) and forwards the callback to
the PC's local server at `<origin>/oauth/callback?<same query>`, then relays the
server's close-tab HTML back. The Worker is a **blind relay**: the `code` is
PKCE-locked and single-use and the verifier never leaves the PC, so a code seen
here is unredeemable. The query string (`code`/`state`) is **never logged**, the
response is `no-store`, and the forward destination is re-validated against
`URL_RE` on read so it can only ever be a `*.trycloudflare.com` origin (no
open-redirect / SSRF). Uses the looser `GET_LIMITER`.

**Validation**

- `proof` must match `^[0-9a-f]{64}$`.
- `url` must match `^https://[a-z0-9-]+\.trycloudflare\.com$` (bare quick-tunnel
  origin only — no port/path/query), so the store can't be abused as an open
  redirect.
- `rendezvous_key` (path param) must match `^[0-9a-f]{64}$`.

On publish, the Worker computes `rendezvous_key = sha256(proof_hex_string)` and
stores `key → url` in KV with `expirationTtl` (default **600 s**, configurable).

---

## Abuse & cost protection

This service runs on Cloudflare's **free tier**, whose hard limit is
**1000 KV writes/day**. Two layers protect that quota and prevent counter
blowups:

1. **Per-IP rate limiting** via Cloudflare's native `ratelimit` binding
   (constants at the top of `src/index.js`, enforced values in `wrangler.toml`):
   - `POST /publish` — **20 / minute / IP** (strict; every publish is a KV write)
   - `GET  /r/:key`  — **120 / minute / IP** (looser; reads are cheap)
   - The publish limiter is checked **before** the KV write, so throttled
     requests cost zero writes.
2. **Client-side discipline (REQUIRED of the PC).** The PC must **only publish
   when its tunnel URL actually changes**, plus a **slow keepalive** to refresh
   the TTL. With the default 600 s TTL, republishing every ~5 minutes is
   ≈ 288 writes/day — comfortably inside the free 1000/day. **Do not** publish
   on a tight loop.

> **Going public?** Move to the Workers **Paid plan ($5/mo)** before launch — it
> lifts KV writes to millions/day and removes the 1000/day ceiling that the
> free tier imposes.

Additional hardening already in the Worker: 1 KiB request-body cap, strict
regex validation before any KV access, `Cache-Control: no-store` on all
responses, and the token is never transmitted to or stored by the Worker.

---

## Deploy

Prerequisites: Node 18+ and a Cloudflare account. `wrangler` is pinned as a
dev-dependency, so the commands below use `npx wrangler` (no global install
needed — or run `npm i -g wrangler` if you prefer a global binary).

```bash
# 1. Install dev tooling (wrangler)
npm install

# 2. Authenticate (opens a browser; one-time)
npx wrangler login
npx wrangler whoami        # confirm the account

# 3. Create the KV namespace and copy the printed id
npx wrangler kv namespace create KV_RENDEZVOUS
#   → paste the id into wrangler.toml, replacing <KV_NAMESPACE_ID>

# 4. Deploy
npx wrangler deploy
#   → prints the live URL, e.g. https://osia-rendezvous.<subdomain>.workers.dev
```

Tail live logs with `npx wrangler tail`.

---

## Test it (curl)

Replace `$BASE` with your deployed URL (e.g.
`https://osia-rendezvous.<subdomain>.workers.dev`). These use the reference
vectors above, so they work end-to-end out of the box.

**1) Publish** (PC → Worker):

```bash
BASE="https://osia-rendezvous.<subdomain>.workers.dev"

curl -sS -X POST "$BASE/publish" \
  -H 'content-type: application/json' \
  -d '{
        "proof": "d1712a430e5899bbf339c30bf48806bc6898b9564204ddd03c71c515e7846ead",
        "url":   "https://calm-frost-1234.trycloudflare.com"
      }'
# → {"ok":true}
```

**2) Resolve** (phone → Worker). The path param is the **`rendezvous_key`**
(= `sha256` of the proof hex string), *not* the proof:

```bash
curl -sS "$BASE/r/866b67a00a0fe6d5f35206afc35c28c68bf30e311c18c759cc999843a177c5d2"
# → {"url":"https://calm-frost-1234.trycloudflare.com"}
```

Resolving an unknown (or expired) key returns `404 {"ok":false,"error":"not_found"}`.

---

## Files

| File             | Purpose |
|------------------|---------|
| `src/index.js`   | The Worker: routing, validation, key derivation, KV, rate limiting. |
| `wrangler.toml`  | KV binding (`KV_RENDEZVOUS`), TTL var, `ratelimit` bindings. **Set the KV id.** |
| `package.json`   | Scripts + pinned `wrangler` dev-dependency. |
| `README.md`      | This file. |
| `.gitignore`     | Ignores `node_modules/`, `.wrangler/`, local secrets. |
