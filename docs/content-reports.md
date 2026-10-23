# Voluntary response reports

`osia-content-reports` is separate from the rendezvous and Chat relay Workers.
It receives only user-reviewed text (up to 3000 UTF-16 code units), a reason
and an optional note (up to 500). No pairing token, provider key, device ID,
conversation ID or automatic history is accepted. Unexpected fields are rejected.

`POST /v1/reports` returns HTTP 201 and a random receipt only after the private
KV write succeeds. Other outcomes must remain unconfirmed in the client.
There is no automatic retry and no public list/read/delete route. A distinct
user submission is a new report, never blocked by similarity to an earlier one.

The dedicated `OSIA_CONTENT_REPORTS` namespace expires each report after 30 days.
The Worker stores no IP address in the report and emits no application logs.
Cloudflare still handles network metadata. Per-IP and global rate limits, an
actual streamed body limit and strict field validation limit ingestion abuse.
These are technical bounds for this one support operation, not Chat limits.

## Operator handling

The separate owner dashboard is implemented in `wrangler.admin.jsonc` and
`src/admin/`, with deployment intentionally pending. See
[admin security, workflow and activation](reports-admin.md). Its read/status
layer leaves this ingestion Worker, request schema and KV TTL unchanged.

Open the private namespace in the authenticated Cloudflare account. Filter keys
by `report:`; metadata contains the category and receipt time. Review reports
for harmful/deceptive output, investigate the relevant provider/product behavior,
and record fixes without copying users' text to public tickets. Reports may
contain personal data even though the sender can redact them first.

Use the receipt reference for a user's access/deletion request to
`contact@osia.space`. Respect the 30-day inbox expiry; if a separate support or
legal record is necessary, apply the privacy policy rather than claiming that
all copies share the inbox TTL. Receipt IDs and content must not appear in
public build logs. Synthetic deployment probes are marked explicitly as tests.

Run `node --test test/content_reports.test.js`, and dry-run
`wrangler deploy --config wrangler.reports.jsonc --dry-run` before deployment.
The authoritative endpoint is the deployed `osia-content-reports` Worker on the
account's `aymengherbi06.workers.dev` subdomain; verify `/health` and a synthetic
stored report before releasing a client. Do not deploy the existing Chat relay
or rendezvous configuration as part of a reports-only change.
