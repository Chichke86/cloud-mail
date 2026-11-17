# WiseReply Cloudflare deployment checklist

**Status: local verification only. Do not deploy this branch, turn on Workers Builds, change DNS or Email Routing, or write to a remote D1/KV/R2 resource without approval.** This checklist targets a fresh, isolated deployment. It does not authorize copying a production mailbox or importing a database over existing data.

## What the fork changes

- Password storage: native Workers `node:crypto` scrypt with a unique 16-byte salt, 32-byte digest and fixed versioned parameters (`N=32768, r=8, p=3`). Legacy password digests are deliberately not accepted. For an existing installation, arrange an offline admin reset and controlled user resets before any cutover. Do not re-enable legacy logins as a fallback.
- Authentication: short-lived opaque 8-hour sessions. D1 stores only the SHA-256 digest of each high-entropy session token (not a password hash). The browser holds the token only in a Secure, HttpOnly, SameSite=Strict cookie; the frontend's local storage contains a sign-in marker, not a credential. Logout/password reset invalidate sessions; websocket connections recheck access on heartbeat and delivery. Cross-origin API traffic is denied; no permissive CORS.
- Authorization: app administration is restricted to the configured administrator. Non-admin users need an explicit permission for all-mail access and other privileged actions. Attachments need a live session plus a matching mailbox record; the old raw storage aliases are disabled. Served files use no-store, nosniff and a sandbox policy; only selected raster formats can render inline. Browser email HTML blocks remote images and active content.
- SQL: bound inputs in the legacy bulk insertion code, an explicit allowlist for the dynamic attachment column, and bound ownership/session predicates. The bulk public API is not mounted.
- Abuse controls: login limiter on IP and normalized account, per-user limiter, and an additional budget for sending/password operations. Cloudflare's binding is per location and approximate; it is not a global lockout or a DDoS guarantee.
- Surface and egress: no registration, OAuth, invite API, public automation API, test handlers, hosted bootstrap, Resend hook/provider, Telegram, external webhook forwarding, automatic mail forwarding, Workers AI extraction, or external object storage. Unprovisioned and inactive recipients are rejected; no application catch-all. Cloudflare Email Sending is the only optional external-mail provider; the binding is absent until explicitly configured. Optional Turnstile may contact Cloudflare when used. The browser's CSP limits passive egress. User-clicked links and intentionally sent mail can leave the system.
- Supply chain: removed the auto-deploy workflow and the old `test` script that performed a deploy. The vendored TinyMCE 7.9.1 was replaced with a lockfile-managed patched dependency; inactive PWA tooling was removed. Use the lockfiles and re-run audits at release time.

The egress review was a source and bundle review, not a certification of all transitive code. The browser no longer persists opened messages or recipient history to local storage. Explicit drafts and their attachments still live in browser IndexedDB; use managed devices/browser profiles and treat local browser storage as sensitive. Upstream sample signing keys remain in public Git history; rotate any legacy keys or credentials actually reused in your infrastructure.

## 1. Verify locally (no Cloudflare credentials needed)

Use a current Node 22 or 24 and pnpm 11. From the repository root:

```sh
pnpm --dir mail-vue install --frozen-lockfile
pnpm --dir mail-worker install --frozen-lockfile
pnpm --dir mail-vue build
WRANGLER_SEND_METRICS=false pnpm --dir mail-worker test
WRANGLER_SEND_METRICS=false pnpm --dir mail-worker exec wrangler deploy --dry-run
pnpm --dir mail-vue audit
pnpm --dir mail-worker audit
```

The default Worker config uses synthetic local IDs and no public route. The tests use a temporary Workers runtime, D1, KV and R2. The Vue build must precede packaging or running a local browser against Worker Assets.

## 2. Build the initial database offline

1. Use a fresh local checkout/state directory. In the **default local** `mail-worker/wrangler.toml`, temporarily replace local `admin` and `domain` with the approved admin mailbox and mail domains so the generated rows match the intended deployment. Never add real resource IDs to that local config.
2. Create a mode-0600 ignored `mail-worker/.dev.vars` containing `BOOTSTRAP_SECRET` (32 random bytes as 64 lowercase hex characters) and `BOOTSTRAP_PASSWORD` (at least 15 characters; generated in a password manager). Do not put either in shell history, a URL, tracked config, terminal logs, or chat.
3. From `mail-worker` start the local-only entrypoint: `pnpm exec wrangler dev src/bootstrap-local.js --local --ip 127.0.0.1 --local-protocol https`. Never use `src/bootstrap-local.js` in a hosted Worker, Preview, or Tunnel. Make a single HTTPS `POST https://127.0.0.1:8787/bootstrap` with the exact bootstrap secret in the `Authorization` header using a local client that does not log it. Expect 204; a repeat on populated state returns 409.
4. Stop the bootstrap server. Use `pnpm exec wrangler d1 export wisereply-local --local --output wisereply-seed.sql.local`. Export **before signing in or loading sample mail**, to avoid carrying sessions or test data to another environment. Inspect the SQL in a protected editor: it should contain only schema, default roles/settings and the initial admin/account. Protect the generated SQL as sensitive (it contains a password verifier). Remove the bootstrap variables from the local environment; do not upload them.

## 3. Approval gate for any live action

Confirm the Cloudflare account, Worker, app hostname, mail domain(s), initial admin, inbound addresses, and whether outbound is needed. Use staging-only resources, dummy messages, a separate private R2 bucket, and a separate D1 and KV namespace. Copy `mail-worker/wrangler.wisereply.toml.example` to the ignored `wrangler.wisereply.toml` and populate only the approved IDs. Verify all bindings and the account ID before any remote operation; never use guessed IDs or enable automatic provisioning. Keep `workers_dev` and `preview_urls` disabled. Enforce HTTPS, add an identity gate with MFA for a private staff mailbox, and make sure there is no alternate public route.

- Leave both R2 public access mechanisms (public development URL and public custom domain) off. Do not add CDN caching to file or API paths. If migrating, inventory/revoke public storage URLs and purge any historical cached copies after approval; an app change cannot make an existing public bucket private.
- Import the reviewed seed only into an approved **empty** D1 database. For an existing deployment, use a separately reviewed additive migration/reset strategy, a backup and an isolated rehearsal; this seed is not a migration for live data.
- Point only approved test aliases to the staged worker. Verify MX/SPF/DKIM/DMARC and the current Cloudflare Email Service account/domain requirements before routing real traffic. Only enable `[[send_email]]` after domain verification and approval, and smoke-test sending and rejection with controlled recipients.
- Test HTTPS, auth and role boundaries with two staged users, file visibility/cache headers, realtime and revocation, mail routing/delivery and existing integrations, and confirm that unread/compose/download work in the supported browsers. Measure scrypt CPU and memory at expected load on the intended Workers plan. Validate the Cloudflare WAF/edge rate policy against distributed attempts. Confirm logs/traces do not retain message bodies, auth cookies, or secrets.
- Before production cutover, agree on rollback and recovery, including D1 and R2 snapshots. Worker rollback alone does not revert database or storage changes. An upstream build is not a safe rollback target after password/session migration. Require explicit production approval after staging verification.

References: [Workers test harness](https://developers.cloudflare.com/workers/testing/test-harness/get-started/), [Workers rate limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/), [D1 import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/), [public R2 access](https://developers.cloudflare.com/r2/buckets/public-buckets/), [Email Routing Worker handler](https://developers.cloudflare.com/email-service/api/route-emails/email-handler/), [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
