# Security model

NetGuard treats the dashboard as a security boundary. Identity, session,
transport, and abuse protections are built in from first run.

## Authentication

- **Setup-gated provisioning** — on a fresh install there are no users. The
  daemon writes a one-time setup token to `/var/lib/netmon/setup-token`
  (`0600`), valid **24 h**. The `/setup` page consumes it to create the admin
  user. After that, setup is closed.
- **Password policy** — minimum **12 characters**, must contain lower, upper,
  digit, and symbol characters.
- **Forced reset** — users created before hardening (or with weak passwords)
  are marked and redirected to `/password-reset.html`. OOB tokens are written
  to `/var/lib/netmon/password-reset-token.<username>`, valid **1 h**.
- **Sessions** — random, high-entropy tokens stored hashed server-side, issued
  with a configurable TTL (default 7 days). Revocable per-session or globally
  (revoke-all).
- **Machine API token** *(optional)* — `auth_api_token` configures a static
  machine credential for local helper processes (the system tray). It is
  presented as `Authorization: Bearer <token>` or `?token=<token>`.
  Scope-limited by design: the credential carries **no user identity**, so it
  can reach the firewall endpoints but is refused by the user-scoped
  `/api/auth/*` actions (password change, password-reset issuance, session
  revocation, audit log) — those still require a real cookie session.

## Session transport

- Session cookie is `HttpOnly` (not readable from JS) and `SameSite=Lax`.
- **CSRF protection** — a rotating `netmon_xsrf` cookie is mirrored as the
  `X-XSRF-TOKEN` header; the server requires that header on every mutating
  request. The frontend patches `fetch` to attach it automatically. Requests
  authenticated with the machine API token skip this check because a
  Bearer/query token cannot be attached by a cross-site request — the token
  itself is the CSRF defense.
- Cookie is only honored over the served origin; when deployed behind TLS,
  set secure-cookie behavior within the auth layer.

## Rate limiting & abuse

- The rate limiter is scoped **only** to the privileged endpoints
  (`/api/auth/login`, `/api/auth/setup`, `/api/auth/password-reset`), so
  legit dashboard traffic is never throttled.
- Per-username **lockout** on failure accumulates inside `Authenticate()`
  regardless of middleware path.
- All throttle + auth failures are recorded in the **audit log**
  (`/api/auth/events`, dashboard **events** page).

## Audit logging

Every authentication-relevant action is appended to the `auth_events` table:
successful logins, failed logins, lockouts, password changes, resets,
revocations, and setup. The most recent 100 are surfaced in the UI and via
`GET /api/auth/events`.

## Privilege dropping

The daemon starts as root (to read `/proc` and manage nftables). If
`run_as` is set in the config, it drops privileges to that user after
initialization while keeping the capabilities it needs. See
`internal/privdrop`.

## Firewall safety

- Firewall enforcement is **non-destructive**: populating nftables sets
  rather than replacing chains, with methodology designed to be reverted.
- **Panic mode** reverts policy to accept and auto-reverts; the whole
  dashboard flashes red so there's no ambiguity about state.
- Errors from nftables are **non-fatal** — the daemon keeps serving the
  dashboard even if the firewall layer can't apply rules (e.g. unprivileged
  dev runs).

## Network exposure

By default the dashboard listens on `127.0.0.1:8484`. Exposing it beyond
localhost is supported but should be done behind a reverse proxy with TLS.
Auth protects the API, but transport security is your responsibility in
remote deployments.