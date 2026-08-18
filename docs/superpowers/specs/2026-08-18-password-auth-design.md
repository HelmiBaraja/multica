# Password-only auth and landing removal

Date: 2026-08-18
Branch: `claude/local-username-password-auth-093a8d`

## Goal

Replace email-OTP and Google sign-in with email + password credentials, and
delete the marketing landing site so `/` goes straight to login.

Users can create an account with email + password alone. No verification code,
no OAuth.

## Reference and its limits

GitHub PR #744 ("Add email/password login for self-hosted auth") is the starting
reference, but it is stale and does not deliver this goal:

- Its migration is `040_*`; this repo is at `347_*`.
- Its base `VerifyCode`/`GoogleLogin` are far simpler than the current
  handlers, so its `writeLoginResponse` helper is missing auth cookies, CSRF,
  analytics, and disabled-user checks that exist today.
- Its "password setup" still requires an emailed OTP code, so it is not
  signup with credentials alone.
- It leaks account existence through distinct error strings.

Take from it: bcrypt, the `password_hash` column, the `/auth/password/*` route
namespace, and the client/store wiring shape. Design the rest fresh.

## Decisions

| Decision | Choice |
| --- | --- |
| Login identifier | Email. No new `username` column. |
| Signup openness | Open, gated by the existing `ALLOW_SIGNUP` env var. |
| OTP and Google | Removed entirely, all clients. |
| Landing scope | All of `(landing)` and `features/landing`. |
| Root route `/` | Redirect to `/login`. |
| Mobile | Converted to password in this change. |
| Existing users | Accept lockout. No CLI escape hatch. |
| `verification_code` table | Left in place. Code usage removed. |

### Rationale for the two judgment calls

**Existing users are locked out.** Accounts created via OTP or Google have
`password_hash = NULL` and no credential to present. The alternative — letting
anyone claim a password-less account by setting a password on it — is an
account-takeover hole and is rejected. If recovery is needed later, the safe
form is an operator-run CLI command, not a public endpoint.

**The `verification_code` table stays.** Dropping a table is irreversible and an
empty table costs nothing. Only the queries and generated code are removed.

## Reusing what already exists

`ALLOW_SIGNUP` is already plumbed end to end and needs no new flag:

- `server/internal/handler/config.go:95` reads the env var
- `checkSignupAllowed(email, isNew)` at `server/internal/handler/auth.go:235`
  gates it, and also honours `AllowedEmailDomains` and `AllowedEmails`
- `/api/config` exposes `allow_signup`
- `packages/core/config/index.ts` and `packages/core/platform/auth-initializer.tsx`
  carry it to the UI

Password signup calls the same gate. Introducing a second flag would create two
sources of truth for one policy.

## Server

### Migration

`server/migrations/348_user_password_auth.{up,down}.sql`

```sql
ALTER TABLE "user" ADD COLUMN password_hash TEXT;
```

Nullable, no default, no index — `email` is already unique, so no
`CREATE INDEX CONCURRENTLY` requirement applies.

### Queries

`server/pkg/db/queries/user.sql`: add `password_hash` to `CreateUser`, add
`SetUserPasswordHash`. Regenerate with `make sqlc`.

### Dependency

Add `golang.org/x/crypto` to `server/go.mod` for `bcrypt`.

### Shared login tail

Today `VerifyCode` (`auth.go:368`) ends with a substantial sequence that must
not be lost or duplicated:

- `auth.SetAuthCookies` — HttpOnly auth cookie plus CSRF cookie
- CloudFront signed cookies when `h.CFSigner != nil`
- `obsmetrics.RecordEvent(... analytics.Signup(...))` when the user is new
- `auth.IsTemporarilyDisabledUserEmail` / `ErrTemporarilyDisabledUser` handling
- `SignupError` mapped to 403

Extract this into `completeLogin(w, r, user, isNew)` and have both password
handlers use it. Copying it per handler is how these checks get missed.

### Handlers

`POST /auth/password/signup`

1. Decode, lowercase and trim email, require email and password
2. Reject a password shorter than 8 characters
3. `checkSignupAllowed(email, isNew=true)`
4. Reject with 409 if the account already exists
5. `bcrypt.GenerateFromPassword` at `bcrypt.DefaultCost`
6. Create the user with the hash, then `completeLogin(..., isNew=true)`

`POST /auth/password/login`

1. Decode, lowercase and trim email, require email and password
2. Look up the user; `bcrypt.CompareHashAndPassword` against the stored hash
3. On any failure — unknown email, null hash, or wrong password — return one
   generic `invalid email or password`
4. `completeLogin(..., isNew=false)`

The single generic error is deliberate. Distinct messages for "no password set"
versus "wrong password" turn the endpoint into an account enumeration oracle.

### Routes

In `server/cmd/server/router.go`, replace the three auth routes:

```
r.With(authRL).Post("/auth/password/signup", h.PasswordSignup)
r.With(authLoginRL).Post("/auth/password/login", h.PasswordLogin)
```

`authRL` is 5/min and is reused for signup. Add `authLoginRL` as a dedicated
limiter for password login, defaulting to 10/min and overridable via
`RATE_LIMIT_AUTH_LOGIN`, following the `envPositiveInt` pattern already used at
`router.go:1143`. Reusing `authVerifyRL` at 20/min is too loose against brute
force. `authVerifyRL` itself is removed with the OTP routes.

### Removals

- `SendCode`, `VerifyCode`, `GoogleLogin` and their request/response types
- `generateCode`, `isDevVerificationCode`, `isSixDigitCode`,
  `devVerificationCodeEnv`
- Routes `/auth/send-code`, `/auth/verify-code`, `/auth/google`
- `server/pkg/db/queries/verification_code.sql` and its generated code
- `SendVerificationCode` from `server/internal/service/email.go`
  (`SendInvitationEmail` stays — invitations still send mail)
- `GoogleClientID` from `AppConfig` and `GOOGLE_CLIENT_ID` from `.env.example`

## Shared packages

`packages/core/api/client.ts` and `packages/core/auth/store.ts`: replace
`sendCode` / `verifyCode` / `googleLogin` with `signupWithPassword` and
`loginWithPassword`.

`packages/core/api/schemas.ts`, `packages/core/config/index.ts`, and
`packages/core/platform/auth-initializer.tsx`: drop `google_client_id` /
`googleClientId`.

`packages/views/auth/login-page.tsx` (487 lines) collapses to a single card:

- Email and password fields
- A sign-in / create-account toggle, hidden when `allowSignup` is false
- Removed: the `code` step, `InputOTP` imports, resend cooldown, Google button,
  `google` and `onGoogleLogin` props
- Kept: the `cli_confirm` step, `redirectToCliCallback`, `validateCliCallback`,
  and the `extra` slot

The CLI flow must keep working. `server/cmd/multica/cmd_auth.go:265` opens
`{appURL}/login?cli_callback=…&cli_state=…` in a browser and waits for the token
on a local callback server. Password login satisfies that unchanged.

## Web

Delete:

- `apps/web/app/(landing)/` — `/`, `/homepage`, `/about`, `/changelog`,
  `/download`, `/usecases`, `/usecases/[slug]`, `/contact-sales`
- `apps/web/features/landing/` — 39 files including its own i18n dictionaries
- `apps/web/app/auth/callback/` — the Google OAuth callback and its test

Add `apps/web/app/page.tsx` redirecting to `/login`. Logged-in users continue
through the existing `resolvePostAuthDestination`.

Clean up:

- `apps/web/app/sitemap.ts:20` — the `/changelog` entry
- `apps/web/app/robots.ts:10` — the `/about` and `/changelog` allows
- `apps/web/app/type-scale.test.ts:56` — the `marketingPaths` exemption
- `apps/web/app/custom.css:87,98` — the `--font-instrument-serif` stack.
  That font is loaded only by the landing layout, so leaving the CSS would
  reference a variable nothing defines.
- `apps/web/app/(auth)/login/page.tsx` — the `googleClientId` wiring

## Desktop

`apps/desktop/src/renderer/src/pages/login.tsx`: remove `handleGoogleLogin` and
the `onGoogleLogin` prop. Desktop renders the shared `LoginPage`, so it inherits
the password form.

`apps/desktop/src/main/index.ts`: remove the "open URL in default browser for
Google login" IPC path if nothing else uses it. Desktop now logs in inline
rather than round-tripping through the browser.

## Mobile

`apps/mobile` shares only types and pure functions, so its auth is converted
separately but to the same semantics.

- `apps/mobile/data/api.ts` — replace `sendCode` / `verifyCode` with
  `signupWithPassword` / `loginWithPassword`
- `apps/mobile/data/auth-store.ts` — same swap; token is still written only on a
  successful credential call, and the 401-clears / 5xx-preserves rule is unchanged
- `apps/mobile/app/(auth)/login.tsx` — email plus password fields and a
  sign-in / create-account toggle. Mobile has no config store today, so it
  fetches `/api/config` on mount to read `allow_signup` and hides the
  create-account toggle when it is false. Absent or failed config defaults to
  showing the toggle, matching the `BooleanWithDefaultSchema(true)` default the
  shared schema already uses — the server still enforces the gate, so a visible
  toggle on a closed instance yields a clean 403 rather than an account.
- Delete `apps/mobile/app/(auth)/verify.tsx`
- `apps/mobile/lib/auth-error.ts` — `mapAuthError` messages currently assume
  codes; retarget them at credential failures.

## Testing

| Layer | Work |
| --- | --- |
| `server/internal/handler/auth_password_test.go` | New. Signup gating via `ALLOW_SIGNUP`, duplicate account, min length, wrong password, unknown email, null hash — asserting the generic error is identical across all failure modes. |
| `server/internal/handler/handler_test.go`, `config_test.go`, `cmd/server/integration_test.go` | Drop OTP and Google cases, add password paths. |
| `packages/views/auth/login-page.test.tsx` | Rewrite for the credentials form: sign-in, signup, toggle hidden when `allowSignup` is false, CLI callback, error display. |
| `packages/core/api/schema.test.ts` | Malformed-response test for the login response, per the API-compatibility rule in CLAUDE.md. |
| `apps/web/app/(auth)/login/page.test.tsx` | Update; delete `apps/web/app/auth/callback/page.test.tsx`. |
| `e2e/fixtures.ts` | `TestApiClient.login` becomes a single password-signup call, replacing send-code → DB read → verify-code and the per-email rate-limit workaround. |

Verification: `pnpm typecheck`, `pnpm test`, `make test`, `pnpm exec playwright test`.

## Commit sequence

One branch, four commits, each leaving the tree green. Removal lands only after
every client is migrated, so nothing is broken mid-branch.

1. `feat(auth): add email/password signup and login` — migration, queries,
   handlers, routes, shared client and store. OTP and Google still present.
2. `refactor(auth): move web, desktop, and mobile onto password login` —
   login UI, mobile screens, e2e fixtures.
3. `refactor(auth): remove email OTP and Google sign-in` — handlers, routes,
   queries, config field, callback route.
4. `refactor(web): remove the landing site` — routes, feature directory,
   sitemap, robots, fonts, type-scale exemption.

## Out of scope

- A `username` column. Email stays the identifier.
- Password reset or "forgot password". No credential recovery exists after this
  change; adding it needs its own design.
- Dropping the `verification_code` table.
- Docs under `apps/docs/` that describe the login flow, unless they break a
  build check.
