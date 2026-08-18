# Password-Only Auth and Landing Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace email-OTP and Google sign-in with email + password credentials across server, web, desktop, and mobile, and delete the marketing landing site so `/` redirects to `/login`.

**Architecture:** A nullable `password_hash` column on `"user"`, bcrypt hashing, and two new public endpoints (`/auth/password/signup`, `/auth/password/login`) that share one `completeLogin` tail with the handlers they replace. Signup reuses the existing `ALLOW_SIGNUP` gate rather than adding a second flag. Clients migrate onto the new endpoints before the old ones are deleted, so the tree is green at every commit.

**Tech Stack:** Go 1.26 (Chi, sqlc, pgx, `golang.org/x/crypto/bcrypt`), PostgreSQL 17, TypeScript strict, Next.js App Router, React, Zustand, TanStack Query, Zod, Vitest, Playwright, Expo/React Native.

**Spec:** `docs/superpowers/specs/2026-08-18-password-auth-design.md`

## Global Constraints

- Minimum password length is **8 characters**. Enforced server-side; the UI mirrors it.
- Password login returns **one identical error string for every failure mode** — unknown email, null hash, wrong password: `invalid email or password`. Never branch the message.
- Signup gating goes through the existing `h.checkSignupAllowed(email, isNew)`. **Do not add a new env var.**
- No database foreign keys, no cascading deletes. Any index a migration creates must use `CREATE INDEX CONCURRENTLY` in its own single-statement file. (This plan adds no index.)
- Code comments must be English.
- Parse all API JSON through a Zod schema via `parseWithFallback` in `packages/core/api/schema.ts`. Never cast network JSON to `T`.
- `packages/views/` must not import `next/*` or `react-router-dom`, and must not mock them in tests.
- Mobile shares only types and pure functions from `@multica/core`, using `import type` for types.
- Locale keys must be added to **all four** files: `packages/views/locales/{en,zh-Hans,ja,ko}/auth.json`.
- Commit messages use conventional prefixes: `feat(scope)`, `fix(scope)`, `refactor(scope)`, `test(scope)`.

## File Structure

**Server**
- `server/migrations/348_user_password_auth.{up,down}.sql` — new; adds `password_hash`
- `server/pkg/db/queries/user.sql` — modify; `CreateUser` gains the column, add `SetUserPasswordHash`
- `server/internal/handler/auth.go` — modify; `completeLogin`, `PasswordSignup`, `PasswordLogin`; later loses OTP/Google
- `server/internal/handler/auth_password_test.go` — new; all credential behaviour
- `server/cmd/server/router.go` — modify; routes and the login rate limiter
- `server/internal/handler/config.go` — modify; drops `GoogleClientID`
- `server/internal/service/email.go` — modify; drops `SendVerificationCode`

**Shared packages**
- `packages/core/api/client.ts`, `packages/core/auth/store.ts` — credential methods replace OTP/Google
- `packages/core/api/schemas.ts`, `packages/core/config/index.ts`, `packages/core/platform/auth-initializer.tsx` — drop `google_client_id`
- `packages/views/auth/login-page.tsx` — the credentials form; single responsibility, replaces a 3-step wizard
- `packages/views/locales/*/auth.json` — copy

**Apps**
- `apps/web/app/page.tsx` — new root redirect; `apps/web/app/(landing)/`, `apps/web/features/landing/`, `apps/web/app/auth/callback/` deleted
- `apps/desktop/src/renderer/src/pages/login.tsx` — drops Google
- `apps/mobile/data/{api.ts,auth-store.ts}`, `apps/mobile/app/(auth)/login.tsx`, `apps/mobile/lib/auth-error.ts` — credentials; `verify.tsx` deleted
- `e2e/fixtures.ts` — `TestApiClient.login` becomes one signup call

---

## Task 1: Add the `password_hash` column

**Files:**
- Create: `server/migrations/348_user_password_auth.up.sql`
- Create: `server/migrations/348_user_password_auth.down.sql`
- Modify: `server/pkg/db/queries/user.sql`

**Interfaces:**
- Consumes: nothing
- Produces: `db.User.PasswordHash pgtype.Text`; `db.CreateUserParams.PasswordHash pgtype.Text`

The design doc also listed a `SetUserPasswordHash` query. It is **not** added here: nothing in this plan updates an existing user's password, because password change and reset are out of scope. Add it with the feature that needs it rather than shipping a query with no caller.

- [ ] **Step 1: Write the up migration**

`server/migrations/348_user_password_auth.up.sql`:

```sql
-- Nullable: accounts created before password auth have no credential, and
-- the login handler treats a NULL hash as "no password set".
ALTER TABLE "user" ADD COLUMN password_hash TEXT;
```

- [ ] **Step 2: Write the down migration**

`server/migrations/348_user_password_auth.down.sql`:

```sql
ALTER TABLE "user" DROP COLUMN password_hash;
```

- [ ] **Step 3: Add the queries**

In `server/pkg/db/queries/user.sql`, change `CreateUser`:

```sql
-- name: CreateUser :one
INSERT INTO "user" (name, email, avatar_url, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING *;
```

- [ ] **Step 4: Apply the migration, then regenerate sqlc**

Both halves are required. `make sqlc` is pure code generation and never touches a database, so without `make migrate-up` the dev database keeps its old schema and Task 3's DB-backed handler tests fail on a missing column — a failure that reads like a handler bug rather than an unapplied migration.

```bash
make migrate-up
```

```bash
make sqlc
```

Verify the column actually landed:

```bash
docker exec multica-postgres-1 psql -U multica -d multica -c '\d "user"' | grep password_hash
```

Expected: a `password_hash | text` row, and `server/pkg/db/generated/models.go` gains `PasswordHash pgtype.Text` on `User`.

- [ ] **Step 5: Verify the build still compiles**

```bash
cd server && go build ./...
```

Expected: PASS. The existing call site uses a **keyed** struct literal (`db.CreateUserParams{Name: …, Email: …}`), and Go zero-values omitted fields in keyed literals — only unkeyed literals break when a field is added. So the new column does not break the build, and Step 6 is documentation rather than repair.

- [ ] **Step 6: State the no-credential invariant at the existing call site**

In `server/internal/handler/auth.go`, inside `findOrCreateUser`, the `CreateUser` call becomes:

```go
	created, err := h.Queries.CreateUser(ctx, db.CreateUserParams{
		Name:  name,
		Email: email,
		// No credential: this path is the OTP/Google entry point, which is
		// removed in a later task. Password signup sets the hash explicitly.
		PasswordHash: pgtype.Text{},
	})
```

- [ ] **Step 7: Verify the build passes**

```bash
cd server && go build ./... && go vet ./internal/handler
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add server/migrations/348_user_password_auth.up.sql server/migrations/348_user_password_auth.down.sql server/pkg/db/queries/user.sql server/pkg/db/generated server/internal/handler/auth.go
git commit -m "feat(auth): add password_hash column and queries"
```

---

## Task 2: Extract the shared login tail into `completeLogin`

This is a pure refactor. `VerifyCode` and `GoogleLogin` both end with the same sequence; the two password handlers need it too. Extracting once prevents the cookie/CSRF/analytics steps from being missed in a copy.

**Files:**
- Modify: `server/internal/handler/auth.go`
- Test: `server/internal/handler/handler_test.go` (existing tests must keep passing unchanged)

**Interfaces:**
- Consumes: `h.issueJWT`, `auth.SetAuthCookies`, `h.CFSigner`
- Produces: `func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, user db.User, cdnTTL time.Duration)` — writes the full success response and returns nothing; callers must `return` immediately after calling it.

**Signup analytics stay at the call sites and are NOT part of this helper.** The two existing tails are not identical, and folding them together would silently change behavior:

| | `VerifyCode` | `GoogleLogin` |
| --- | --- | --- |
| CDN cookie TTL | `auth.AuthTokenTTL()` (auth.go:444) | hardcoded `72 * time.Hour` (auth.go:650) |
| Signup event | plain `analytics.Signup(...)` | also stamps `evt.Properties["auth_method"] = "google"` (auth.go:603) |
| Event position | immediately before `issueJWT` | before a name/avatar profile-update block that sits between it and `issueJWT` (auth.go:606-631) |

So the CDN TTL is an explicit parameter, and each caller keeps its own analytics line in its own position.

- [ ] **Step 1: Run the existing auth tests to capture the green baseline**

```bash
cd server && go test ./internal/handler -run 'TestVerifyCode|TestGoogleLogin|TestSignupGating' -count=1
```

Expected: PASS. Record the names that ran — the same set must pass after the refactor.

- [ ] **Step 2: Add the `completeLogin` helper**

In `server/internal/handler/auth.go`, after `issueJWT`:

```go
// completeLogin writes the standard successful-authentication response: a
// JWT, the HttpOnly auth cookie plus its CSRF companion, CloudFront signed
// cookies when the CDN serves private content, and the LoginResponse body.
// Every authentication entry point ends here — the paired cookie calls are
// easy to omit in a hand-rolled copy, and omitting them yields a token the
// browser cannot actually use.
//
// Signup analytics deliberately stay at the call sites: each entry point
// stamps its own auth_method, and the Google path fires its event before a
// profile-update step that must not move.
//
// cdnTTL bounds only the CloudFront cookies. It is NOT the JWT lifetime,
// which issueJWT takes from auth.AuthTokenTTL().
//
// Callers must return immediately: this function owns the response.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, user db.User, cdnTTL time.Duration) {
	tokenString, err := h.issueJWT(user)
	if err != nil {
		if errors.Is(err, auth.ErrTemporarilyDisabledUser) {
			writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
			return
		}
		slog.Warn("login failed", append(logger.RequestAttrs(r), "error", err, "email", user.Email)...)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// HttpOnly auth cookie (browser clients) + CSRF cookie.
	if err := auth.SetAuthCookies(w, tokenString); err != nil {
		slog.Warn("failed to set auth cookies", "error", err)
	}

	// CloudFront signed cookies for CDN access.
	if h.CFSigner != nil {
		for _, cookie := range h.CFSigner.SignedCookies(time.Now().Add(cdnTTL)) {
			http.SetCookie(w, cookie)
		}
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		Token: tokenString,
		User:  h.userToResponse(user),
	})
}
```

One accepted deviation: the error-path `slog.Warn` unifies from `"login failed"` / `"google login failed"` to `"login failed"`. The success-path `slog.Info` lines stay at their call sites, so the two paths remain distinguishable in logs.

- [ ] **Step 3: Rewrite the tail of `VerifyCode` to call it**

In `VerifyCode`, **keep** the existing `if isNew { obsmetrics.RecordEvent(...) }` block exactly where it is. Replace only from `tokenString, err := h.issueJWT(user)` through the closing `writeJSON(...)` with:

```go
	slog.Info("user logged in", append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)
	h.completeLogin(w, r, user, auth.AuthTokenTTL())
```

- [ ] **Step 4: Rewrite the tail of `GoogleLogin` to call it**

Same substitution, with two differences that preserve current behavior exactly:

- **Keep** its `if isNew {` block — including `evt.Properties["auth_method"] = "google"` — in its current position, before the name/avatar profile-update block. Do not move it.
- Pass its own TTL, not `auth.AuthTokenTTL()`:

```go
	slog.Info("user logged in via google", append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)
	h.completeLogin(w, r, user, 72*time.Hour)
```

- [ ] **Step 5: Run the tests to confirm nothing changed**

```bash
cd server && go test ./internal/handler -run 'TestVerifyCode|TestGoogleLogin|TestSignupGating' -count=1 && go vet ./internal/handler
```

Expected: PASS, the same set as Step 1.

- [ ] **Step 6: Commit**

```bash
git add server/internal/handler/auth.go
git commit -m "refactor(auth): extract completeLogin from VerifyCode and GoogleLogin"
```

---

## Task 3: `POST /auth/password/signup`

**Files:**
- Modify: `server/internal/handler/auth.go`
- Create: `server/internal/handler/auth_password_test.go`

**Interfaces:**
- Consumes: `h.completeLogin`, `h.checkSignupAllowed`, `h.Queries.GetUserByEmail`, `h.Queries.CreateUser`
- Produces: `func (h *Handler) PasswordSignup(w http.ResponseWriter, r *http.Request)`; `PasswordSignupRequest{Email, Password, Name string}`; constants `minPasswordLength = 8`, `errInvalidCredentials = "invalid email or password"`

- [ ] **Step 1: Write the failing tests**

Create `server/internal/handler/auth_password_test.go`. These use the same `testHandler` harness as `handler_test.go`, which is constructed with `Config{AllowSignup: true}`.

**On the local `postJSON` helper:** the package already has `newRequest(method, path, body)` at `handler_test.go:182`, and normally you would reuse it rather than add a parallel abstraction. Do not reuse it here. It sets `X-User-ID` and `X-Workspace-ID` on every request, which are the headers of an *authenticated* caller. Signup and login are anonymous public endpoints, and a test that sends a user id while claiming to be a brand-new visitor is lying about the scenario. `postJSON` also differs in shape: it executes the handler and returns the recorder. Say this in a comment so the next reader does not "fix" it back.

```go
package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// postJSON issues an anonymous JSON request against a handler and returns the
// recorder. Deliberately not handler_test.go's newRequest: that helper stamps
// X-User-ID and X-Workspace-ID, and signup/login are public endpoints whose
// callers have no session yet.
func postJSON(t *testing.T, h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// uniqueEmail keeps each test row independent of previous runs.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("pw-%s-%d@example.com", t.Name(), timeNowUnixNano())
}

func TestPasswordSignupCreatesAccount(t *testing.T) {
	email := uniqueEmail(t)
	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
		"email":    email,
		"password": "correct-horse",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	var resp LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("token: want non-empty")
	}
	if resp.User.Email != email {
		t.Fatalf("email: want %q, got %q", email, resp.User.Email)
	}
}

func TestPasswordSignupRejectsShortPassword(t *testing.T) {
	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
		"email":    uniqueEmail(t),
		"password": "short7!",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestPasswordSignupRejectsDuplicateAccount(t *testing.T) {
	email := uniqueEmail(t)
	body := map[string]string{"email": email, "password": "correct-horse"}

	if rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", body); rec.Code != http.StatusOK {
		t.Fatalf("first signup: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second signup: want 409, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestPasswordSignupHonoursSignupGate(t *testing.T) {
	// Flip the gate on the shared handler and restore it. Do NOT copy the
	// Handler struct to do this — it is ~100 fields of live services, and a
	// copy silently diverges from the one the other tests use.
	prev := testHandler.cfg.AllowSignup
	testHandler.cfg.AllowSignup = false
	t.Cleanup(func() { testHandler.cfg.AllowSignup = prev })

	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
		"email":    uniqueEmail(t),
		"password": "correct-horse",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
}
```

Add the `timeNowUnixNano` helper at the bottom of the same file:

```go
func timeNowUnixNano() int64 { return time.Now().UnixNano() }
```

and add `"time"` to the import block.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd server && go test ./internal/handler -run TestPasswordSignup -count=1
```

Expected: FAIL to compile — `testHandler.PasswordSignup` undefined.

- [ ] **Step 3: Implement the handler**

In `server/internal/handler/auth.go`, add near the other request types:

```go
type PasswordSignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

const minPasswordLength = 8

// errInvalidCredentials is the ONLY failure string the login endpoint may
// return. Distinguishing "no account", "no password set", and "wrong
// password" turns the endpoint into an account-enumeration oracle, so all
// three collapse to this one message.
const errInvalidCredentials = "invalid email or password"
```

and the handler:

```go
// PasswordSignup creates an account from an email and password alone. It is
// gated by the same checkSignupAllowed policy as every other entry point, so
// ALLOW_SIGNUP and the email/domain allowlists apply unchanged.
func (h *Handler) PasswordSignup(w http.ResponseWriter, r *http.Request) {
	var req PasswordSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if len([]rune(req.Password)) < minPasswordLength {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("password must be at least %d characters", minPasswordLength))
		return
	}
	if auth.IsTemporarilyDisabledUserEmail(email) {
		writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
		return
	}

	// Signup is an explicit create: an existing account is a conflict, not a
	// login. Silently logging the caller in would let anyone who guesses an
	// email discover that it is registered.
	_, err := h.Queries.GetUserByEmail(r.Context(), email)
	if err == nil {
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	}
	if !isNotFound(err) {
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	if err := h.checkSignupAllowed(email, true); err != nil {
		var signupErr SignupError
		if errors.As(err, &signupErr) {
			writeError(w, http.StatusForbidden, signupErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = email
		if at := strings.Index(email, "@"); at > 0 {
			name = email[:at]
		}
	}

	user, err := h.Queries.CreateUser(r.Context(), db.CreateUserParams{
		Name:         name,
		Email:        email,
		PasswordHash: pgtype.Text{String: string(hash), Valid: true},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	// Signup analytics live at the call site, matching the other entry
	// points, so each one stamps its own auth_method.
	evt := analytics.Signup(uuidToString(user.ID), user.Email, signupSourceFromRequest(r))
	evt.Properties["auth_method"] = "password"
	obsmetrics.RecordEvent(h.Analytics, h.Metrics, evt)

	slog.Info("user signed up with password", append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)
	h.completeLogin(w, r, user, auth.AuthTokenTTL())
}
```

Add `"golang.org/x/crypto/bcrypt"` to the import block.

- [ ] **Step 4: Add the bcrypt dependency**

```bash
cd server && go get golang.org/x/crypto@latest && go mod tidy
```

- [ ] **Step 5: Run the tests to verify they pass — and that they actually ran**

```bash
cd server && go test ./internal/handler -run TestPasswordSignup -count=1 -v
```

Expected: PASS — all four tests, each appearing by name as `--- PASS: TestPasswordSignup...`.

**Check for a skip, not just for `ok`.** `TestMain` at `handler_test.go:44-53` calls `os.Exit(0)` when the database is unreachable, printing `Skipping tests: ...`. A skipped run therefore reports `ok` with zero tests executed, which is indistinguishable from success if you only read the last line. If the output contains `Skipping tests:` or shows no `--- PASS` lines, the suite did not run — treat that as a failure and report it, do not record it as a pass.

A PostgreSQL container is running on 127.0.0.1:5432 and `TestMain` defaults to `postgres://multica:multica@localhost:5432/multica?sslmode=disable`, so the suite should connect without any environment setup.

- [ ] **Step 6: Commit**

```bash
git add server/internal/handler/auth.go server/internal/handler/auth_password_test.go server/go.mod server/go.sum
git commit -m "feat(auth): add password signup endpoint"
```

---

## Task 4: `POST /auth/password/login`

**Files:**
- Modify: `server/internal/handler/auth.go`
- Modify: `server/internal/handler/auth_password_test.go`

**Interfaces:**
- Consumes: `h.completeLogin`, `errInvalidCredentials`, `h.Queries.GetUserByEmail`
- Produces: `func (h *Handler) PasswordLogin(w http.ResponseWriter, r *http.Request)`; `PasswordLoginRequest{Email, Password string}`

- [ ] **Step 0: Add cleanup for test-created accounts**

Task 3's tests create real rows in a **shared** development database and never remove them, so every run leaves more `pw-Test…@example.com` accounts behind. Add this helper and wire it into the Task 3 tests as well as your own — same file, coherent change:

```go
// cleanupUser deletes a test-created account when the test ends. These tests
// run against a shared development database, so without this every run leaves
// another account behind. Safe as a plain DELETE: this schema has no foreign
// keys or cascades, and a signup creates no dependent rows.
func cleanupUser(t *testing.T, email string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = testPool.Exec(
			context.Background(),
			`DELETE FROM "user" WHERE email = $1`,
			strings.ToLower(strings.TrimSpace(email)),
		)
	})
}
```

Call `cleanupUser(t, email)` immediately after generating an email in every test that signs one up — including the four Task 3 tests, which currently leak.

- [ ] **Step 1: Write the failing tests**

Append to `server/internal/handler/auth_password_test.go`:

```go
// signupFixture creates an account and returns its email.
func signupFixture(t *testing.T, password string) string {
	t.Helper()
	email := uniqueEmail(t)
	cleanupUser(t, email)
	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
		"email":    email,
		"password": password,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("fixture signup: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	return email
}

func TestPasswordLoginSucceeds(t *testing.T) {
	email := signupFixture(t, "correct-horse")

	rec := postJSON(t, testHandler.PasswordLogin, "/auth/password/login", map[string]string{
		"email":    email,
		"password": "correct-horse",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	var resp LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("token: want non-empty")
	}
}

func TestPasswordLoginIsCaseInsensitiveOnEmail(t *testing.T) {
	email := signupFixture(t, "correct-horse")

	rec := postJSON(t, testHandler.PasswordLogin, "/auth/password/login", map[string]string{
		"email":    strings.ToUpper(email),
		"password": "correct-horse",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// The three failure modes must be indistinguishable. A caller able to tell
// "no such account" from "wrong password" can enumerate registered emails.
func TestPasswordLoginFailuresAreIndistinguishable(t *testing.T) {
	withPassword := signupFixture(t, "correct-horse")

	// An account that exists but has no password hash — the state every
	// pre-existing OTP/Google account is left in. Seeded through CreateUser
	// directly, NOT findOrCreateUser: that helper is deleted in Task 13 along
	// with its only two callers.
	//
	// The email MUST be lowercased here. CreateUser stores exactly what it is
	// given, while the login handler lowercases its input before looking up.
	// A mixed-case seed would therefore never be found, and this case would
	// silently exercise the "unknown email" path instead of the "no password
	// set" path — the test would still pass, for the wrong reason, and one of
	// the three failure modes would go untested.
	noPassword := strings.ToLower(uniqueEmail(t))
	cleanupUser(t, noPassword)
	if _, err := testHandler.Queries.CreateUser(context.Background(), db.CreateUserParams{
		Name:         "no-password",
		Email:        noPassword,
		PasswordHash: pgtype.Text{},
	}); err != nil {
		t.Fatalf("seed password-less user: %v", err)
	}

	cases := []struct {
		name  string
		email string
	}{
		{"unknown_email", uniqueEmail(t)},
		{"no_password_set", noPassword},
		{"wrong_password", withPassword},
	}

	var bodies []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, testHandler.PasswordLogin, "/auth/password/login", map[string]string{
				"email":    tc.email,
				"password": "not-the-password",
			})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status: want 401, got %d (%s)", rec.Code, rec.Body.String())
			}
			bodies = append(bodies, rec.Body.String())
		})
	}

	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("failure responses differ and leak account state:\n  %s\n  %s", bodies[0], bodies[i])
		}
	}
}
```

Add `"context"`, `"strings"`, `"github.com/jackc/pgx/v5/pgtype"`, and `db "github.com/multica-ai/multica/server/pkg/db/generated"` to the import block.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd server && go test ./internal/handler -run TestPasswordLogin -count=1
```

Expected: FAIL to compile — `testHandler.PasswordLogin` undefined.

- [ ] **Step 3: Implement the handler**

In `server/internal/handler/auth.go`:

```go
type PasswordLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// dummyPasswordHash backs the unknown-account path so a missing email costs
// the same bcrypt round as a wrong password. Generated once rather than
// hardcoded: a literal hash has to be exactly right for bcrypt to do real
// work, and if it ever stopped being valid the comparison would return early
// and quietly restore the timing difference this exists to erase. Lazy rather
// than init() so process startup does not pay a deliberate ~60ms.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("multica-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		// Unreachable: a fixed short input at the default cost cannot fail.
		panic(fmt.Sprintf("generate dummy password hash: %v", err))
	}
	return h
})

// PasswordLogin authenticates an email + password pair. Every failure mode
// returns errInvalidCredentials with the same 401 status — see the constant's
// comment for why the cases are not distinguished.
func (h *Handler) PasswordLogin(w http.ResponseWriter, r *http.Request) {
	var req PasswordLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if auth.IsTemporarilyDisabledUserEmail(email) {
		writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
		return
	}

	user, err := h.Queries.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Spend a bcrypt round anyway so a missing account is not measurably
		// faster than a wrong password.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(req.Password))
		writeError(w, http.StatusUnauthorized, errInvalidCredentials)
		return
	}

	if !user.PasswordHash.Valid || user.PasswordHash.String == "" {
		// Same bcrypt round as the other two failure paths. Returning early
		// here would make "account exists but has no password" measurably
		// faster than both "no such account" and "wrong password" — and that
		// set is exactly the pre-existing OTP/Google accounts, which is a
		// useful thing for an attacker to enumerate. Identical bodies are not
		// enough on their own; the timing has to match too.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(req.Password))
		writeError(w, http.StatusUnauthorized, errInvalidCredentials)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, errInvalidCredentials)
		return
	}

	if auth.IsTemporarilyDisabledUser(uuidToString(user.ID), user.Email) {
		writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
		return
	}

	slog.Info("user logged in with password", append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "email", user.Email)...)
	// No analytics here: this is a returning user, not a signup.
	h.completeLogin(w, r, user, auth.AuthTokenTTL())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd server && go test ./internal/handler -run 'TestPassword' -count=1 -v
```

Expected: PASS — signup and login suites.

- [ ] **Step 5: Commit**

```bash
git add server/internal/handler/auth.go server/internal/handler/auth_password_test.go
git commit -m "feat(auth): add password login endpoint"
```

---

## Task 5: Mount the routes with a dedicated login rate limiter

**Files:**
- Modify: `server/cmd/server/router.go:1143-1149`
- Modify: `server/cmd/server/integration_test.go`

**Interfaces:**
- Consumes: `h.PasswordSignup`, `h.PasswordLogin`
- Produces: routes `POST /auth/password/signup`, `POST /auth/password/login`

- [ ] **Step 1: Write the failing integration test**

Append to `server/cmd/server/integration_test.go`, matching the file's existing style for building a router and issuing requests:

`TestMain` in that file already builds a router and serves it at the package-level
`testServer`, so the test posts against that:

```go
func TestPasswordAuthRoutesAreMounted(t *testing.T) {
	for _, path := range []string{"/auth/password/signup", "/auth/password/login"} {
		resp, err := http.Post(testServer.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()

		// An empty body is a 400 from the handler. A 404 means the route is
		// not mounted at all, which is what this test guards.
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("%s: route not mounted", path)
		}
	}
}
```

Add `"strings"` to the import block if it is not already there.

- [ ] **Step 2: Run it to verify it fails**

```bash
cd server && go test ./cmd/server -run TestPasswordAuthRoutesAreMounted -count=1
```

Expected: FAIL — both paths return 404.

- [ ] **Step 3: Add the rate limiter and routes**

In `server/cmd/server/router.go`, beside the existing limiters at line 1143:

```go
	// Password login is the brute-forceable endpoint: a wrong guess costs the
	// attacker one request, so it gets a tighter budget than the OTP verify
	// limiter it replaces (20/min).
	authLoginRL := middleware.RateLimit(rdb, envPositiveInt("RATE_LIMIT_AUTH_LOGIN", 10), time.Minute, trustedProxies)
```

and in the public auth group:

```go
	r.With(authRL).Post("/auth/password/signup", h.PasswordSignup)
	r.With(authLoginRL).Post("/auth/password/login", h.PasswordLogin)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd server && go test ./cmd/server -run TestPasswordAuthRoutesAreMounted -count=1
```

Expected: PASS.

- [ ] **Step 5: Document the new env var**

In `.env.example`, beside the other `RATE_LIMIT_*` entries:

```
# Password login attempts allowed per minute per client. Lower is safer;
# raise only if legitimate users are being throttled.
RATE_LIMIT_AUTH_LOGIN=10
```

- [ ] **Step 6: Run the full server suite**

```bash
make test
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add server/cmd/server/router.go server/cmd/server/integration_test.go .env.example
git commit -m "feat(auth): mount password auth routes with a dedicated rate limit"
```

---

## Task 6: Add credential methods to the shared API client and auth store

**Files:**
- Modify: `packages/core/api/client.ts:676-695`
- Modify: `packages/core/auth/store.ts`
- Test: `packages/core/auth/store.test.ts`

**Interfaces:**
- Consumes: the two server endpoints from Tasks 3–5
- Produces:
  - `ApiClient.signupWithPassword(email: string, password: string, name?: string): Promise<LoginResponse>`
  - `ApiClient.loginWithPassword(email: string, password: string): Promise<LoginResponse>`
  - `AuthState.signupWithPassword(email: string, password: string, name?: string): Promise<User>`
  - `AuthState.loginWithPassword(email: string, password: string): Promise<User>`

- [ ] **Step 1: Write the failing store test**

`packages/core/auth/store.test.ts` **already exists** — extend it, do not overwrite it. It has two passing tests (`retryAuthentication`, `logout`) that must survive, and it already defines `fakeUser`, `makeStorage()`, and `makeApi()`. Reuse those rather than introducing a parallel set of helpers.

Do **not** add a `// @vitest-environment node` directive. `store.ts` imports `identifyAnalytics` from `../analytics`, and `packages/core/analytics/index.ts` branches on `typeof window` at lines 91, 109, 399, and 444 — exactly the case CLAUDE.md says must not get the node directive.

Widen the existing `makeApi` to accept overrides and to carry the two new methods:

```ts
function makeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    setToken: vi.fn(),
    signupWithPassword: vi.fn().mockResolvedValue({ token: "t-1", user: fakeUser }),
    loginWithPassword: vi.fn().mockResolvedValue({ token: "t-1", user: fakeUser }),
    ...overrides,
  } as unknown as ApiClient;
}
```

Then append a second `describe` block:

```ts
describe("authStore credentials", () => {
  it("logs in with a password and marks the session authenticated", async () => {
    const storage = makeStorage();
    const api = makeApi();
    const store = createAuthStore({ api, storage });

    const result = await store.getState().loginWithPassword("alice@example.com", "correct-horse");

    expect(api.loginWithPassword).toHaveBeenCalledWith("alice@example.com", "correct-horse");
    expect(result).toEqual(fakeUser);
    expect(store.getState().status).toBe("authenticated");
    expect(store.getState().user).toEqual(fakeUser);
  });

  it("persists the token in token mode but not in cookie mode", async () => {
    const tokenStorage = makeStorage();
    const tokenStore = createAuthStore({ api: makeApi(), storage: tokenStorage });
    await tokenStore.getState().loginWithPassword("alice@example.com", "correct-horse");
    expect(tokenStorage.snapshot().multica_token).toBe("t-1");

    const cookieStorage = makeStorage();
    const cookieStore = createAuthStore({ api: makeApi(), storage: cookieStorage, cookieAuth: true });
    await cookieStore.getState().loginWithPassword("alice@example.com", "correct-horse");
    expect(cookieStorage.snapshot().multica_token).toBeUndefined();
  });

  it("signs up and authenticates in one call", async () => {
    const api = makeApi();
    const store = createAuthStore({ api, storage: makeStorage() });

    await store.getState().signupWithPassword("alice@example.com", "correct-horse");

    expect(api.signupWithPassword).toHaveBeenCalledWith("alice@example.com", "correct-horse", undefined);
    expect(store.getState().status).toBe("authenticated");
  });

  it("leaves the session unauthenticated when login rejects", async () => {
    const store = createAuthStore({
      api: makeApi({
        loginWithPassword: vi.fn().mockRejectedValue(new Error("invalid email or password")),
      }),
      storage: makeStorage(),
    });

    await expect(
      store.getState().loginWithPassword("alice@example.com", "nope"),
    ).rejects.toThrow("invalid email or password");
    expect(store.getState().user).toBeNull();
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
pnpm --filter @multica/core test auth/store.test.ts
```

Expected: FAIL — `loginWithPassword is not a function`, with the two pre-existing tests still passing.

**Confirm the run actually matched your file.** `packages/core/vitest.config.ts` sets `passWithNoTests: true`, so a filter matching nothing reports success. The output must name `auth/store.test.ts` and show six tests (two existing plus your four); if it shows "no test files found" or zero tests, the filter missed and you have proven nothing.

- [ ] **Step 3: Add the client methods**

In `packages/core/api/client.ts`, beside `sendCode`:

```ts
  async signupWithPassword(
    email: string,
    password: string,
    name?: string,
  ): Promise<LoginResponse> {
    return this.fetch("/auth/password/signup", {
      method: "POST",
      body: JSON.stringify({ email, password, name }),
    });
  }

  async loginWithPassword(email: string, password: string): Promise<LoginResponse> {
    return this.fetch("/auth/password/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  }
```

- [ ] **Step 4: Add the store actions**

In `packages/core/auth/store.ts`, add to the `AuthState` interface:

```ts
  signupWithPassword: (email: string, password: string, name?: string) => Promise<User>;
  loginWithPassword: (email: string, password: string) => Promise<User>;
```

and to the store body, beside `verifyCode`:

```ts
    signupWithPassword: async (email: string, password: string, name?: string) => {
      const { token, user } = await api.signupWithPassword(email, password, name);
      if (!cookieAuth) {
        storage.setItem("multica_token", token);
        api.setToken(token);
      }
      onLogin?.();
      identifyAnalytics(user.id, { email: user.email, name: user.name });
      set({ user, isLoading: false, status: "authenticated" });
      return user;
    },

    loginWithPassword: async (email: string, password: string) => {
      const { token, user } = await api.loginWithPassword(email, password);
      if (!cookieAuth) {
        storage.setItem("multica_token", token);
        api.setToken(token);
      }
      onLogin?.();
      identifyAnalytics(user.id, { email: user.email, name: user.name });
      set({ user, isLoading: false, status: "authenticated" });
      return user;
    },
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
pnpm --filter @multica/core test auth/store.test.ts && pnpm --filter @multica/core typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/core/api/client.ts packages/core/auth/store.ts packages/core/auth/store.test.ts
git commit -m "feat(auth): add password credential methods to core client and store"
```

---

## Task 7: Add the credential copy to all four locales

Doing this before the UI task means the component can reference real keys instead of placeholders.

**Files:**
- Modify: `packages/views/locales/en/auth.json`
- Modify: `packages/views/locales/zh-Hans/auth.json`
- Modify: `packages/views/locales/ja/auth.json`
- Modify: `packages/views/locales/ko/auth.json`

**Interfaces:**
- Produces: keys `signin.description`, `signin.submit`, `signin.submitting`, `signin.switch_to_signup`, `signup.title`, `signup.description`, `signup.submit`, `signup.submitting`, `signup.switch_to_signin`, `common.password`, `common.password_placeholder`, `common.password_required`, `common.password_too_short`, `errors.credentials_invalid`, `errors.signup_failed`

- [ ] **Step 1: Read the Chinese voice conventions**

```bash
sed -n '1,200p' apps/docs/content/docs/developers/conventions.zh.mdx
```

Follow its glossary and tone rules for the `zh-Hans` strings. Do not invent product terms.

- [ ] **Step 2: Update `en/auth.json` — ADD ONLY, remove nothing**

This task is **purely additive**. `packages/views/i18n/resources-types.ts:7` types the dictionary as `typeof en/auth.json`, and `login-page.tsx` still reads `verify.*` and `signin.sending` until Task 8. Deleting a key here would fail typecheck and land a red commit. The dead keys (`signin.sending`, `signin.google`, `verify.*`, `errors.send_failed`, `errors.resend_failed`, `errors.code_invalid`) are removed in **Task 8**, in the same commit that stops the component referencing them.

Add the `signup` block, and add the new keys to `signin`, `common`, and `errors` while leaving every existing key in place. `signin.description` is the one existing value that changes, because it no longer promises a code.

```json
  "signin": {
    "title": "Sign in to Multica",
    "description": "Enter your email and password",
    "continue": "Continue",
    "sending": "Sending code...",
    "google": "Continue with Google",
    "submit": "Sign in",
    "submitting": "Signing in...",
    "switch_to_signup": "Need an account? Sign up"
  },
  "signup": {
    "title": "Create your account",
    "description": "Choose an email and password to get started",
    "submit": "Create account",
    "submitting": "Creating account...",
    "switch_to_signin": "Already have an account? Sign in"
  },
  "common": {
    "back": "Back",
    "email": "Email",
    "email_placeholder": "you@example.com",
    "email_required": "Email is required",
    "password": "Password",
    "password_placeholder": "At least 8 characters",
    "password_required": "Password is required",
    "password_too_short": "Password must be at least 8 characters"
  },
  "errors": {
    "server_unreachable": "Make sure the server is running.",
    "send_failed": "Failed to send code.",
    "resend_failed": "Failed to resend code",
    "code_invalid": "Invalid or expired code",
    "credentials_invalid": "Invalid email or password",
    "signup_failed": "Could not create your account.",
    "cli_auth_failed": "Failed to authorize CLI. Please log in again."
  },
```

Leave the `verify`, `cli`, `web`, and `desktop` blocks untouched — Task 8 removes `verify`.

- [ ] **Step 3: Apply the same key set to the other three locales**

Translate the new values for `zh-Hans`, `ja`, and `ko`, again adding only. Every key present in `en/auth.json` must exist in all three.

- [ ] **Step 3b: Verify the workspace still typechecks**

```bash
pnpm --filter @multica/views typecheck
```

Expected: PASS. This is the check that proves the task stayed additive — a removed key would break `login-page.tsx`, which still reads the OTP copy until Task 8.

- [ ] **Step 4: Verify the four files have identical key sets**

```bash
for l in en zh-Hans ja ko; do
  echo "$l: $(node -e "
    const f=require('./packages/views/locales/$l/auth.json');
    const walk=(o,p='')=>Object.entries(o).flatMap(([k,v])=>typeof v==='object'?walk(v,p+k+'.'):[p+k]);
    console.log(walk(f).sort().join(','))
  " | md5)"
done
```

Expected: the same hash on all four lines.

- [ ] **Step 5: Commit**

```bash
git add packages/views/locales
git commit -m "feat(auth): add credential copy to all locales"
```

---

## Task 8: Rewrite the shared login page as a credentials form

**Files:**
- Modify: `packages/views/auth/login-page.tsx`
- Modify: `packages/views/locales/{en,zh-Hans,ja,ko}/auth.json` (delete the now-dead OTP keys)
- Test: `packages/views/auth/login-page.test.tsx`

**Interfaces:**
- Consumes: `useAuthStore().loginWithPassword`, `useAuthStore().signupWithPassword`, `useConfigStore().allowSignup`, the Task 7 locale keys
- Produces: `LoginPage` props become `{ logo?, onSuccess, cliCallback?, onTokenObtained?, extra? }` — `google` and `onGoogleLogin` are **removed**. `redirectToCliCallback` and `validateCliCallback` keep their current signatures. (`extra` survives this task and is removed in Task 9, which owns its last call site.)

- [ ] **Step 1: Write the failing tests**

Rewrite `packages/views/auth/login-page.test.tsx`. The existing file mocks `@multica/core/auth` and `@multica/core/api`; both mocks change. Replace the OTP hoisted mocks (`mockSendCode`, `mockVerifyCode`, `mockApiVerifyCode`) with:

```tsx
const mockLoginWithPassword = vi.hoisted(() => vi.fn());
const mockSignupWithPassword = vi.hoisted(() => vi.fn());
const mockApiLoginWithPassword = vi.hoisted(() => vi.fn());
const mockApiSignupWithPassword = vi.hoisted(() => vi.fn());

vi.mock("@multica/core/auth", () => ({
  useAuthStore: Object.assign(
    (selector?: (s: unknown) => unknown) => {
      const state = {
        loginWithPassword: mockLoginWithPassword,
        signupWithPassword: mockSignupWithPassword,
      };
      return selector ? selector(state) : state;
    },
    {
      getState: () => ({
        loginWithPassword: mockLoginWithPassword,
        signupWithPassword: mockSignupWithPassword,
      }),
    },
  ),
}));
```

and the API mock — `loginWithPassword` / `signupWithPassword` are what the CLI-callback path calls directly, so they must exist on the mocked `api` object:

```tsx
vi.mock("@multica/core/api", () => ({
  api: {
    listWorkspaces: mockApiListWorkspaces,
    loginWithPassword: mockApiLoginWithPassword,
    signupWithPassword: mockApiSignupWithPassword,
    setToken: mockApiSetToken,
    getMe: mockApiGetMe,
    issueCliToken: mockApiIssueCliToken,
  },
}));
```

The behavioural tests:

```tsx
it("signs in with email and password", async () => {
  mockLoginWithPassword.mockResolvedValueOnce({ id: "u-1", email: "a@example.com", name: "A" });
  mockApiListWorkspaces.mockResolvedValueOnce([{ id: "ws-1" }]);

  render(<LoginPage onSuccess={onSuccess} />);
  const user = userEvent.setup();

  await user.type(screen.getByLabelText(/email/i), "a@example.com");
  await user.type(screen.getByLabelText(/password/i), "correct-horse");
  await user.click(screen.getByRole("button", { name: /^sign in$/i }));

  await waitFor(() => {
    expect(mockLoginWithPassword).toHaveBeenCalledWith("a@example.com", "correct-horse");
    expect(onSuccess).toHaveBeenCalled();
  });
});

it("shows the server error when credentials are rejected", async () => {
  mockLoginWithPassword.mockRejectedValueOnce(new Error("invalid email or password"));

  render(<LoginPage onSuccess={onSuccess} />);
  const user = userEvent.setup();

  await user.type(screen.getByLabelText(/email/i), "a@example.com");
  await user.type(screen.getByLabelText(/password/i), "wrong-password");
  await user.click(screen.getByRole("button", { name: /^sign in$/i }));

  await waitFor(() => {
    expect(screen.getByText(/invalid email or password/i)).toBeInTheDocument();
  });
  expect(onSuccess).not.toHaveBeenCalled();
});

it("switches to signup and creates an account", async () => {
  mockSignupWithPassword.mockResolvedValueOnce({ id: "u-1", email: "a@example.com", name: "A" });
  mockApiListWorkspaces.mockResolvedValueOnce([]);

  render(<LoginPage onSuccess={onSuccess} />);
  const user = userEvent.setup();

  await user.click(screen.getByRole("button", { name: /need an account/i }));
  await user.type(screen.getByLabelText(/email/i), "a@example.com");
  await user.type(screen.getByLabelText(/password/i), "correct-horse");
  await user.click(screen.getByRole("button", { name: /^create account$/i }));

  await waitFor(() => {
    expect(mockSignupWithPassword).toHaveBeenCalledWith("a@example.com", "correct-horse");
    expect(onSuccess).toHaveBeenCalled();
  });
});

it("rejects a short password before calling the server", async () => {
  render(<LoginPage onSuccess={onSuccess} />);
  const user = userEvent.setup();

  await user.click(screen.getByRole("button", { name: /need an account/i }));
  await user.type(screen.getByLabelText(/email/i), "a@example.com");
  await user.type(screen.getByLabelText(/password/i), "short7!");
  await user.click(screen.getByRole("button", { name: /^create account$/i }));

  await waitFor(() => {
    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
  });
  expect(mockSignupWithPassword).not.toHaveBeenCalled();
});

it("hides the signup switch when the deployment disallows signup", () => {
  mockAllowSignup = false;
  render(<LoginPage onSuccess={onSuccess} />);
  expect(screen.queryByRole("button", { name: /need an account/i })).not.toBeInTheDocument();
});

it("redirects to the CLI callback with the token instead of calling onSuccess", async () => {
  mockApiLoginWithPassword.mockResolvedValueOnce({ token: "cli-token", user: { id: "u-1" } });

  render(
    <LoginPage
      onSuccess={onSuccess}
      cliCallback={{ url: "http://localhost:51234/callback", state: "st-1" }}
    />,
  );
  const user = userEvent.setup();

  await user.type(screen.getByLabelText(/email/i), "a@example.com");
  await user.type(screen.getByLabelText(/password/i), "correct-horse");
  await user.click(screen.getByRole("button", { name: /^sign in$/i }));

  await waitFor(() => {
    expect(window.location.href).toContain("token=cli-token");
  });
  expect(onSuccess).not.toHaveBeenCalled();
});
```

Mock the config store alongside the others so `mockAllowSignup` is readable:

```tsx
let mockAllowSignup = true;
vi.mock("@multica/core/config", () => ({
  useConfigStore: Object.assign(
    (selector?: (s: unknown) => unknown) => {
      const state = { allowSignup: mockAllowSignup };
      return selector ? selector(state) : state;
    },
    { getState: () => ({ allowSignup: mockAllowSignup }) },
  ),
}));
```

Reset `mockAllowSignup = true` in `beforeEach`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
pnpm --filter @multica/views test auth/login-page.test.tsx
```

Expected: FAIL — no password field is rendered.

- [ ] **Step 3: Rewrite the component**

In `packages/views/auth/login-page.tsx`:

- Delete the `GoogleAuthConfig` interface, the `google` and `onGoogleLogin` props, `handleGoogleLogin`, and the entire Google `<Button>` including its inline SVG.
- Delete the `InputOTP`/`InputOTPGroup`/`InputOTPSlot` import, the `code` and `cooldown` state, the cooldown `useEffect`, `handleSendCode`, `handleVerify`, `handleResend`, and the whole `step === "code"` block.
- Narrow the step state to `useState<"credentials" | "cli_confirm">("credentials")`.
- Keep, unchanged: the `cliCallback` session-detection `useEffect`, `handleCliAuthorize`, the `cli_confirm` render block, `redirectToCliCallback`, `validateCliCallback`, and the `extra` slot.

Add the new state and submit handler:

```tsx
  const allowSignup = useConfigStore((s) => s.allowSignup);
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [password, setPassword] = useState("");

  const handleSubmit = useCallback(
    async (e?: React.FormEvent) => {
      e?.preventDefault();
      if (!email) {
        setError(t(($) => $.common.email_required));
        return;
      }
      if (!password) {
        setError(t(($) => $.common.password_required));
        return;
      }
      // Mirror the server's floor so a doomed signup costs no round trip.
      if (mode === "signup" && password.length < MIN_PASSWORD_LENGTH) {
        setError(t(($) => $.common.password_too_short));
        return;
      }

      setLoading(true);
      setError("");
      try {
        if (cliCallback) {
          // CLI path: take the token directly for the redirect URL.
          const { token } =
            mode === "signup"
              ? await api.signupWithPassword(email, password)
              : await api.loginWithPassword(email, password);
          localStorage.setItem("multica_token", token);
          api.setToken(token);
          onTokenObtained?.();
          redirectToCliCallback(cliCallback.url, token, cliCallback.state);
          return;
        }

        // Normal path: seed the workspace list into the Query cache so the
        // caller's onSuccess can compute a destination synchronously.
        if (mode === "signup") {
          await useAuthStore.getState().signupWithPassword(email, password);
        } else {
          await useAuthStore.getState().loginWithPassword(email, password);
        }
        const wsList = await api.listWorkspaces();
        qc.setQueryData(workspaceKeys.list(), wsList);
        onTokenObtained?.();
        onSuccess();
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : t(($) =>
                mode === "signup" ? $.errors.signup_failed : $.errors.credentials_invalid,
              ),
        );
        setLoading(false);
      }
    },
    [cliCallback, email, mode, onSuccess, onTokenObtained, password, qc, t],
  );
```

with, near the top of the file:

```tsx
/** Mirrors minPasswordLength in server/internal/handler/auth.go. */
const MIN_PASSWORD_LENGTH = 8;
```

The credentials render block:

```tsx
  return (
    <div className="flex min-h-svh items-center justify-center">
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          {logo && <div className="mx-auto mb-4">{logo}</div>}
          <CardTitle className="text-display-sm">
            {t(($) => (mode === "signup" ? $.signup.title : $.signin.title))}
          </CardTitle>
          <CardDescription>
            {t(($) => (mode === "signup" ? $.signup.description : $.signin.description))}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form id="login-form" onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="login-email">{t(($) => $.common.email)}</Label>
              <Input
                id="login-email"
                type="email"
                autoComplete="email"
                placeholder={t(($) => $.common.email_placeholder)}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="login-password">{t(($) => $.common.password)}</Label>
              <Input
                id="login-password"
                type="password"
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
                placeholder={t(($) => $.common.password_placeholder)}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error && <p className="text-body text-destructive">{error}</p>}
          </form>
        </CardContent>
        <CardFooter className="flex flex-col gap-3">
          <Button
            type="submit"
            form="login-form"
            className="w-full"
            size="lg"
            disabled={!email || !password || loading}
          >
            {loading
              ? t(($) => (mode === "signup" ? $.signup.submitting : $.signin.submitting))
              : t(($) => (mode === "signup" ? $.signup.submit : $.signin.submit))}
          </Button>
          {allowSignup && (
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setMode((m) => (m === "signup" ? "signin" : "signup"));
                setError("");
              }}
            >
              {t(($) =>
                mode === "signup" ? $.signup.switch_to_signin : $.signin.switch_to_signup,
              )}
            </Button>
          )}
          {extra && <div className="w-full pt-1 text-center">{extra}</div>}
        </CardFooter>
      </Card>
    </div>
  );
```

Import `useConfigStore` from `@multica/core/config`.

- [ ] **Step 4: Delete the now-dead OTP locale keys**

Task 7 deliberately left these in place, because the component still read them. It no longer does, so remove from all four `auth.json` files: `signin.continue`, `signin.sending`, `signin.google`, the whole `verify` block, `errors.send_failed`, `errors.resend_failed`, and `errors.code_invalid`.

Also check whether `errors.server_unreachable` still has a reader — `handleSendCode` was its only one:

```bash
grep -rn "server_unreachable" packages apps --include='*.tsx' --include='*.ts' | grep -v node_modules | grep -v locales
```

If that returns nothing, delete the key too.

Then confirm the four files still agree:

```bash
for l in en zh-Hans ja ko; do
  echo "$l: $(node -e "
    const f=require('./packages/views/locales/$l/auth.json');
    const walk=(o,p='')=>Object.entries(o).flatMap(([k,v])=>typeof v==='object'?walk(v,p+k+'.'):[p+k]);
    console.log(walk(f).sort().join(','))
  " | md5)"
done
```

Expected: the same hash on all four lines.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
pnpm --filter @multica/views test auth/login-page.test.tsx && pnpm --filter @multica/views typecheck
```

Expected: PASS — all six tests, and typecheck proves no surviving reader of a deleted key.

- [ ] **Step 6: Commit**

```bash
git add packages/views/auth/login-page.tsx packages/views/auth/login-page.test.tsx packages/views/locales
git commit -m "refactor(auth): rewrite the shared login page as a credentials form"
```

---

## Task 9: Update the web login route

**Files:**
- Modify: `apps/web/app/(auth)/login/page.tsx:63,218-248`
- Modify: `packages/views/auth/login-page.tsx` (drop the now-unused `extra` prop)
- Modify: `packages/views/locales/{en,zh-Hans,ja,ko}/auth.json` (drop `web.prefer_desktop` / `web.download`)
- Test: `apps/web/app/(auth)/login/page.test.tsx`

**Interfaces:**
- Consumes: the Task 8 `LoginPage` props
- Produces: `LoginPage` props become `{ logo?, onSuccess, cliCallback?, onTokenObtained? }` — `extra` is removed here, in the same commit as its last call site.

- [ ] **Step 1: Remove the Google and download wiring**

In `apps/web/app/(auth)/login/page.tsx`:

- Delete the `const googleClientId = useConfigStore((state) => state.googleClientId);` line and the `googleState` variable if it becomes unused.
- Delete the `google={...}` prop from `<LoginPage>`.
- Delete the `extra={...}` prop entirely. It links to `/download`, which Task 15 deletes; keeping it would render a dead link. Remove the now-unused `Link` import and the `web.prefer_desktop` / `web.download` usages.

Then, in the same commit, remove the prop itself from `packages/views/auth/login-page.tsx` — its `extra?: ReactNode` declaration, the destructured parameter, and the `{extra && <div …>{extra}</div>}` render line. The web login page was its only consumer, so it is now dead. Doing this in one commit keeps both files green; splitting it would leave one of them red.

Drop `web.prefer_desktop` and `web.download` from all four `auth.json` files, and verify nothing else reads them:

```bash
grep -rn "prefer_desktop\|web.download" apps packages --include='*.tsx' --include='*.ts' | grep -v node_modules | grep -v locales
```

Expected: no output. Keep the rest of the `web` block — `web.desktop_handoff.*` is still used by the desktop handoff flow in this same file.

The call becomes:

```tsx
  return (
    <LoginPage
      onSuccess={handleSuccess}
      cliCallback={
        cliCallbackRaw && validateCliCallback(cliCallbackRaw)
          ? { url: cliCallbackRaw, state: cliState }
          : undefined
      }
      onTokenObtained={setLoggedInCookie}
    />
  );
```

- [ ] **Step 2: Update the route test**

In `apps/web/app/(auth)/login/page.test.tsx`, delete any case asserting the Google button, the `googleClientId` config wiring, or the download prompt. Keep the post-login destination tests, which are the reason this file exists.

- [ ] **Step 3: Run the tests**

```bash
pnpm --filter @multica/web test "app/(auth)/login/page.test.tsx" && pnpm --filter @multica/views typecheck && pnpm --filter @multica/web typecheck
```

Expected: PASS. The two typechecks are what prove the `extra` removal left no orphaned consumer.

- [ ] **Step 4: Commit**

```bash
git add "apps/web/app/(auth)/login/page.tsx" "apps/web/app/(auth)/login/page.test.tsx" packages/views/auth/login-page.tsx packages/views/locales
git commit -m "refactor(auth): drop Google and download wiring from the web login route"
```

---

## Task 10: Update the desktop login page

**Files:**
- Modify: `apps/desktop/src/renderer/src/pages/login.tsx`
- Modify: `apps/desktop/src/main/index.ts:675`

**Interfaces:**
- Consumes: the Task 8 `LoginPage` props
- Produces: no exported change

- [ ] **Step 1: Remove the Google handler**

`apps/desktop/src/renderer/src/pages/login.tsx` becomes:

```tsx
import { LoginPage } from "@multica/views/auth";
import { DragStrip } from "@multica/views/platform";
import { MulticaIcon } from "@multica/ui/components/common/multica-icon";

export function DesktopLoginPage() {
  return (
    <div className="flex h-screen flex-col">
      <DragStrip />
      <LoginPage
        logo={<MulticaIcon bordered size="lg" />}
        onSuccess={() => {
          // Auth store update triggers AppContent re-render → shows DesktopShell.
          // Initial workspace navigation happens in routes.tsx via IndexRedirect.
        }}
      />
    </div>
  );
}
```

`requireRuntimeAppUrl` becomes unused here — delete it from this file. Desktop now authenticates in-app instead of round-tripping through the browser.

- [ ] **Step 2: Check whether the openExternal IPC is still used**

```bash
grep -rn "openExternal" apps/desktop/src --include='*.ts' --include='*.tsx'
```

If the renderer no longer calls it anywhere, delete the IPC handler at `apps/desktop/src/main/index.ts:675` and its preload binding. If another feature still uses it, leave it and only update its comment, which currently says "used by renderer for Google login".

- [ ] **Step 3: Typecheck the desktop app**

```bash
pnpm --filter @multica/desktop typecheck
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add apps/desktop/src
git commit -m "refactor(auth): drop Google sign-in from the desktop login page"
```

---

## Task 11: Convert mobile to credentials

**Files:**
- Modify: `apps/mobile/data/api.ts:365-378`
- Modify: `apps/mobile/data/auth-store.ts`
- Modify: `apps/mobile/app/(auth)/login.tsx`
- Modify: `apps/mobile/lib/auth-error.ts`
- Delete: `apps/mobile/app/(auth)/verify.tsx`

**Interfaces:**
- Consumes: the two server endpoints
- Produces: `api.signupWithPassword(email, password, name?)`, `api.loginWithPassword(email, password)`, `useAuthStore().signupWithPassword`, `useAuthStore().loginWithPassword`

- [ ] **Step 1: Read the mobile pre-flight rules**

```bash
cat apps/mobile/CLAUDE.md
```

Follow its import limits, UI rules, and parity requirements for every step below.

- [ ] **Step 2: Replace the API methods**

In `apps/mobile/data/api.ts`, swap `sendCode` / `verifyCode` for:

```ts
  async signupWithPassword(
    email: string,
    password: string,
    name?: string,
  ): Promise<LoginResponse> {
    return this.fetch<LoginResponse>("/auth/password/signup", {
      method: "POST",
      body: JSON.stringify({ email, password, name }),
    });
  }

  async loginWithPassword(email: string, password: string): Promise<LoginResponse> {
    return this.fetch<LoginResponse>("/auth/password/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  }
```

- [ ] **Step 3: Replace the store actions**

In `apps/mobile/data/auth-store.ts`, change the interface members and bodies. The token-write rule is unchanged: the token is persisted only after a successful credential call.

```ts
  signupWithPassword: (email: string, password: string) => Promise<User>;
  loginWithPassword: (email: string, password: string) => Promise<User>;
```

```ts
  signupWithPassword: async (email, password) => {
    const { token, user } = await api.signupWithPassword(email, password);
    await setToken(token);
    api.setToken(token);
    set({ user });
    return user;
  },

  loginWithPassword: async (email, password) => {
    const { token, user } = await api.loginWithPassword(email, password);
    await setToken(token);
    api.setToken(token);
    set({ user });
    return user;
  },
```

Update the file's header comment: the line "Token written ONLY on successful verifyCode" becomes "Token written ONLY on a successful credential call".

- [ ] **Step 4: Rewrite the login screen**

`apps/mobile/app/(auth)/login.tsx` keeps its existing layout, haptics, and component imports, and gains a password field plus a signin/signup toggle. Replace the component body's state and submit handler with:

```tsx
  const loginWithPassword = useAuthStore((s) => s.loginWithPassword);
  const signupWithPassword = useAuthStore((s) => s.signupWithPassword);
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [allowSignup, setAllowSignup] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Mobile has no config store; read the deployment's signup policy directly.
  // A failed fetch leaves the toggle visible — the server still enforces the
  // gate, so the worst case is a clean 403 rather than an unwanted account.
  useEffect(() => {
    let cancelled = false;
    api
      .getConfig()
      .then((cfg) => {
        if (!cancelled) setAllowSignup(cfg.allow_signup);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const onSubmit = async () => {
    const trimmed = email.trim();
    if (!trimmed || !password) return;
    if (mode === "signup" && password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    void Haptics.selectionAsync();
    setSubmitting(true);
    setError(null);
    try {
      if (mode === "signup") {
        await signupWithPassword(trimmed, password);
      } else {
        await loginWithPassword(trimmed, password);
      }
      router.replace("/");
    } catch (err) {
      void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      setError(mapAuthError(err, "Couldn't sign you in. Try again."));
    } finally {
      setSubmitting(false);
    }
  };
```

Add a second `TextField` for the password with `secureTextEntry`, `autoCapitalize="none"`, and `autoComplete={mode === "signup" ? "new-password" : "password"}`, and render the mode toggle as a `Button` with `variant="ghost"` only when `allowSignup` is true. Update the header copy so it no longer promises a verification code.

`api.getConfig()` does **not** exist on the mobile client yet — add it alongside `getMe`, following that method's `fetchValidated` pattern:

```ts
  async getConfig(opts?: { signal?: AbortSignal }): Promise<AppConfigResponse> {
    return this.fetchValidated(
      "/api/config",
      AppConfigSchema,
      EMPTY_APP_CONFIG,
      { ...opts, endpoint: "getConfig" },
    );
  }
```

Import `AppConfigSchema`, `EMPTY_APP_CONFIG`, and `type AppConfigResponse` from `@multica/core/api` — schemas and types are pure, so this stays within the mobile import limits.

- [ ] **Step 5: Retarget the auth error copy**

`apps/mobile/lib/auth-error.ts` currently returns code-specific strings. Replace the first two branches:

```ts
  if (/invalid email or password/.test(msg)) {
    return "That email and password don't match.";
  }
  if (/already exists/.test(msg)) {
    return "An account with that email already exists. Try signing in.";
  }
  if (/at least 8 characters/.test(msg)) {
    return "Password must be at least 8 characters.";
  }
```

Keep the rate-limit and network branches as they are.

- [ ] **Step 6: Delete the verification screen**

```bash
git rm "apps/mobile/app/(auth)/verify.tsx"
```

- [ ] **Step 7: Typecheck**

```bash
pnpm --filter @multica/mobile typecheck
```

Expected: PASS, with no remaining reference to `sendCode`, `verifyCode`, or `/verify`.

- [ ] **Step 8: Commit**

```bash
git add apps/mobile
git commit -m "refactor(auth): convert mobile sign-in to email and password"
```

---

## Task 12: Simplify the E2E login fixture

**Files:**
- Modify: `e2e/fixtures.ts:56-115`
- Modify: `e2e/helpers.ts` (only if the `login` signature changes)

**Interfaces:**
- Consumes: `POST /auth/password/signup`, `POST /auth/password/login`
- Produces: `TestApiClient.login(email: string, name: string)` — signature unchanged, so no call site moves

- [ ] **Step 1: Replace the OTP dance with a credential call**

In `e2e/fixtures.ts`, replace the body of `login` with:

```ts
  async login(email: string, name: string) {
    // Signup is idempotent from the suite's point of view: a 409 means a
    // previous run already created this account, so fall through to login.
    // No DB round trip and no rate-limit cleanup is needed any more.
    const password = E2E_PASSWORD;

    const signupRes = await fetch(`${API_BASE}/auth/password/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, name }),
    });

    let data: { token: string; user?: { name?: string } };
    if (signupRes.ok) {
      data = await signupRes.json();
    } else if (signupRes.status === 409) {
      const loginRes = await fetch(`${API_BASE}/auth/password/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      if (!loginRes.ok) {
        throw new Error(`password login failed: ${loginRes.status}`);
      }
      data = await loginRes.json();
    } else {
      throw new Error(`password signup failed: ${signupRes.status}`);
    }

    this.token = data.token;
    this.email = email;

    if (name && data.user?.name !== name) {
      await this.authedFetch("/api/me", {
        method: "PATCH",
        body: JSON.stringify({ name }),
      });
    }

    return data;
  }
```

Add the shared constant near the other module constants:

```ts
/** Fixed across the suite so a re-run can log into an account a previous run created. */
const E2E_PASSWORD = "e2e-test-password";
```

- [ ] **Step 2: Drop the now-unused Postgres client**

If `pg` was imported only for the verification-code read and cleanup, remove the import and the `DATABASE_URL` usage from this method. Check first — other fixture methods may still need it:

```bash
grep -n "pg\.\|DATABASE_URL" e2e/fixtures.ts
```

- [ ] **Step 3: Run a fast E2E spec to confirm login works end to end**

```bash
pnpm exec playwright test e2e/auth.spec.ts
```

Expected: PASS.

- [ ] **Step 4: Run the full E2E suite**

```bash
pnpm exec playwright test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add e2e/fixtures.ts e2e/helpers.ts
git commit -m "test(e2e): authenticate fixtures with password credentials"
```

---

## Task 13: Remove the OTP and Google endpoints from the server

Every client is now on credentials, so the old paths can go.

**Files:**
- Modify: `server/internal/handler/auth.go`
- Modify: `server/cmd/server/router.go`
- Modify: `server/internal/handler/config.go:26,96`
- Modify: `server/internal/service/email.go:340`
- Delete: `server/pkg/db/queries/verification_code.sql`
- Modify: `server/internal/handler/handler_test.go`, `config_test.go`, `server/cmd/server/integration_test.go`

**Interfaces:**
- Produces: `AppConfig` loses `GoogleClientID`. `/auth/send-code`, `/auth/verify-code`, `/auth/google` no longer exist.

- [ ] **Step 1: Delete the handlers and their helpers**

From `server/internal/handler/auth.go` remove: `SendCode`, `VerifyCode`, `GoogleLogin`, `SendCodeRequest`, `VerifyCodeRequest`, `GoogleLoginRequest`, `googleTokenResponse`, `googleUserInfo`, `generateCode`, `isDevVerificationCode`, `isSixDigitCode`, and the `devVerificationCodeEnv` constant.

Also remove these two, which have **no caller left** once the above are gone:

- `findOrCreateUser` — its only two production callers were `VerifyCode` and `GoogleLogin`. Password signup creates the user itself, because signup must reject an existing account rather than log into it.
- `isProductionEnv` — called only by `isDevVerificationCode`.

Keep: `checkSignupAllowed` (called by `PasswordSignup`), `signupSourceFromRequest` and `issueJWT` (called by `completeLogin`), and `completeLogin` itself.

Confirm before deleting, since a later task may have added a caller:

```bash
grep -rn "findOrCreateUser\|isProductionEnv" server --include='*.go'
```

Remove any import left unused (`crypto/rand`, `encoding/binary`, `crypto/subtle`).

- [ ] **Step 2: Delete the routes**

In `server/cmd/server/router.go`, remove the three route lines and the now-unused `authVerifyRL` limiter:

```go
	r.With(authRL).Post("/auth/send-code", h.SendCode)
	r.With(authVerifyRL).Post("/auth/verify-code", h.VerifyCode)
	r.With(authRL).Post("/auth/google", h.GoogleLogin)
```

- [ ] **Step 3: Drop the Google config field**

In `server/internal/handler/config.go`, delete the `GoogleClientID` struct field and its assignment. In `.env.example`, delete `GOOGLE_CLIENT_ID` and the comment block above it.

Also fix the rate-limit summary comment at `.env.example:24-25`. It currently reads "Defaults are 5 for send-code/google and 20 for verify-code" — both of those limits disappear with the routes you are deleting in Step 2, and Task 5 added a 10/min login limit the summary never mentioned. Rewrite it to describe what actually remains: `RATE_LIMIT_AUTH` at 5/min for signup and `RATE_LIMIT_AUTH_LOGIN` at 10/min for login. Delete the `RATE_LIMIT_AUTH_VERIFY` entry too, since `authVerifyRL` goes with the OTP routes.

- [ ] **Step 4: Drop the verification-code plumbing**

```bash
git rm server/pkg/db/queries/verification_code.sql
make sqlc
```

This regenerates without `verification_code.sql.go`. Remove `SendVerificationCode` from `server/internal/service/email.go`, keeping `SendInvitationEmail`.

The `verification_code` **table stays** — no migration drops it. Dropping a table is irreversible and an empty table costs nothing.

- [ ] **Step 5: Delete the dead tests**

Remove OTP and Google cases from `server/internal/handler/handler_test.go`, the `GOOGLE_CLIENT_ID` assertions from `config_test.go`, and any send-code/verify-code cases from `server/cmd/server/integration_test.go`.

In `server/internal/handler/auth_signup_test.go`, delete `TestFindOrCreateUserGating` (lines 68–115) — it exercises the function deleted in Step 1, and its three cases are the mock-DB restatement of a policy `TestSignupGating` already covers directly against `checkSignupAllowed`. **Keep `TestSignupGating`**: it is the canonical test for the gate that password signup now depends on. If `mockDB` / `mockRow` become unused after this deletion, remove them too.

- [ ] **Step 6: Verify the server builds and tests green**

```bash
cd server && go build ./... && go vet ./... && make -C .. test
```

Expected: PASS, with no reference to `SendCode`, `VerifyCode`, or `GoogleLogin` remaining:

```bash
grep -rn "SendCode\|VerifyCode\|GoogleLogin\|GOOGLE_CLIENT_ID" server --include='*.go'
```

Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add server .env.example
git commit -m "refactor(auth): remove email OTP and Google sign-in from the server"
```

---

## Task 14: Remove the OTP and Google client code

**Files:**
- Modify: `packages/core/api/client.ts`, `packages/core/auth/store.ts`
- Modify: `packages/core/api/schemas.ts:584,789,806`
- Modify: `packages/core/config/index.ts:11,38,55,66,69`
- Modify: `packages/core/platform/auth-initializer.tsx:71`
- Delete: `apps/web/app/auth/callback/`
- Test: `packages/core/api/schema.test.ts`

**Interfaces:**
- Produces: `AppConfigResponse` loses `google_client_id`; `ConfigState` loses `googleClientId`; `AuthState` loses `sendCode`, `verifyCode`, `loginWithGoogle`; `ApiClient` loses `sendCode`, `verifyCode`, `googleLogin`.

- [ ] **Step 1: Write the malformed-response test first**

Per the API-compatibility rule, add to `packages/core/api/schema.test.ts`:

```ts
it("keeps a login response usable when the server omits optional user fields", () => {
  const parsed = parseWithFallback(
    LoginResponseSchema,
    { token: "t-1", user: { id: "u-1", email: "a@example.com", name: "A" } },
    EMPTY_LOGIN_RESPONSE,
  );
  expect(parsed.token).toBe("t-1");
  expect(parsed.user.email).toBe("a@example.com");
});

it("falls back rather than throwing when a login response is malformed", () => {
  const parsed = parseWithFallback(
    LoginResponseSchema,
    { token: 42, user: null },
    EMPTY_LOGIN_RESPONSE,
  );
  expect(parsed).toEqual(EMPTY_LOGIN_RESPONSE);
});

it("defaults allow_signup to true when the server omits it", () => {
  const cfg = parseWithFallback(AppConfigSchema, { cdn_domain: "" }, EMPTY_APP_CONFIG);
  expect(cfg.allow_signup).toBe(true);
});
```

`LoginResponseSchema` and `EMPTY_LOGIN_RESPONSE` do **not** exist in `packages/core/api/schemas.ts` yet — today the auth endpoints return unvalidated JSON. Add them; the login response is consumed by UI logic and must pass through a schema:

```ts
export const LoginResponseSchema = z.object({
  token: z.string(),
  user: UserSchema,
}).loose();

export const EMPTY_LOGIN_RESPONSE = { token: "", user: EMPTY_USER };
```

and route `signupWithPassword` / `loginWithPassword` through `parseWithFallback` in the client.

- [ ] **Step 2: Run it to verify it fails**

```bash
pnpm --filter @multica/core test api/schema.test.ts
```

Expected: FAIL — `LoginResponseSchema` is not exported.

- [ ] **Step 3: Add the schema and wire the client through it**

Implement the schema from Step 1, then make the two credential methods parse their response instead of returning raw JSON.

- [ ] **Step 4: Delete the OTP and Google client code**

- `packages/core/api/client.ts`: delete `sendCode`, `verifyCode`, `googleLogin`.
- `packages/core/auth/store.ts`: delete `sendCode`, `verifyCode`, `loginWithGoogle` from both the interface and the store body.
- `packages/core/api/schemas.ts`: delete `google_client_id` from `AppConfigResponse`, `AppConfigSchema`, and `EMPTY_APP_CONFIG`.
- `packages/core/config/index.ts`: delete `googleClientId` from the state interface, the `setAuthConfig` parameter, the defaults, and the setter body.
- `packages/core/platform/auth-initializer.tsx`: delete the `googleClientId: cfg.google_client_id` line.
- Fix the two test files that pass `googleClientId` in a config object: `packages/views/runtimes/components/connect-remote-dialog.test.tsx:44` and any others `grep` finds.

- [ ] **Step 5: Delete the Google OAuth callback route**

```bash
git rm -r apps/web/app/auth/callback
```

Then confirm nothing links to it:

```bash
grep -rn "auth/callback" apps packages e2e --include='*.ts' --include='*.tsx' | grep -v node_modules
```

Expected: only `multica://auth/callback` desktop deep-link references, which are a different scheme and stay.

- [ ] **Step 6: Verify**

```bash
pnpm typecheck && pnpm test
```

Expected: PASS.

```bash
grep -rn "sendCode\|verifyCode\|googleLogin\|loginWithGoogle\|googleClientId" packages apps --include='*.ts' --include='*.tsx' | grep -v node_modules
```

Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add packages apps
git commit -m "refactor(auth): remove OTP and Google client code"
```

---

## Task 15: Remove the landing site and redirect `/` to login

**Files:**
- Delete: `apps/web/app/(landing)/` (10 files), `apps/web/features/landing/` (39 files)
- Create: `apps/web/app/page.tsx`
- Modify: `apps/web/app/sitemap.ts:20`, `apps/web/app/robots.ts:10`, `apps/web/app/type-scale.test.ts:56`, `apps/web/app/custom.css:69-98`

**Interfaces:**
- Produces: `/` redirects to `/login`

- [ ] **Step 1: Write the failing route test**

Create `apps/web/app/page.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";

const mockRedirect = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({ redirect: mockRedirect }));

import RootPage from "./page";

describe("root route", () => {
  it("redirects to the login page", () => {
    RootPage();
    expect(mockRedirect).toHaveBeenCalledWith("/login");
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
pnpm --filter @multica/web test app/page.test.tsx
```

Expected: FAIL — `./page` cannot be resolved (the current `/` lives in the `(landing)` group).

- [ ] **Step 3: Delete the landing site**

```bash
git rm -r "apps/web/app/(landing)" apps/web/features/landing
```

- [ ] **Step 4: Add the root redirect**

`apps/web/app/page.tsx`:

```tsx
import { redirect } from "next/navigation";

// The marketing site is gone: the product entry point is the login page,
// which forwards already-authenticated users on to their workspace via
// resolvePostAuthDestination.
export default function RootPage() {
  redirect("/login");
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
pnpm --filter @multica/web test app/page.test.tsx
```

Expected: PASS.

- [ ] **Step 6: Clean up the references**

- `apps/web/app/sitemap.ts`: delete the `/changelog` entry. If `/` is the only survivor, keep just that.
- `apps/web/app/robots.ts`: change `allow: ["/", "/about", "/changelog"]` to `allow: ["/"]`.
- `apps/web/app/type-scale.test.ts:56`: delete the `marketingPaths` constant and whatever exemption consumes it — no marketing ramp remains to exempt.
- `apps/web/app/custom.css:69-98`: delete the `--font-serif` blocks that reference `--font-instrument-serif`. That variable was defined only by the deleted landing layout, so the stack now points at nothing. Check whether anything else uses `--font-serif` first:

```bash
grep -rn "font-serif" apps packages --include='*.css' --include='*.tsx' | grep -v node_modules
```

- [ ] **Step 7: Verify nothing references the landing feature**

```bash
grep -rn "features/landing\|(landing)" apps packages e2e | grep -v node_modules
```

Expected: no output.

- [ ] **Step 8: Build and run the full suite**

```bash
pnpm typecheck && pnpm lint && pnpm test && pnpm --filter @multica/web build
```

Expected: PASS. The build is the gate that catches a dangling import from a deleted landing component.

- [ ] **Step 9: Run the E2E suite**

```bash
pnpm exec playwright test
```

Expected: PASS. Watch `e2e/navigation.spec.ts`, which references landing paths — update any assertion that expects `/` to render marketing content.

- [ ] **Step 10: Commit**

```bash
git add apps/web
git commit -m "refactor(web): remove the landing site and redirect / to login"
```

---

## Final Verification

- [ ] **Run everything**

```bash
pnpm typecheck && pnpm lint && pnpm test && make test && pnpm exec playwright test
```

- [ ] **Confirm the removals are complete**

```bash
grep -rn "send-code\|verify-code\|auth/google\|GOOGLE_CLIENT_ID\|features/landing" server apps packages e2e --include='*.go' --include='*.ts' --include='*.tsx' --include='*.sql' | grep -v node_modules
```

Expected: no output.

- [ ] **Manual smoke test**

```bash
make dev
```

Then verify by hand:
1. `/` redirects to `/login`
2. Create an account with a new email and an 8+ character password → lands in a workspace
3. Log out, log back in with the same credentials
4. A wrong password shows `invalid email or password`
5. An unknown email shows the **same** message
6. `ALLOW_SIGNUP=false` hides the signup toggle and makes signup return 403
7. `multica auth login` opens the browser, accepts credentials, and returns a token to the CLI
