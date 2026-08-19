package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
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

func TestPasswordSignupCreatesAccount(t *testing.T) {
	email := uniqueEmail(t)
	cleanupUser(t, email)
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
	// uniqueEmail embeds t.Name(), which contains uppercase letters, but the
	// handler lowercases the email before persisting/returning it (email
	// identity is case-insensitive). Compare against the normalized form.
	if resp.User.Email != strings.ToLower(email) {
		t.Fatalf("email: want %q, got %q", strings.ToLower(email), resp.User.Email)
	}
}

func TestPasswordSignupRejectsShortPassword(t *testing.T) {
	email := uniqueEmail(t)
	cleanupUser(t, email)
	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
		"email":    email,
		"password": "short7!",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestPasswordSignupRejectsDuplicateAccount(t *testing.T) {
	email := uniqueEmail(t)
	cleanupUser(t, email)
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

	email := uniqueEmail(t)
	cleanupUser(t, email)
	rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
		"email":    email,
		"password": "correct-horse",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// On a closed instance, signup must not leak whether an email is already
// registered: an existing account and an unknown email both have to return
// the same status. Before this fix, PasswordSignup checked GetUserByEmail
// before checkSignupAllowed, so an existing account got 409 while an unknown
// one got 403 — exactly the account-existence signal PasswordLogin's
// identical-401 design is built to hide.
func TestPasswordSignupGateHidesAccountExistence(t *testing.T) {
	// Create the account while signup is still open.
	existing := signupFixture(t, "correct-horse")

	prev := testHandler.cfg.AllowSignup
	testHandler.cfg.AllowSignup = false
	t.Cleanup(func() { testHandler.cfg.AllowSignup = prev })

	unknown := uniqueEmail(t)

	cases := []struct {
		name  string
		email string
	}{
		{"existing_account", existing},
		{"unknown_email", unknown},
	}

	var statuses []int
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJSON(t, testHandler.PasswordSignup, "/auth/password/signup", map[string]string{
				"email":    tc.email,
				"password": "correct-horse",
			})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status: want 403, got %d (%s)", rec.Code, rec.Body.String())
			}
			statuses = append(statuses, rec.Code)
		})
	}

	for i := 1; i < len(statuses); i++ {
		if statuses[i] != statuses[0] {
			t.Fatalf("signup-gate responses differ and leak account existence: %v", statuses)
		}
	}
}

func timeNowUnixNano() int64 { return time.Now().UnixNano() }

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
