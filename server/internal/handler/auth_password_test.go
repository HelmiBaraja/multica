package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	// uniqueEmail embeds t.Name(), which contains uppercase letters, but the
	// handler lowercases the email before persisting/returning it (email
	// identity is case-insensitive). Compare against the normalized form.
	if resp.User.Email != strings.ToLower(email) {
		t.Fatalf("email: want %q, got %q", strings.ToLower(email), resp.User.Email)
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

func timeNowUnixNano() int64 { return time.Now().UnixNano() }
