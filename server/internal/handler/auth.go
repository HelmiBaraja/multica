package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/analytics"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/logger"
	obsmetrics "github.com/multica-ai/multica/server/internal/metrics"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"golang.org/x/crypto/bcrypt"
)

// SignupError represents signup restriction errors
type SignupError struct {
	Message string
}

func (e SignupError) Error() string {
	return e.Message
}

var ErrSignupProhibited = SignupError{Message: "user registration is disabled on this self-hosted instance"}
var ErrEmailNotAllowed = SignupError{Message: "email address or domain not allowed on this instance"}

// supportedLanguages mirrors `SUPPORTED_LOCALES` in packages/core/i18n/types.ts.
// Keep both lists in sync when adding a locale — the user-controlled `language`
// field round-trips through GetMe back into i18n.changeLanguage(), so without
// validation an arbitrary string would persist and echo to every device.
var supportedLanguages = map[string]struct{}{
	"en":      {},
	"zh-Hans": {},
	"ko":      {},
	"ja":      {},
}

type UserResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
	AvatarURL *string `json:"avatar_url"`
	Language  *string `json:"language"`
	// Pinned IANA tz; nil = no preference (use browser-detected tz).
	Timezone                *string         `json:"timezone"`
	OnboardedAt             *string         `json:"onboarded_at"`
	OnboardingQuestionnaire json.RawMessage `json:"onboarding_questionnaire"`
	StarterContentState     *string         `json:"starter_content_state"`
	ProfileDescription      string          `json:"profile_description"`
	CreatedAt               string          `json:"created_at"`
	UpdatedAt               string          `json:"updated_at"`
}

// MaxProfileDescriptionLen caps the user-supplied profile_description body.
// Picked at 2000 chars per MUL-2406: enough room for role / stack / a few
// preferences, short enough that injecting it into every agent brief
// doesn't move the needle on prompt cost.
const MaxProfileDescriptionLen = 2000

func (h *Handler) userToResponse(u db.User) UserResponse {
	// JSONB column is []byte with DEFAULT '{}', so it's never nil at the DB
	// level. Defensive coalesce just in case a future ALTER makes the column
	// nullable and some row comes back with no default applied.
	q := u.OnboardingQuestionnaire
	if len(q) == 0 {
		q = []byte("{}")
	}
	return UserResponse{
		ID:                      uuidToString(u.ID),
		Name:                    u.Name,
		Email:                   u.Email,
		AvatarURL:               h.resolveAvatarURLPtr(textToPtr(u.AvatarUrl)),
		Language:                textToPtr(u.Language),
		Timezone:                textToPtr(u.Timezone),
		OnboardedAt:             timestampToPtr(u.OnboardedAt),
		OnboardingQuestionnaire: json.RawMessage(q),
		StarterContentState:     textToPtr(u.StarterContentState),
		ProfileDescription:      u.ProfileDescription,
		CreatedAt:               timestampToString(u.CreatedAt),
		UpdatedAt:               timestampToString(u.UpdatedAt),
	}
}

type LoginResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}

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

func (h *Handler) issueJWT(user db.User) (string, error) {
	if auth.IsTemporarilyDisabledUser(uuidToString(user.ID), user.Email) {
		return "", auth.ErrTemporarilyDisabledUser
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   uuidToString(user.ID),
		"email": user.Email,
		"name":  user.Name,
		"exp":   time.Now().Add(auth.AuthTokenTTL()).Unix(),
		"iat":   time.Now().Unix(),
	})
	return token.SignedString(auth.JWTSecret())
}

// completeLogin writes the standard successful-authentication response: a
// JWT, the HttpOnly auth cookie plus its CSRF companion, CloudFront signed
// cookies when the CDN serves private content, and the LoginResponse body.
// Every authentication entry point ends here — the paired cookie calls are
// easy to omit in a hand-rolled copy, and omitting them yields a token the
// browser cannot actually use.
//
// Signup analytics deliberately stay at the call site: it stamps its own
// auth_method rather than this shared helper doing it generically.
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

// signupSourceFromRequest reads the attribution cookie the web frontend
// sets on the first pageview (UTM + referrer bundle). The frontend writes
// a JSON string URL-encoded into the cookie value — Go does not
// auto-decode Cookie.Value, so we have to unescape here before the string
// lands in PostHog. Missing cookie / decode failures collapse to the
// empty string; that simply omits signup_source from the event rather
// than sending percent-encoded garbage. Never fall back to r.Referer() —
// the frontend has already sanitised attribution and a raw referer can
// leak OAuth code/state from the callback URL.
//
// The cap is the server-side defence against a client that manages to set
// an oversize cookie; it matches SIGNUP_SOURCE_MAX_LEN on the frontend.
const signupSourceMaxLen = 512

func signupSourceFromRequest(r *http.Request) string {
	c, err := r.Cookie("multica_signup_source")
	if err != nil || c == nil {
		return ""
	}
	decoded, err := url.QueryUnescape(c.Value)
	if err != nil {
		return ""
	}
	if len(decoded) > signupSourceMaxLen {
		return ""
	}
	return decoded
}

func (h *Handler) checkSignupAllowed(email string, isNewUser bool) error {
	if !isNewUser {
		return nil // existing users always allowed to log in
	}

	email = strings.ToLower(email)
	domain := ""
	if at := strings.Index(email, "@"); at > 0 {
		domain = email[at+1:]
	}

	// 1. explicit email whitelist always wins
	if len(h.cfg.AllowedEmails) > 0 && contains(h.cfg.AllowedEmails, email) {
		return nil
	}

	// 2. domain whitelist always wins
	if len(h.cfg.AllowedEmailDomains) > 0 && contains(h.cfg.AllowedEmailDomains, domain) {
		return nil
	}

	// 3. general signup flag
	if !h.cfg.AllowSignup {
		return ErrSignupProhibited
	}

	// 4. if allowlists are set but didn't match, block
	if len(h.cfg.AllowedEmailDomains) > 0 || len(h.cfg.AllowedEmails) > 0 {
		return ErrSignupProhibited
	}

	return nil
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

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

type PasswordLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// dummyPasswordHash is a valid bcrypt hash with no corresponding known
// password, generated once at first use and cached for the life of the
// process. It exists so the "unknown email" path can spend the same bcrypt
// round as the "wrong password" path, keeping the two indistinguishable by
// timing.
//
// Deliberately generated rather than a hardcoded literal: a hand-written
// literal is easy to get subtly wrong-length (a well-formed bcrypt hash is
// exactly 60 bytes), and bcrypt.CompareHashAndPassword returns early on a
// malformed hash — which would silently restore the timing gap this
// variable exists to erase.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing-defense"), bcrypt.DefaultCost)
	if err != nil {
		// GenerateFromPassword only fails on a bad cost constant, which
		// bcrypt.DefaultCost never is. Panicking here surfaces a broken
		// build immediately rather than quietly reopening the timing oracle.
		panic(fmt.Sprintf("dummyPasswordHash: bcrypt.GenerateFromPassword failed: %v", err))
	}
	return hash
})

// PasswordLogin authenticates an email + password pair. Every failure mode
// returns errInvalidCredentials with the same 401 status — see the
// constant's comment for why the cases are not distinguished.
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

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	user, err := h.Queries.GetUser(r.Context(), parseUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, h.userToResponse(user))
}

type UpdateMeRequest struct {
	Name               *string `json:"name"`
	AvatarURL          *string `json:"avatar_url"`
	Language           *string `json:"language"`
	ProfileDescription *string `json:"profile_description"`
	// IANA tz to pin; "" clears back to NULL; nil leaves untouched.
	Timezone *string `json:"timezone"`
}

// IssueCliToken returns a fresh JWT for the authenticated user.
// This allows cookie-authenticated browser sessions to obtain a bearer token
// that can be handed off to the CLI via the cli_callback redirect.
func (h *Handler) IssueCliToken(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	user, err := h.Queries.GetUser(r.Context(), parseUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	tokenString, err := h.issueJWT(user)
	if err != nil {
		if errors.Is(err, auth.ErrTemporarilyDisabledUser) {
			writeError(w, http.StatusForbidden, auth.TemporarilyDisabledUserError)
			return
		}
		slog.Warn("cli-token: failed to issue JWT", append(logger.RequestAttrs(r), "error", err, "user_id", userID)...)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": tokenString})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearAuthCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	var req UpdateMeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	currentUser, err := h.Queries.GetUser(r.Context(), parseUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	name := currentUser.Name
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
	}

	params := db.UpdateUserParams{
		ID:   currentUser.ID,
		Name: name,
	}
	if req.AvatarURL != nil {
		avatarURL, ok := h.acceptAvatarURL(w, r, *req.AvatarURL, currentUser.AvatarUrl.String)
		if !ok {
			return
		}
		params.AvatarUrl = pgtype.Text{String: avatarURL, Valid: true}
	}
	if req.Language != nil {
		lang := strings.TrimSpace(*req.Language)
		if _, ok := supportedLanguages[lang]; !ok {
			writeError(w, http.StatusBadRequest, "unsupported language")
			return
		}
		params.Language = pgtype.Text{String: lang, Valid: true}
	}
	if req.ProfileDescription != nil {
		// Count runes, not bytes: 2000 chars of Chinese must not be rejected
		// as ~6000 bytes. utf8.RuneCountInString handles invalid UTF-8 by
		// counting each bad byte as one rune, which still bounds the column.
		desc := strings.TrimSpace(*req.ProfileDescription)
		if utf8.RuneCountInString(desc) > MaxProfileDescriptionLen {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("profile_description exceeds %d characters", MaxProfileDescriptionLen))
			return
		}
		params.ProfileDescription = pgtype.Text{String: desc, Valid: true}
	}

	if req.Timezone != nil {
		// Valid=false → column untouched; Valid=true + "" → clear to
		// NULL; Valid=true + IANA → set. Three-way semantics enforced
		// in the UpdateUser SQL CASE.
		tz := strings.TrimSpace(*req.Timezone)
		if tz != "" {
			if loc, err := time.LoadLocation(tz); err != nil || loc == nil {
				writeError(w, http.StatusBadRequest, "invalid timezone")
				return
			}
		}
		params.Timezone = pgtype.Text{String: tz, Valid: true}
	}

	updatedUser, err := h.Queries.UpdateUser(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	writeJSON(w, http.StatusOK, h.userToResponse(updatedUser))
}
