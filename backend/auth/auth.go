// Package auth implements single-admin authentication for the panel.
//
// Credentials live in the environment (AUTH_USERNAME / AUTH_PASSWORD) so they
// can be set on first setup without a user store. A successful login returns a
// stateless, HMAC-SHA256 signed token (JWT-like: payload.signature) that the
// Auth middleware verifies on every protected request. No external JWT
// dependency is required — the standard library covers signing and verifying.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"
)

// Errors returned by Validate.
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

// Service authenticates the admin user and issues/verifies session tokens.
type Service struct {
	username string
	password string
	secret   []byte
	ttl      time.Duration
}

// claims is the signed token payload.
type claims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// NewService builds a Service from the configured credentials. An empty secret
// triggers an ephemeral random key (sessions then reset on restart); set
// AUTH_TOKEN_SECRET to keep tokens valid across restarts. A non-positive ttl
// falls back to 24h.
func NewService(username, password, secret string, ttl time.Duration) *Service {
	key := []byte(secret)
	if strings.TrimSpace(secret) == "" {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			// Refuse to run with a predictable signing key.
			panic("auth: failed to generate token secret: " + err.Error())
		}
		log.Println("AUTH_TOKEN_SECRET is empty; generated an ephemeral token secret (sessions reset on restart). Set AUTH_TOKEN_SECRET to persist sessions.")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if strings.TrimSpace(password) == "" {
		log.Println("AUTH_PASSWORD is empty; login is disabled and the API is locked. Set AUTH_USERNAME and AUTH_PASSWORD to enable access.")
	}
	return &Service{
		username: username,
		password: password,
		secret:   key,
		ttl:      ttl,
	}
}

// Enabled reports whether credentials are configured. When false, login fails
// and protected routes are locked.
func (s *Service) Enabled() bool {
	return s.username != "" && s.password != ""
}

// TTL is the lifetime of issued tokens.
func (s *Service) TTL() time.Duration { return s.ttl }

// Authenticate compares the supplied credentials in constant time.
func (s *Service) Authenticate(username, password string) bool {
	if !s.Enabled() {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(s.password)) == 1
	return userOK && passOK
}

// Issue returns a signed token and its expiry, computed from now.
func (s *Service) Issue(now time.Time) (token string, expiresAt time.Time, err error) {
	expiresAt = now.Add(s.ttl)
	body, err := json.Marshal(claims{Sub: s.username, Iat: now.Unix(), Exp: expiresAt.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + s.sign(payload), expiresAt, nil
}

// Validate verifies the token signature and expiry, returning the subject.
func (s *Service) Validate(token string, now time.Time) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidToken
	}
	expected := s.sign(parts[0])
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) != 1 {
		return "", ErrInvalidToken
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidToken
	}
	var c claims
	if err := json.Unmarshal(body, &c); err != nil {
		return "", ErrInvalidToken
	}
	if now.Unix() >= c.Exp {
		return "", ErrExpiredToken
	}
	return c.Sub, nil
}

func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
