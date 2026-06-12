package auth

import (
	"testing"
	"time"
)

func newTestService() *Service {
	return NewService("admin", "s3cret", "test-secret", time.Hour)
}

func TestAuthenticate(t *testing.T) {
	svc := newTestService()
	if !svc.Authenticate("admin", "s3cret") {
		t.Fatal("expected valid credentials to authenticate")
	}
	if svc.Authenticate("admin", "wrong") {
		t.Fatal("expected wrong password to fail")
	}
	if svc.Authenticate("root", "s3cret") {
		t.Fatal("expected wrong username to fail")
	}
}

func TestEnabled(t *testing.T) {
	if NewService("admin", "", "secret", time.Hour).Enabled() {
		t.Fatal("expected service to be disabled without a password")
	}
	if !newTestService().Enabled() {
		t.Fatal("expected service to be enabled with credentials")
	}
}

func TestIssueAndValidate(t *testing.T) {
	svc := newTestService()
	now := time.Unix(1_700_000_000, 0)

	token, exp, err := svc.Issue(now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !exp.After(now) {
		t.Fatal("expected expiry in the future")
	}

	sub, err := svc.Validate(token, now)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if sub != "admin" {
		t.Fatalf("expected subject admin, got %q", sub)
	}
}

func TestValidateExpired(t *testing.T) {
	svc := newTestService()
	now := time.Unix(1_700_000_000, 0)
	token, _, _ := svc.Issue(now)

	if _, err := svc.Validate(token, now.Add(2*time.Hour)); err != ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}

func TestValidateTampered(t *testing.T) {
	svc := newTestService()
	now := time.Unix(1_700_000_000, 0)
	token, _, _ := svc.Issue(now)

	if _, err := svc.Validate(token+"x", now); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for tampered signature, got %v", err)
	}
	if _, err := svc.Validate("garbage", now); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for malformed token, got %v", err)
	}

	// A token signed with a different secret must not validate.
	other := NewService("admin", "s3cret", "other-secret", time.Hour)
	if _, err := svc.Validate(mustIssue(t, other, now), now); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for foreign secret, got %v", err)
	}
}

func mustIssue(t *testing.T, s *Service, now time.Time) string {
	t.Helper()
	token, _, err := s.Issue(now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return token
}
