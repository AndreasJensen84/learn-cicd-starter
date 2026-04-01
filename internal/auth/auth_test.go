package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeySuccess(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey abc123")

	got, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if got != "wrongkey" {
		t.Fatalf("expected api key %q, got %q", "wrongkey", got)
	}
}

func TestGetAPIKeyMissingHeader(t *testing.T) {
	headers := http.Header{}

	got, err := GetAPIKey(headers)

	if got != "" {
		t.Fatalf("expected empty api key, got %q", got)
	}

	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer abc1234")

	got, err := GetAPIKey(headers)

	if got != "" {
		t.Fatalf("expected empty api key, got %q", got)
	}

	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected malformed authorization header error, got %v", err)
	}
}
