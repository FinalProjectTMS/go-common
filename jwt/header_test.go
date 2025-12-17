package jwt

import (
	"errors"
	"testing"
)

func TestExtractBearerToken_Success(t *testing.T) {
	header := "Bearer abc.def.ghi"

	token, err := ExtractBearerToken(header)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "abc.def.ghi" {
		t.Fatalf("expected token, got %s", token)
	}
}

func TestExtractBearerToken_EmptyHeader(t *testing.T) {
	_, err := ExtractBearerToken("")

	if !errors.Is(err, ErrEmptyAuthHeader) {
		t.Fatalf("expected ErrEmptyAuthHeader, got %v", err)
	}
}

func TestExtractBearerToken_InvalidHeader(t *testing.T) {
	_, err := ExtractBearerToken("InvalidHeader")

	if !errors.Is(err, ErrInvalidAuthHeader) {
		t.Fatalf("expected ErrInvalidAuthHeader, got %v", err)
	}
}

func TestExtractBearerToken_EmptyToken(t *testing.T) {
	_, err := ExtractBearerToken("Bearer ")

	if !errors.Is(err, ErrEmptyToken) {
		t.Fatalf("expected ErrEmptyToken, got %v", err)
	}
}
