package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	validSecret = []byte("valid-secret")
)

func TestParseToken_Success(t *testing.T) {
	secret := validSecret

	cfg := Config{
		Secret: secret,
	}

	claims := &Claims{
		UserID:    42,
		Role:      "admin",
		IsRefresh: false,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "test",
		},
	}

	tokenString := createTestToken(secret, claims)

	result, err := ParseToken(tokenString, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.UserID != 42 {
		t.Fatalf("expected userID 42, got %d", result.UserID)
	}

	if result.Role != "admin" {
		t.Fatalf("expected role admin, got %s", result.Role)
	}
}

func TestParseToken_InvalidSignature(t *testing.T) {
	cfg := Config{
		Secret: validSecret,
	}

	claims := &Claims{
		UserID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	tokenString := createTestToken([]byte("wrong-secret"), claims)

	_, err := ParseToken(tokenString, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestParseToken_ExpiredToken(t *testing.T) {
	secret := validSecret

	cfg := Config{
		Secret: secret,
	}

	claims := &Claims{
		UserID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}

	tokenString := createTestToken(secret, claims)

	_, err := ParseToken(tokenString, cfg)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseToken_InvalidToken(t *testing.T) {
	cfg := Config{
		Secret: validSecret,
	}

	_, err := ParseToken("not-a-jwt", cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func createTestToken(secret []byte, claims *Claims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		panic(err)
	}
	return signed
}
