package jwt

import (
	"strings"
)

func ExtractBearerToken(header string) (string, error) {
	if header == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", ErrInvalidAuthHeader
	}

	if parts[1] == "" {
		return "", ErrEmptyToken
	}

	return parts[1], nil
}
