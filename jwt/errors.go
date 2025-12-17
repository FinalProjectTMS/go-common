package jwt

import "errors"

var (
	ErrEmptyAuthHeader   = errors.New("authorization header is empty")
	ErrInvalidAuthHeader = errors.New("invalid authorization header, correct format: Bearer <token>")
	ErrEmptyToken        = errors.New("token is empty")
	ErrInvalidToken      = errors.New("token is invalid")
)
