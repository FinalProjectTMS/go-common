package jwt

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	jwt.RegisteredClaims
	UserID    int    `json:"user_id"`
	Role      string `json:"role"`
	IsRefresh bool   `json:"is_refresh"`
}
