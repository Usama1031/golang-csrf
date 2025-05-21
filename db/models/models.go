package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/usama1031/golang-csrf/randomstrings"
)

type User struct {
	Username, PasswordHash, Role string
}

type TokenClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateRandomStrings(32)
}
