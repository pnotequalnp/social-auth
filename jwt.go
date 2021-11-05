package main

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type HasuraClaims struct {
	DefaultRole  string   `json:"x-hasura-default-role"`
	AllowedRoles []string `json:"x-hasura-allowed-roles"`
	Id           string   `json:"x-hasura-user-id"`
}

type Claims struct {
	jwt.StandardClaims
	Roles []string `json:"roles"`
}

var (
	secret []byte
	issuer string
)

func InitJWT(s []byte, iss string) (string, error) {
	secret = s
	issuer = iss

	return GenJWTExp("00000000-0000-0000-0000-000000000000", []string{"auth"}, 6e14) // 1 week
}

func GenJWT(id string, roles []string) (string, error) {
	return GenJWTExp(id, roles, 9e11) // 15 minutes
}

func GenJWTExp(id string, roles []string, exp time.Duration) (string, error) {
	claims := Claims{
		jwt.StandardClaims{
			Subject:   id,
			ExpiresAt: time.Now().Add(exp).Unix(),
			Issuer:    issuer,
		},
		roles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}
