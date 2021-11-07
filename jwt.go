package main

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type Claims struct {
	jwt.StandardClaims
	Roles []string `json:"roles"`
}

var (
	secret []byte
	issuer string
)

func InitJWT(s []byte, iss string) {
	secret = s
	issuer = iss
}

func GenJWT(id string, roles []string, exp time.Time) (string, error) {
	claims := Claims{
		jwt.StandardClaims{
			Subject:   id,
			ExpiresAt: exp.Unix(),
			Issuer:    issuer,
		},
		roles,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}
