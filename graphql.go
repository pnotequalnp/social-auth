package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/machinebox/graphql"
)

var (
	ErrNotFound = errors.New("Email not in database")
	client      *graphql.Client
	getHash     *graphql.Request = graphql.NewRequest(`
		query ($email: String!) {
			user(where: {email: {_eq: $email}}) {
				id
				password
			}
		}
	`)
)

type getResponse struct {
	User []struct {
		Id       string
		Password string
	}
}

func InitGraphQL(url string) {
	client = graphql.NewClient(url)
}

func FetchHash(ctx context.Context, email string, token string) (string, string, error) {
	getHash.Var("email", email)
	getHash.Header.Set("Cookie", fmt.Sprintf("auth=%s", token))

	var res getResponse
	if err := client.Run(ctx, getHash, &res); err != nil {
		return "", "", err
	}
	if len(res.User) != 1 {
		return "", "", ErrNotFound
	}

	return res.User[0].Id, res.User[0].Password, nil
}
