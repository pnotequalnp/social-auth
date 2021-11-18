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
				uuid
				password
				admin
				slug
				display
			}
		}
	`)
)

type User struct {
	Uuid     string
	Password string
	Admin    bool
	Slug     string
	Display  string
}

type getResponse struct {
	User []User
}

func InitGraphQL(url string) {
	client = graphql.NewClient(url)
}

func FetchHash(ctx context.Context, email string, token string) (User, error) {
	getHash.Var("email", email)
	getHash.Header.Set("Cookie", fmt.Sprintf("auth=%s", token))

	var res getResponse
	if err := client.Run(ctx, getHash, &res); err != nil {
		return User{}, err
	}
	if len(res.User) != 1 {
		return User{}, ErrNotFound
	}

	return res.User[0], nil
}
