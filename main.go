package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
)

var (
	err400 = events.APIGatewayProxyResponse{
		StatusCode: http.StatusBadRequest,
		Body:       http.StatusText(http.StatusBadRequest),
	}

	err401 = events.APIGatewayProxyResponse{
		StatusCode: http.StatusUnauthorized,
		Body:       http.StatusText(http.StatusUnauthorized),
	}

	err500 = events.APIGatewayProxyResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       http.StatusText(http.StatusInternalServerError),
	}

	token    string
	tokenExp time.Time
	exp      time.Duration
	domain   string
)

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	type requestBody struct {
		Email    string
		Password string
	}

	var req requestBody
	err := json.Unmarshal([]byte(request.Body), &req)
	if err != nil {
		return err400, nil
	}

	ensureToken()
	user, err := FetchHash(ctx, req.Email, token)
	if err != nil {
		switch err {
		case ErrNotFound:
			return err401, nil
		default:
			log.Println("ERROR: User fetch failed", err)
			return err500, nil
		}
	}

	hash, params, err := DecodeHash(user.Password)
	if err != nil {
		log.Println("ERROR: Hash validation failed", err)
		return err500, nil
	}

	if uint32(lambdacontext.MemoryLimitInMB) < 750 * params.Memory {
		log.Println("ERROR: Not enough memory to compute hash")
		return err500, nil
	}

	valid, err := ValidateHash(params, []byte(req.Password), &hash)
	if err != nil {
		log.Println("ERROR: Hash validation failed", err)
		return err500, nil
	}
	if !valid {
		return err401, nil
	}

	userExp := time.Now().Add(exp)

	roles := []string{"user"}
	if user.Admin {
		roles = append([]string{"admin"}, roles...)
	}

	userToken, err := GenJWT(user.Uuid, roles, userExp)
	if err != nil {
		log.Println("ERROR: JWT creation failed", err)
		return err500, nil
	}

	type response struct {
		Id      string   `json:"id"`
		Roles   []string `json:"roles"`
		Slug    string   `json:"slug"`
		Display string   `json:"display"`
	}

	res, _ := json.Marshal(response{
		user.Uuid,
		roles,
		user.Slug,
		user.Display,
	})

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       string(res),
		Headers: map[string]string{
			"Set-Cookie": fmt.Sprintf(
				"auth=%s; Domain=%s; Secure; HttpOnly; SameSite=Lax; Expires=%s GMT",
				userToken, domain, userExp.Format("Mon, 02 Jan 2006 15:04:05")),
		},
	}, nil
}

func main() {
	d, err := time.ParseDuration(os.Getenv("JWT_DURATION"))
	if err != nil {
		log.Fatal("FATAL: Could not parse JWT duration", err)
	}
	exp = d

	domain = os.Getenv("AUTH_DOMAIN")

	InitJWT([]byte(os.Getenv("JWT_SECRET")), os.Getenv("JWT_ISSUER"))

	InitGraphQL(os.Getenv("GRAPHQL_ENDPOINT"))

	log.Println("INFO: Successfully initialized")

	lambda.Start(handler)
}

func ensureToken() string {
	if tokenExp.Before(time.Now().Add(6e10)) {
		tokenExp = time.Now().Add(3e11)
		tok, err := GenJWT("00000000-0000-0000-0000-000000000000", []string{"auth"}, tokenExp)
		if err != nil {
			log.Fatal("FATAL: Auth token creation failed", err)
		}
		token = tok
	}

	return token
}
