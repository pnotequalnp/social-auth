package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
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
)

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	type resType struct {
		Email string
		Password string
	}

	var res resType
	err := json.Unmarshal([]byte(req.Body), &res)
	if err != nil {
		return err400, nil
	}

	id, encoded, err := FetchHash(ctx, res.Email)
	if err != nil {
		switch err {
		case ErrNotFound:
			return err401, nil
		default:
			log.Println("ERROR: User fetch failed", err)
			return err500, nil
		}
	}

	// TODO: ensure memory is not more than available
	valid, err := ValidateEncodedHash([]byte(res.Password), encoded)
	if err != nil {
		log.Println("ERROR: Hash validation failed", err)
		return err500, nil
	}
	if !valid {
		return err401, nil
	}

	// TODO: fetch roles instead of giving admin all the time
	token, err := GenJWT(id, []string{"admin"})
	if err != nil {
		log.Println("ERROR: JWT creation failed", err)
		return err500, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       token,
	}, nil
}

func main() {
	token, err := InitJWT([]byte(os.Getenv("JWT_SECRET")), os.Getenv("JWT_ISSUER"))
	if err != nil {
		log.Fatal(err)
	}

	InitGraphQL(os.Getenv("HASURA_ENDPOINT"), token)

	log.Println("INFO: Successfully initialized")

	lambda.Start(handler)
}
