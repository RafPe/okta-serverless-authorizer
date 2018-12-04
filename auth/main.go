package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

type jwtData struct {
	accessToken string
	jwt         jwt.JWT
	iss         string
	sub         string
	scopes      []string
}

var (
	tokenData *jwtData
)

//generatePolicy
//
func generatePolicy(tkn *jwtData, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	// Use token subject
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: tkn.sub}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"issuer": tkn.iss,
		// "numberKey":  123,
		// "booleanKey": true,
	}
	log.Println(authResponse)
	return authResponse
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Println(event)

	log.Println("Create tokenData")
	tokenData := &jwtData{
		accessToken: extractJWT(event.AuthorizationToken),
	}

	log.Println("ParseJWT")
	err := tokenData.ParseJWT()
	if err != nil {
		log.Println("Error while parsing JWT")
		log.Println(err)
		// Return a 401 Unauthorized response
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Token is invalid")
	}

	// SCENARIO 1: Extract programatically from JWK
	//
	// rsaPublic, _ := pubKey.(rsa.PublicKey)
	// savePublicPEMKey(rsaPublic)

	// SCENARIO 2: Extract RSAPublicKeyFromPEM from the file
	//
	// bytes, _ := ioutil.ReadFile("./okta-jwk.pub")

	// SCENARIO 3: Extract RSAPublicKeyFromPEM from env var
	//
	certFromEnv := os.Getenv("OKTA_PUBLIC_KEY")
	log.Println(certFromEnv)

	bytes := []byte(certFromEnv)
	log.Println("ParseRSAPublicKey from PEM")

	rsaPublic, err := crypto.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Error: RSAPublicKeyFromPEM")
	}

	log.Println("Validate token")
	if err := tokenData.jwt.Validate(rsaPublic, crypto.SigningMethodRS256); err == nil {
		// For future you could also do claims and perform allow there
		log.Println("Validate success")

		log.Println("ExtractTokenInfo")
		tokenData.ExtractTokenInfo()
		log.Println("ExtractScopes")
		tokenData.ExtractScopes()

		return generatePolicy(tokenData, "Allow", event.MethodArn), nil
	}

	log.Println("Validate failure")

	// Return a 401 Unauthorized response
	return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")

}

func main() {
	lambda.Start(handleRequest)
}

//ParseJWT
//
func (tkn *jwtData) ParseJWT() error {
	var err error

	tkn.jwt, err = jws.ParseJWT([]byte(tkn.accessToken))
	if err != nil {
		return err
	}

	return nil
}

//ExtractTokenInfo
//
func (tkn *jwtData) ExtractTokenInfo() {
	log.Println("executing > ExtractTokenInfo")

	sub, _ := tkn.jwt.Claims().Subject()
	log.Println(sub)
	iss, _ := tkn.jwt.Claims().Issuer()
	log.Println(iss)

	tkn.sub = sub
	tkn.iss = iss

	log.Println("finished > ExtractTokenInfo")
}

//ExtractScopes
//
func (tkn *jwtData) ExtractScopes() {
	scopes := tkn.jwt.Claims().Get("scp").([]interface{})

	for _, v := range scopes {
		scope, ok := v.(string)
		if !ok {
			continue
		}
		tkn.scopes = append(tkn.scopes, scope)
	}

}

//extractJWT: Extracts from Authorization header
//
func extractJWT(authHeader string) string {
	log.Println("extractJWT")
	splitToken := strings.Split(authHeader, "Bearer")
	if len(splitToken) > 0 {
		jwt := strings.TrimSpace(splitToken[1])
		return jwt
	}

	return ""
}
