package auth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(passwd string) (string, error) {

	cost := bcrypt.MinCost

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwd), cost)

	return string(hashedPassword), err
}

func CheckPasswordHash(passwd, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(passwd))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	secret, err := base64.StdEncoding.DecodeString(tokenSecret)
	if err != nil {
		return "", err
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return ss, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {

	secret, err := base64.StdEncoding.DecodeString(tokenSecret)
	if err != nil {
		return uuid.UUID{}, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.UUID{}, errors.New("Unknown claims type")
	}

	parsed_uuid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.UUID{}, err
	}

	return parsed_uuid, nil

}

func GetBearerToken(headers http.Header) (string, error) {

	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization header not found")
	}

	authValue := strings.Split(authHeader, " ")
	if len(authValue) < 2 || authValue[0] != "Bearer" {
		return "", errors.New("Invalid Bearer token")
	}

	token := authValue[1]

	return token, nil
}
