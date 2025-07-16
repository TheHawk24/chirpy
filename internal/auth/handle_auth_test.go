package auth

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCheckPasswordHash(t *testing.T) {

	hash, _ := HashPassword("yellow")

	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"Hashed Password", "yellow", hash},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := CheckPasswordHash(test.input, test.want)
			if err != nil {
				t.Errorf("Failed test, got: %s, want: %s", err, test.want)
			}
		})
	}

}

func TestMakeJWT(t *testing.T) {

	userID := uuid.New()
	secret := base64.StdEncoding.EncodeToString([]byte("YELLOW"))
	time_duration := time.Minute * 2

	token, err := MakeJWT(userID, secret, time_duration)
	if err != nil {
		t.Errorf("Failed test, got: %s", err)
	}

	jwtUUID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Errorf("Failed test, got: %s", err)

	}

	if jwtUUID != userID {
		t.Errorf("Failed test, got: %s, want: %s", jwtUUID, userID)
	}

	secret = base64.StdEncoding.EncodeToString([]byte("HELLO"))
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Errorf("Failed test, supposed to error. Wrong secret")

	}

	time.Sleep(time_duration)

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Errorf("Failed test, token should have expired")
	}

}

func TestGetBearerToken(t *testing.T) {

	headers := http.Header{
		"Authorization": {
			"Bear Token",
		},
	}
	_, err := GetBearerToken(headers)
	if err != nil {
		t.Errorf("Test Failed, got: %s", err)
	}

	headers2 := http.Header{
		"Authorization": {
			"Bear",
		},
	}
	token, err := GetBearerToken(headers2)
	if err == nil {
		t.Errorf("Test Failed, got: %s", token)
	}
}
