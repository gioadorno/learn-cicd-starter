package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("no authorization header", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected ErrNoAuthHeaderIncluded, got nil")
		}
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "foobar")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("expected malformed authorization header error, got nil")
		}
		if !errors.Is(err, errors.New("malformed authorization header")) {
			t.Errorf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("valid authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my_api_key")
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if apiKey != "my_api_key" {
			t.Errorf("expected my_api_key, got %v", apiKey)
		}
	})
}
