package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateAPIKey_NotEmpty(t *testing.T) {
	key := generateAPIKey()
	if key == "" {
		t.Error("generateAPIKey() returned an empty string")
	}
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	key1 := generateAPIKey()
	key2 := generateAPIKey()
	if key1 == key2 {
		t.Errorf("generateAPIKey() returned identical keys: %s", key1)
	}
}

func TestGenerateAPIKey_Length(t *testing.T) {
	key := generateAPIKey()
	// 32 bytes Base64 URLEncoded should be 44 characters
	// Base64 length formula: 4 * ceil(n / 3)
	// 4 * ceil(32 / 3) = 4 * 11 = 44
	expectedLength := 44
	if len(key) != expectedLength {
		t.Errorf("generateAPIKey() returned key of length %d, want %d", len(key), expectedLength)
	}
}

func TestGenerateAPIKey_Decoding(t *testing.T) {
	key := generateAPIKey()
	decoded, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		t.Errorf("Failed to decode generated API key %s: %v", key, err)
	}
	if len(decoded) != 32 {
		t.Errorf("Decoded API key has length %d, want 32", len(decoded))
	}
}

func TestSendJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	data := map[string]string{"message": "success"}

	sendJSON(recorder, http.StatusCreated, data)

	if recorder.Code != http.StatusCreated {
		t.Errorf("Expected status code %d, got %d", http.StatusCreated, recorder.Code)
	}

	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	expectedBody := "{\"message\":\"success\"}\n"
	if recorder.Body.String() != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, recorder.Body.String())
	}
}
