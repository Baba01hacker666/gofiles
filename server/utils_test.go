package main

import (
	"encoding/base64"
	"encoding/json"
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

	type TestPayload struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}

	payload := TestPayload{
		Message: "success",
		Code:    200,
	}

	sendJSON(recorder, http.StatusCreated, payload)

	if recorder.Code != http.StatusCreated {
		t.Errorf("Expected status code %d, got %d", http.StatusCreated, recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var decodedPayload TestPayload
	err := json.NewDecoder(recorder.Body).Decode(&decodedPayload)
	if err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	if decodedPayload.Message != payload.Message || decodedPayload.Code != payload.Code {
		t.Errorf("Expected payload %+v, got %+v", payload, decodedPayload)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"normal file", "report.pdf", "report.pdf", false},
		{"file with spaces", "my file.txt", "my file.txt", false},
		{"simple traversal", "../etc/passwd", "passwd", false},
		{"double traversal", "../../etc/shadow", "shadow", false},
		{"windows absolute path", `C:\Windows\System32\cmd.exe`, "cmd.exe", false},
		{"windows UNC path", `\\server\share\file.txt`, "file.txt", false},
		{"backslash traversal", `..\..\secret`, "secret", false},
		{"mixed slashes", `..\/../secret`, "secret", false},
		{"trailing slash", "folder/", "folder", false},
		{"trailing backslash", `folder\`, "folder", false},
		{"just dot", ".", "", true},
		{"just dotdot", "..", "", true},
		{"empty string", "", "", true},
		{"only slashes", "///", "", true},
		{"only backslashes", `\\\`, "", true},
		{"nested with backslashes", `subdir\..\..\file.txt`, "file.txt", false},
		{"unicode name", "файл.txt", "файл.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
