package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestAddFileToZip_Success(t *testing.T) {
	// Create a temporary file
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "test.txt")
	content := []byte("hello zip")
	err := os.WriteFile(tempFile, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// Create an in-memory zip writer
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Call the function
	err = addFileToZip(zipWriter, tempFile, "test.txt")
	if err != nil {
		t.Errorf("addFileToZip failed: %v", err)
	}

	// Close the zip writer
	err = zipWriter.Close()
	if err != nil {
		t.Fatalf("Failed to close zip writer: %v", err)
	}

	// Read the zip archive back
	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to read created zip: %v", err)
	}

	if len(zipReader.File) != 1 {
		t.Fatalf("Expected 1 file in zip, got %d", len(zipReader.File))
	}

	// Check file content
	f := zipReader.File[0]
	if f.Name != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got '%s'", f.Name)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("Failed to open file inside zip: %v", err)
	}
	defer rc.Close()

	readContent, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read file inside zip: %v", err)
	}

	if string(readContent) != "hello zip" {
		t.Errorf("Expected content 'hello zip', got '%s'", string(readContent))
	}
}

func TestAddFileToZip_Failure(t *testing.T) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Try to add a non-existent file
	err := addFileToZip(zipWriter, "non_existent_file.txt", "test.txt")
	if err == nil {
		t.Error("Expected error when adding non-existent file to zip, got nil")
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
