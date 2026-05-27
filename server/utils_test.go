package main

import (
	"encoding/base64"
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

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"normal file", "test.txt", "test.txt", false},
		{"file with space", "test file.txt", "test file.txt", false},
		{"path traversal unix", "../../../etc/passwd", "passwd", false},
		{"path traversal windows", "..\\..\\..\\Windows\\System32\\cmd.exe", "cmd.exe", false},
		{"absolute path unix", "/etc/passwd", "passwd", false},
		{"absolute path windows", "C:\\Windows\\System32\\cmd.exe", "cmd.exe", false},
		{"mixed slashes", "a/b\\c/d.txt", "d.txt", false},
		{"empty string", "", "", true},
		{"dot", ".", "", true},
		{"dot dot", "..", "", true},
		{"slash", "/", "", true},
		{"backslash", "\\", "", true},
		{"trailing slash unix", "folder/", "", true},
		{"trailing slash windows", "folder\\", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sanitizeName() = %v, want %v", got, tt.want)
			}
		})
	}
}
