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
		input    string
		expected string
	}{
		{"normal.txt", "normal.txt"},
		{"space in name.txt", "space in name.txt"},
		{"  trimmed.txt  ", "trimmed.txt"},
		{"path/to/file.txt", "file.txt"},
		{"path\\to\\file.txt", "file.txt"},
		{"../../etc/passwd", "passwd"},
		{"..", ""},
		{".", ""},
		{"", ""},
		{"file..txt", "file..txt"},
		{"/abs/path", "path"},
		{"C:\\Windows\\System32\\cmd.exe", "cmd.exe"},
		{"trailing/", ""},
		{"trailing//", ""},
		{"/leading", "leading"},
		{"dots...txt", "dots...txt"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeName(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
