package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
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

func TestAddToZip_File(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy file
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("Hello, World!")
	err = os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create a buffer to hold the zip
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Call addToZip
	err = addToZip(zipWriter, testFile, tmpDir)
	if err != nil {
		t.Errorf("addToZip failed: %v", err)
	}

	// Close the zip writer
	err = zipWriter.Close()
	if err != nil {
		t.Fatalf("Failed to close zip writer: %v", err)
	}

	// Verify the zip contents
	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to create zip reader: %v", err)
	}

	if len(zipReader.File) != 1 {
		t.Errorf("Expected 1 file in zip, found %d", len(zipReader.File))
	}

	fileInZip := zipReader.File[0]
	if fileInZip.Name != "test.txt" {
		t.Errorf("Expected file name 'test.txt', got '%s'", fileInZip.Name)
	}
}

func TestAddToZip_Directory(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "zip_test_dir")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory
	subDir := filepath.Join(tmpDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	// Create dummy files
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(subDir, "file2.txt")

	err = os.WriteFile(file1, []byte("Content 1"), 0644)
	if err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}

	err = os.WriteFile(file2, []byte("Content 2"), 0644)
	if err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	// Create a buffer to hold the zip
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Call addToZip for the whole directory
	err = addToZip(zipWriter, tmpDir, tmpDir)
	if err != nil {
		t.Errorf("addToZip failed: %v", err)
	}

	// Close the zip writer
	err = zipWriter.Close()
	if err != nil {
		t.Fatalf("Failed to close zip writer: %v", err)
	}

	// Verify the zip contents
	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to create zip reader: %v", err)
	}

	// We expect 2 files in the zip (directories themselves are not added, only files in addToZip implementation)
	expectedFiles := map[string]bool{
		"file1.txt": false,
		filepath.Join("subdir", "file2.txt"): false,
	}

	for _, f := range zipReader.File {
		// Normalize paths for comparison, zip paths might use forward slashes
		normalizedName := filepath.FromSlash(f.Name)
		if _, ok := expectedFiles[normalizedName]; ok {
			expectedFiles[normalizedName] = true
		} else {
			// Subdirectory itself might be added depending on implementation, let's just check files
			if !f.FileInfo().IsDir() {
			    t.Errorf("Unexpected file in zip: %s", normalizedName)
			}
		}
	}

	for name, found := range expectedFiles {
		if !found {
			t.Errorf("Expected file '%s' not found in zip", name)
		}
	}
}

func TestAddToZip_NonExistentFile(t *testing.T) {
    // Create a buffer to hold the zip
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Call addToZip with a non-existent file
	err := addToZip(zipWriter, "this_file_does_not_exist.txt", ".")
	if err == nil {
		t.Errorf("Expected error for non-existent file, got nil")
	}
}
