package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	// Create a temporary directory for the tests
	tmpDir, err := os.MkdirTemp("", "test-uploads")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// In the real app, uploadDir is a constant.
	// We need to make sure we're testing the logic correctly.
	// Since validatePath uses the global uploadDir constant, we might need to be careful.
	// However, looking at the code, it calculates baseUploadDir := filepath.Abs(uploadDir)

	// For the sake of this unit test, let's assume we can mock it or just test the logic
	// by creating the expected directory structure.

	// Create the "uploads" directory in the current working directory (or where the test runs)
	// But the code uses "./uploads".

	err = os.MkdirAll("./uploads", 0755)
	if err != nil {
		t.Fatalf("Failed to create ./uploads: %v", err)
	}
	defer os.RemoveAll("./uploads")

	baseUploadDir, _ := filepath.Abs("./uploads")

	// Create a sibling directory to test the bypass
	siblingDir := baseUploadDir + "_secret"
	err = os.MkdirAll(siblingDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create sibling dir: %v", err)
	}
	defer os.RemoveAll(siblingDir)

	tests := []struct {
		name        string
		requestPath string
		wantAllowed bool
	}{
		{"Normal file", "file.txt", true},
		{"Subdirectory", "subdir/file.txt", true},
		{"Current directory", ".", true},
		{"Root of uploads", "", true},
		{"Traversal to /etc/passwd", "../../etc/passwd", false},
		{"Path traversal bypass (sibling dir)", "../uploads_secret/secret.txt", false},
		{"Relative traversal outside", "subdir/../../file.txt", false},
		{"Relative traversal inside", "subdir/../file.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePath(tt.requestPath)
			if tt.wantAllowed {
				if err != nil {
					t.Errorf("validatePath(%q) returned unexpected error: %v", tt.requestPath, err)
				}
				if got == "" {
					t.Errorf("validatePath(%q) should be allowed but returned empty string", tt.requestPath)
				}
				if !strings.HasPrefix(got, baseUploadDir) {
					t.Errorf("validatePath(%q) returned path %q outside base %q", tt.requestPath, got, baseUploadDir)
				}
			} else {
				if got != "" {
					t.Errorf("validatePath(%q) should be denied but returned %q", tt.requestPath, got)
				}
			}
		})
	}
}
