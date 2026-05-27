package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadHandler(t *testing.T) {
	// Create a temporary directory for the tests
	tmpDir, err := os.MkdirTemp("", "test-downloads")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// We need to set baseUploadDir to our tmpDir for validatePath to work correctly
	// Save the old baseUploadDir and restore it after the test
	oldBaseUploadDir := baseUploadDir
	baseUploadDir = tmpDir
	defer func() { baseUploadDir = oldBaseUploadDir }()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a subdirectory for testing directory error
	subDir := filepath.Join(tmpDir, "subdir")
	err = os.MkdirAll(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test subdir: %v", err)
	}

	tests := []struct {
		name           string
		pathParam      string
		expectedStatus int
		expectedHeader string
	}{
		{
			name:           "Valid File",
			pathParam:      "test.txt",
			expectedStatus: http.StatusOK,
			expectedHeader: "attachment; filename=test.txt",
		},
		{
			name:           "Missing Path",
			pathParam:      "",
			expectedStatus: http.StatusBadRequest,
			expectedHeader: "",
		},
		{
			name:           "File Not Found",
			pathParam:      "nonexistent.txt",
			expectedStatus: http.StatusNotFound,
			expectedHeader: "",
		},
		{
			name:           "Cannot Download Directory",
			pathParam:      "subdir",
			expectedStatus: http.StatusBadRequest,
			expectedHeader: "",
		},
		{
			name:           "Invalid Path (Traversal)",
			pathParam:      "../etc/passwd",
			expectedStatus: http.StatusForbidden,
			expectedHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/api/download?path="+tt.pathParam, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(downloadHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("Handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedHeader != "" {
				if disp := rr.Header().Get("Content-Disposition"); disp != tt.expectedHeader {
					t.Errorf("Handler returned wrong Content-Disposition header: got %v want %v", disp, tt.expectedHeader)
				}
			}
		})
	}
}
