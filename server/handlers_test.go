package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateDirHandler(t *testing.T) {
	// Setup a temporary directory for uploads
	tmpDir, err := os.MkdirTemp("", "test-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set baseUploadDir to our temp directory so validatePath works correctly
	origBaseUploadDir := baseUploadDir
	baseUploadDir = tmpDir
	defer func() { baseUploadDir = origBaseUploadDir }()

	tests := []struct {
		name           string
		method         string
		body           interface{} // to be marshaled to JSON, or string if invalid
		expectedStatus int
		expectedSuccess bool
		verifyDir      string      // path to verify after creation
	}{
		{
			name:   "Valid directory creation at root",
			method: http.MethodPost,
			body: map[string]string{
				"path": "",
				"name": "new_folder",
			},
			expectedStatus:  http.StatusOK,
			expectedSuccess: true,
			verifyDir:       "new_folder",
		},
		{
			name:   "Valid directory creation with nested path",
			method: http.MethodPost,
			body: map[string]string{
				"path": "existing_dir",
				"name": "nested_folder",
			},
			expectedStatus:  http.StatusOK,
			expectedSuccess: true,
			verifyDir:       "existing_dir/nested_folder",
		},
		{
			name:   "Invalid HTTP method",
			method: http.MethodGet,
			body:   nil,
			expectedStatus:  http.StatusMethodNotAllowed,
			expectedSuccess: false,
		},
		{
			name:   "Invalid JSON",
			method: http.MethodPost,
			body:   "{invalid json}",
			expectedStatus:  http.StatusBadRequest,
			expectedSuccess: false,
		},
		{
			name:   "Empty folder name",
			method: http.MethodPost,
			body: map[string]string{
				"path": "",
				"name": "   ",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedSuccess: false,
		},
		{
			name:   "Path traversal in folder name",
			method: http.MethodPost,
			body: map[string]string{
				"path": "",
				"name": "../hack",
			},
			expectedStatus:  http.StatusOK,
			expectedSuccess: true,
			verifyDir:       "hack",
		},
		{
			name:   "Path traversal in base path",
			method: http.MethodPost,
			body: map[string]string{
				"path": "../outside",
				"name": "folder",
			},
			expectedStatus:  http.StatusForbidden,
			expectedSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Valid directory creation with nested path" {
				os.MkdirAll(filepath.Join(tmpDir, "existing_dir"), 0755)
			}

			var bodyBytes []byte
			if strBody, ok := tt.body.(string); ok {
				bodyBytes = []byte(strBody)
			} else if tt.body != nil {
				bodyBytes, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest(tt.method, "/api/create-dir", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createDirHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, w.Code, w.Body.String())
			}

			var resp Response
			if w.Code < 500 {
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil {
					if resp.Success != tt.expectedSuccess {
						t.Errorf("Expected success=%v, got %v", tt.expectedSuccess, resp.Success)
					}
				}
			}

			if tt.expectedSuccess && tt.verifyDir != "" {
				fullPath := filepath.Join(tmpDir, tt.verifyDir)
				info, err := os.Stat(fullPath)
				if err != nil {
					t.Errorf("Expected directory to be created at %s, but got error: %v", fullPath, err)
				} else if !info.IsDir() {
					t.Errorf("Expected %s to be a directory", fullPath)
				}
			}
		})
	}
}
