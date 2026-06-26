package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionManager_Get(t *testing.T) {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
	}

	// 1. Test valid session
	validID := "valid-session"
	validSession := &Session{
		ID:        validID,
		Username:  "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	sm.sessions[validID] = validSession

	session, exists := sm.Get(validID)
	if !exists {
		t.Errorf("Expected session %s to exist", validID)
	}
	if session != validSession {
		t.Errorf("Expected session %v, got %v", validSession, session)
	}

	// 2. Test non-existent session
	nonExistentID := "non-existent"
	session, exists = sm.Get(nonExistentID)
	if exists {
		t.Error("Expected non-existent session to not exist")
	}
	if session != nil {
		t.Errorf("Expected nil session for non-existent ID, got %v", session)
	}

	// 3. Test expired session
	expiredID := "expired-session"
	expiredSession := &Session{
		ID:        expiredID,
		Username:  "user2",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	sm.sessions[expiredID] = expiredSession

	session, exists = sm.Get(expiredID)
	if exists {
		t.Error("Expected expired session to be considered non-existent")
	}
	if session != nil {
		t.Errorf("Expected nil session for expired ID, got %v", session)
	}
}

func TestSessionManager_Create(t *testing.T) {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
	}

	username := "testuser"
	session := sm.Create(username)

	if session == nil {
		t.Fatalf("Expected session to be created, got nil")
	}

	if session.Username != username {
		t.Errorf("Expected username %s, got %s", username, session.Username)
	}

	if session.ID == "" {
		t.Errorf("Expected non-empty session ID")
	}

	if session.CSRFToken == "" {
		t.Errorf("Expected non-empty CSRF token")
	}

	// Allow some buffer for time comparison
	expectedExpiry := time.Now().Add(24 * time.Hour)
	if session.ExpiresAt.Before(expectedExpiry.Add(-time.Minute)) || session.ExpiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Errorf("Expected expiry around %v, got %v", expectedExpiry, session.ExpiresAt)
	}

	storedSession, exists := sm.sessions[session.ID]
	if !exists {
		t.Errorf("Expected session to be stored in manager")
	}
	if storedSession != session {
		t.Errorf("Expected stored session to be identical to returned session")
	}
}

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

	baseUploadDir, _ = filepath.Abs("./uploads")

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

func TestRateLimiter_GlobalLimit(t *testing.T) {
	rl := NewRateLimiter()

	ip := "127.0.0.1"
	for i := 0; i < 60; i++ {
		if !rl.Allow(ip, "/api/files") {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}

	if rl.Allow(ip, "/api/files") {
		t.Fatal("61st request should have been rate limited")
	}
}

func TestRateLimiter_LoginLimitDoesNotConsumeGlobalBudgetAfterLimit(t *testing.T) {
	rl := NewRateLimiter()

	ip := "127.0.0.2"
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip, "/api/login") {
			t.Fatalf("login request %d should have been allowed", i+1)
		}
	}

	if rl.Allow(ip, "/api/login") {
		t.Fatal("6th login request should have been rate limited")
	}

	for i := 0; i < 55; i++ {
		if !rl.Allow(ip, "/api/files") {
			t.Fatalf("non-login request %d should have been allowed", i+1)
		}
	}

	if rl.Allow(ip, "/api/files") {
		t.Fatal("next non-login request should have exceeded global limit")
	}
}

func TestClientIPFromRemoteAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "ipv4 host and port",
			remoteAddr: "192.168.1.2:54321",
			want:       "192.168.1.2",
		},
		{
			name:       "ipv6 host and port",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "host without port",
			remoteAddr: "10.0.0.7",
			want:       "10.0.0.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientIPFromRemoteAddr(tt.remoteAddr)
			if got != tt.want {
				t.Fatalf("clientIPFromRemoteAddr(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
			}
		})
	}
}

func TestDeleteHandler_RootDirectoryForbidden(t *testing.T) {
	// Setup a temporary directory for tests
	tmpDir, err := os.MkdirTemp("", "test-uploads")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Temporarily override the baseUploadDir
	originalBaseUploadDir := baseUploadDir
	baseUploadDir = tmpDir
	defer func() { baseUploadDir = originalBaseUploadDir }()

	req, err := http.NewRequest(http.MethodDelete, "/api/delete?path=.", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(deleteHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}

	var resp Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Success != false {
		t.Errorf("Expected Success to be false, got true")
	}
}

func TestRenameHandler_RootDirectoryForbidden(t *testing.T) {
	// Setup a temporary directory for tests
	tmpDir, err := os.MkdirTemp("", "test-uploads")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Temporarily override the baseUploadDir
	originalBaseUploadDir := baseUploadDir
	baseUploadDir = tmpDir
	defer func() { baseUploadDir = originalBaseUploadDir }()

	payload := map[string]string{
		"oldPath": ".",
		"newName": "new-name",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, "/api/rename", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(renameHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}

	var resp Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Success != false {
		t.Errorf("Expected Success to be false, got true")
	}
}
