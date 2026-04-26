package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginCookieSecureFlag(t *testing.T) {
	// Setup credentials for comparison in loginHandler
	adminUsername = "admin"
	adminPasswordHash = []byte("$2a$10$8K1p/a06vgu3Y.Z3vY.hO.YvU.8K1p/a06vgu3Y.Z3vY.hO.YvU.") // bcrypt hash of "admin"

	tests := []struct {
		name     string
		certFile string
		keyFile  string
		wantSecure bool
	}{
		{
			name:     "Secure flag should be false when TLS is NOT configured",
			certFile: "",
			keyFile:  "",
			wantSecure: false,
		},
		{
			name:     "Secure flag should be true when TLS IS configured",
			certFile: "cert.pem",
			keyFile:  "key.pem",
			wantSecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock global config
			certFile = tt.certFile
			keyFile = tt.keyFile

			// Create login request
			loginReq := struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}{
				Username: "admin",
				Password: "admin",
			}
			body, _ := json.Marshal(loginReq)
			req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			// Call loginHandler
			loginHandler(w, req)

			// Check response
			resp := w.Result()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status OK, got %v", resp.Status)
			}

			// Check cookie
			cookies := resp.Cookies()
			var sessionCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "session_id" {
					sessionCookie = c
					break
				}
			}

			if sessionCookie == nil {
				t.Fatal("session_id cookie not found")
			}

			if sessionCookie.Secure != tt.wantSecure {
				t.Errorf("Expected Secure=%v, got %v", tt.wantSecure, sessionCookie.Secure)
			}
		})
	}
}
