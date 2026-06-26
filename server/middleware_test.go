package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		expected   string
	}{
		{
			name:       "No headers",
			remoteAddr: "192.168.1.1:12345",
			headers:    nil,
			expected:   "192.168.1.1",
		},
		{
			name:       "X-Real-IP present",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Real-IP": "10.0.0.1",
			},
			expected: "10.0.0.1",
		},
		{
			name:       "X-Forwarded-For single IP",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.2",
			},
			expected: "10.0.0.2",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": " 10.0.0.3, 10.0.0.4 ",
			},
			expected: "10.0.0.4",
		},
		{
			name:       "X-Forwarded-For multiple IPs with empty first",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": ", 10.0.0.5, 10.0.0.6",
			},
			expected: "10.0.0.6",
		},
		{
			name:       "X-Forwarded-For and X-Real-IP both present",
			remoteAddr: "192.168.1.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.6",
				"X-Real-IP":       "10.0.0.7",
			},
			expected: "10.0.0.6",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tc.expected {
				t.Errorf("Expected IP %q, got %q", tc.expected, ip)
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	// Initialize global variables to prevent panics during test
	if sessions == nil {
		sessions = &SessionManager{
			sessions: make(map[string]*Session),
		}
	}
	if rateLimiter == nil {
		rateLimiter = NewRateLimiter()
	}

	// Create a dummy valid session
	session := sessions.Create("testuser")

	tests := []struct {
		name           string
		method         string
		setupRequest   func(req *http.Request)
		expectedStatus int
	}{
		{
			name:           "No Cookie",
			method:         http.MethodGet,
			setupRequest:   func(req *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:   "Invalid Cookie",
			method: http.MethodGet,
			setupRequest: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_id", Value: "invalid_session_value"})
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:   "Valid Cookie GET",
			method: http.MethodGet,
			setupRequest: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_id", Value: session.ID})
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Valid Cookie POST Missing CSRF",
			method: http.MethodPost,
			setupRequest: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_id", Value: session.ID})
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:   "Valid Cookie POST Invalid CSRF",
			method: http.MethodPost,
			setupRequest: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_id", Value: session.ID})
				req.Header.Set("X-CSRF-Token", "wrong_token_value")
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:   "Valid Cookie POST Valid CSRF",
			method: http.MethodPost,
			setupRequest: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_id", Value: session.ID})
				req.Header.Set("X-CSRF-Token", session.CSRFToken)
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/test", nil)
			tt.setupRequest(req)

			rr := httptest.NewRecorder()

			// Dummy handler
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := authMiddleware(nextHandler)
			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}
		})
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeadersMiddleware(nextHandler)
	handler.ServeHTTP(rr, req)

	// Check headers
	headers := rr.Header()
	if got := headers.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options: nosniff, got: %s", got)
	}
	if got := headers.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("Expected X-Frame-Options: DENY, got: %s", got)
	}
	if got := headers.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Expected Referrer-Policy: strict-origin-when-cross-origin, got: %s", got)
	}
	if got := headers.Get("Permissions-Policy"); got != "camera=(), microphone=(), geolocation=()" {
		t.Errorf("Expected Permissions-Policy: camera=(), microphone=(), geolocation=(), got: %s", got)
	}
	if got := headers.Get("X-XSS-Protection"); got != "" {
		t.Errorf("Expected X-XSS-Protection to be removed, got: %s", got)
	}
}
