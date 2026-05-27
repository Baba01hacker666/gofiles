package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	// Initialize global variables to prevent panics during test
	if sessions == nil {
		sessions = &SessionManager{
			sessions: make(map[string]*Session),
		}
	}
	if rateLimiter == nil {
		rateLimiter = &RateLimiter{
			visitors: make(map[string]*Visitor),
		}
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
	if got := headers.Get("X-XSS-Protection"); got != "1; mode=block" {
		t.Errorf("Expected X-XSS-Protection: 1; mode=block, got: %s", got)
	}
}
