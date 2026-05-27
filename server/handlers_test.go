package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetCsrfTokenHandler(t *testing.T) {
	// Initialize global sessions manager for tests
	sessions = &SessionManager{
		sessions: make(map[string]*Session),
	}

	// Create a valid session
	sessionID := "test_session_id"
	csrfToken := "test_csrf_token"
	sessions.sessions[sessionID] = &Session{
		ID:        sessionID,
		Username:  "admin",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CSRFToken: csrfToken,
	}

	tests := []struct {
		name            string
		method          string
		cookieName      string
		cookieValue     string
		expectedStatus  int
		expectedSuccess bool
		expectedToken   string
	}{
		{
			name:            "Valid Request",
			method:          http.MethodGet,
			cookieName:      "session_id",
			cookieValue:     sessionID,
			expectedStatus:  http.StatusOK,
			expectedSuccess: true,
			expectedToken:   csrfToken,
		},
		{
			name:            "Wrong Method",
			method:          http.MethodPost,
			cookieName:      "session_id",
			cookieValue:     sessionID,
			expectedStatus:  http.StatusMethodNotAllowed,
			expectedSuccess: false,
		},
		{
			name:            "Missing Cookie",
			method:          http.MethodGet,
			cookieName:      "",
			cookieValue:     "",
			expectedStatus:  http.StatusUnauthorized,
			expectedSuccess: false,
		},
		{
			name:            "Invalid Session",
			method:          http.MethodGet,
			cookieName:      "session_id",
			cookieValue:     "invalid_session_id",
			expectedStatus:  http.StatusUnauthorized,
			expectedSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "/api/csrf-token", nil)
			if err != nil {
				t.Fatal(err)
			}

			if tt.cookieName != "" {
				cookie := &http.Cookie{
					Name:  tt.cookieName,
					Value: tt.cookieValue,
				}
				req.AddCookie(cookie)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(getCsrfTokenHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedStatus)
			}

			var response Response
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Fatal(err)
			}

			if response.Success != tt.expectedSuccess {
				t.Errorf("handler returned wrong success flag: got %v want %v",
					response.Success, tt.expectedSuccess)
			}

			if tt.expectedSuccess {
				data, ok := response.Data.(map[string]interface{})
				if !ok {
					t.Fatal("response data is not a map")
				}
				token, ok := data["csrf_token"].(string)
				if !ok {
					t.Fatal("csrf_token is not a string")
				}
				if token != tt.expectedToken {
					t.Errorf("handler returned wrong token: got %v want %v",
						token, tt.expectedToken)
				}
			}
		})
	}
}
