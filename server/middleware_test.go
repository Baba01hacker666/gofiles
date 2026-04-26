package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Declare the global variables if they are not defined.
// In a normal test run (go test ./...), they would be available from main.go.
// For isolated file tests, we need to provide them.
var rateLimiter *RateLimiter
var sessions *SessionManager

func TestRateLimitMiddleware(t *testing.T) {
	// Initialize rateLimiter if it's nil
	if rateLimiter == nil {
		rateLimiter = &RateLimiter{
			visitors: make(map[string]*Visitor),
		}
	}

	// Reset rateLimiter for the test
	rateLimiter.Lock()
	rateLimiter.visitors = make(map[string]*Visitor)
	rateLimiter.Unlock()

	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/files", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	// Should allow 60 requests (based on current implementation in auth.go)
	for i := 0; i < 60; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("Request %d should have been allowed, got %d", i+1, rr.Code)
		}
	}

	// 61st request should be rate limited
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware_Login(t *testing.T) {
	// Initialize rateLimiter if it's nil
	if rateLimiter == nil {
		rateLimiter = &RateLimiter{
			visitors: make(map[string]*Visitor),
		}
	}

	// Reset rateLimiter for the test
	rateLimiter.Lock()
	rateLimiter.visitors = make(map[string]*Visitor)
	rateLimiter.Unlock()

	handler := rateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/login", nil)
	req.RemoteAddr = "5.6.7.8:1234"

	// Should allow 5 login requests (based on current implementation in auth.go)
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("Login request %d should have been allowed, got %d", i+1, rr.Code)
		}
	}

	// 6th login request should be rate limited
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests for login, got %d", rr.Code)
	}
}
