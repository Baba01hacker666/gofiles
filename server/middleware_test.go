package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitMiddleware(t *testing.T) {
	// Setup global rateLimiter
	rateLimiter = &RateLimiter{
		visitors: make(map[string]*Visitor),
	}

	// Create dummy next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap handler with middleware
	handlerToTest := rateLimitMiddleware(nextHandler)

	// Helper function to make request
	makeRequest := func(ip, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()
		handlerToTest.ServeHTTP(rr, req)
		return rr
	}

	ip := "10.0.0.1"

	// 1. Allow up to limit (5 for /api/login)
	for i := 0; i < 5; i++ {
		rr := makeRequest(ip, "/api/login")
		if rr.Code != http.StatusOK {
			t.Fatalf("Request %d should be OK, got %v", i+1, rr.Code)
		}
	}

	// 2. Reject 6th request
	rr := makeRequest(ip, "/api/login")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Request 6 should be TooManyRequests, got %v", rr.Code)
	}

	// Check response JSON structure
	var resp Response
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Success != false || resp.Message != "Rate limit exceeded" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}
