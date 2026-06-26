package main

import (
	"testing"
	"time"
)

// Note: baseUploadDir is declared in main.go, no need to redeclare here
// when testing the entire package

func TestRateLimiter_Allow_GlobalLimit(t *testing.T) {
	rl := NewRateLimiter()

	ip := "192.168.1.1"

	// Should allow 60 requests
	for i := 0; i < 60; i++ {
		if !rl.Allow(ip, "/api/files") {
			t.Fatalf("Request %d should be allowed", i+1)
		}
	}

	// 61st request should be blocked
	if rl.Allow(ip, "/api/files") {
		t.Fatal("Request 61 should be blocked")
	}
}

func TestRateLimiter_Allow_LoginLimit(t *testing.T) {
	rl := NewRateLimiter()

	ip := "192.168.1.2"

	// Should allow 5 login requests
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip, "/api/login") {
			t.Fatalf("Login request %d should be allowed", i+1)
		}
	}

	// 6th login request should be blocked
	if rl.Allow(ip, "/api/login") {
		t.Fatal("Login request 6 should be blocked")
	}

	// Even though login is blocked, global limit should still allow other endpoints
	// The 5 login requests also counted towards global, but we have 55 more global requests
	if !rl.Allow(ip, "/api/files") {
		t.Fatal("Global limit should still allow non-login requests")
	}
}

func TestRateLimiter_ResetTime(t *testing.T) {
	rl := NewRateLimiter()

	ip := "192.168.1.3"

	// Exhaust login limit
	for i := 0; i < 5; i++ {
		rl.Allow(ip, "/api/login")
	}
	if rl.Allow(ip, "/api/login") {
		t.Fatal("Login request 6 should be blocked")
	}

	// Exhaust global limit (5 login + 55 non-login = 60 total)
	for i := 0; i < 55; i++ {
		rl.Allow(ip, "/api/files")
	}
	if rl.Allow(ip, "/api/files") {
		t.Fatal("Global request should be blocked")
	}

	// Fast forward time by 2 minutes via the correct shard
	s := rl.shard(ip)
	s.Lock()
	s.visitors[ip].lastSeen = time.Now().Add(-2 * time.Minute)
	s.visitors[ip+":login"].lastSeen = time.Now().Add(-2 * time.Minute)
	s.Unlock()

	// Should be allowed again
	if !rl.Allow(ip, "/api/login") {
		t.Fatal("Login request should be allowed after time reset")
	}

	if !rl.Allow(ip, "/api/files") {
		t.Fatal("Global request should be allowed after time reset")
	}
}
