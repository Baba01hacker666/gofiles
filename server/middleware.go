package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Strip port if present in RemoteAddr for basic IP
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		if !rateLimiter.Allow(ip, r.URL.Path) {
			sendJSON(w, http.StatusTooManyRequests, Response{
				Success: false,
				Message: "Rate limit exceeded",
			})
			return
		}
		next(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			sendJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Message: "Unauthorized",
			})
			return
		}

		session, exists := sessions.Get(cookie.Value)
		if !exists {
			sendJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Message: "Invalid session",
			})
			return
		}

		// CSRF Token Validation for state-changing requests
		if r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			csrfToken := r.Header.Get("X-CSRF-Token")
			// 🛡️ Sentinel: Use constant-time comparison to prevent timing attacks when comparing sensitive tokens
			if csrfToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(session.CSRFToken)) != 1 {
				sendJSON(w, http.StatusForbidden, Response{
					Success: false,
					Message: "Invalid CSRF token",
				})
				return
			}
		}

		next(w, r)
	}
}

func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next(w, r)
	}
}
