package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

// Middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

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

func clientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}

	if strings.HasPrefix(remoteAddr, "[") && strings.HasSuffix(remoteAddr, "]") {
		return strings.Trim(remoteAddr, "[]")
	}

	return remoteAddr
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next(w, r)
	}
}

func getClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		// Zero-alloc: find the last comma to get the rightmost (proxy-direct) IP
		if idx := strings.LastIndexByte(xForwardedFor, ','); idx >= 0 {
			return strings.TrimSpace(xForwardedFor[idx+1:])
		}
		return strings.TrimSpace(xForwardedFor)
	}

	xRealIP := r.Header.Get("X-Real-IP")
	if xRealIP != "" {
		return strings.TrimSpace(xRealIP)
	}

	return clientIPFromRemoteAddr(r.RemoteAddr)
}
