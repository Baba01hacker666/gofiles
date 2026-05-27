package main

import (
	"net/http"
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
