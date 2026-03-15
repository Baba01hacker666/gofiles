package main

import (
	"time"
)

func (rl *RateLimiter) Allow(ip, path string) bool {
	rl.Lock()
	defer rl.Unlock()

	// Check global IP limit
	globalKey := ip
	globalV, globalExists := rl.visitors[globalKey]
	if !globalExists {
		rl.visitors[globalKey] = &Visitor{time.Now(), 1}
		globalV = rl.visitors[globalKey]
	} else {
		if time.Since(globalV.lastSeen) > time.Minute {
			globalV.count = 0
			globalV.lastSeen = time.Now()
		}
		if globalV.count >= 60 {
			return false // Global rate limit exceeded
		}
		globalV.count++
	}

	// Check specific endpoint limit for login
	if path == "/api/login" {
		loginKey := ip + ":login"
		loginV, loginExists := rl.visitors[loginKey]
		if !loginExists {
			rl.visitors[loginKey] = &Visitor{time.Now(), 1}
			return true
		}

		if time.Since(loginV.lastSeen) > time.Minute {
			loginV.count = 1
			loginV.lastSeen = time.Now()
			return true
		}

		if loginV.count >= 5 {
			// Do not penalize global count if login is rate limited
			globalV.count--
			return false // Login rate limit exceeded
		}
		loginV.count++
	}

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &Visitor{time.Now(), 1}
		return true
	}

	if time.Since(v.lastSeen) > time.Minute {
		v.count = 1
		v.lastSeen = time.Now()
		return true
	}

	if v.count >= 60 {
		return false
	}

	v.count++
	return true
}

func (rl *RateLimiter) Cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.Lock()
		for key, v := range rl.visitors {
			if time.Since(v.lastSeen) > 5*time.Minute {
				delete(rl.visitors, key)
			}
		}
		rl.Unlock()
	}
}

func (sm *SessionManager) Create(username string) *Session {
	sm.Lock()
	defer sm.Unlock()

	sessionID := generateAPIKey()
	csrfToken := generateAPIKey()

	session := &Session{
		ID:        sessionID,
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CSRFToken: csrfToken,
	}

	sm.sessions[sessionID] = session
	return session
}

func (sm *SessionManager) Get(sessionID string) (*Session, bool) {
	sm.RLock()
	defer sm.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

func (sm *SessionManager) Cleanup() {
	for {
		time.Sleep(time.Hour)
		sm.Lock()
		for id, session := range sm.sessions {
			if time.Now().After(session.ExpiresAt) {
				delete(sm.sessions, id)
			}
		}
		sm.Unlock()
	}
}
