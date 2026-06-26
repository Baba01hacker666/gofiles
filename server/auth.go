package main

import (
	"time"
)

func (rl *RateLimiter) Allow(ip, path string) bool {
	s := rl.shard(ip)
	s.Lock()
	defer s.Unlock()

	now := time.Now()

	// Check global IP limit
	v, exists := s.visitors[ip]
	if !exists {
		s.visitors[ip] = &Visitor{now, 1}
		v = s.visitors[ip]
	} else {
		if now.Sub(v.lastSeen) > time.Minute {
			v.count = 1
			v.lastSeen = now
		} else {
			if v.count >= 60 {
				return false // Global rate limit exceeded
			}
			v.count++
		}
	}

	// Check specific endpoint limit for login
	if path == "/api/login" {
		loginKey := ip + ":login"
		loginV, loginExists := s.visitors[loginKey]
		if !loginExists {
			s.visitors[loginKey] = &Visitor{now, 1}
			return true
		}

		if now.Sub(loginV.lastSeen) > time.Minute {
			loginV.count = 1
			loginV.lastSeen = now
			return true
		}

		if loginV.count >= 5 {
			// Do not penalize global count if login is rate limited
			v.count--
			return false // Login rate limit exceeded
		}
		loginV.count++
	}
	return true
}

func (rl *RateLimiter) Cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		for _, s := range rl.shards {
			s.Lock()
			now := time.Now()
			for key, v := range s.visitors {
				if now.Sub(v.lastSeen) > 5*time.Minute {
					delete(s.visitors, key)
				}
			}
			s.Unlock()
		}
	}
}

func (sm *SessionManager) Create(username string) *Session {
	sm.Lock()
	defer sm.Unlock()

	sessionID, csrfToken := generateTwoKeys()

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

func (sm *SessionManager) Delete(sessionID string) {
	sm.Lock()
	defer sm.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) Cleanup() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		sm.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			if now.After(session.ExpiresAt) {
				delete(sm.sessions, id)
			}
		}
		sm.Unlock()
	}
}
