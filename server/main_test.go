package main

import (
	"testing"
	"time"
)

func TestSessionManager_Get(t *testing.T) {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
	}

	// 1. Test valid session
	validID := "valid-session"
	validSession := &Session{
		ID:        validID,
		Username:  "user1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	sm.sessions[validID] = validSession

	session, exists := sm.Get(validID)
	if !exists {
		t.Errorf("Expected session %s to exist", validID)
	}
	if session != validSession {
		t.Errorf("Expected session %v, got %v", validSession, session)
	}

	// 2. Test non-existent session
	nonExistentID := "non-existent"
	session, exists = sm.Get(nonExistentID)
	if exists {
		t.Error("Expected non-existent session to not exist")
	}
	if session != nil {
		t.Errorf("Expected nil session for non-existent ID, got %v", session)
	}

	// 3. Test expired session
	expiredID := "expired-session"
	expiredSession := &Session{
		ID:        expiredID,
		Username:  "user2",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	sm.sessions[expiredID] = expiredSession

	session, exists = sm.Get(expiredID)
	if exists {
		t.Error("Expected expired session to be considered non-existent")
	}
	if session != nil {
		t.Errorf("Expected nil session for expired ID, got %v", session)
	}
}
