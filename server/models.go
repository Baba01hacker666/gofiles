package main

import (
	"sync"
	"time"
)

type Session struct {
	ID        string
	Username  string
	ExpiresAt time.Time
	CSRFToken string
}

type SessionManager struct {
	sync.RWMutex
	sessions map[string]*Session
}

type Visitor struct {
	lastSeen time.Time
	count    int
}

type RateLimiter struct {
	sync.RWMutex
	visitors map[string]*Visitor
}

type FileInfo struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	IsDir       bool      `json:"isDir"`
	ModTime     time.Time `json:"modTime"`
	Permissions string    `json:"permissions"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}
