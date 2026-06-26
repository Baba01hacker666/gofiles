package main

import (
	"hash/fnv"
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

const numRateLimitShards = 32

type rateLimiterShard struct {
	sync.Mutex
	visitors map[string]*Visitor
}

// RateLimiter is sharded by IP hash to minimise lock contention under high
// concurrency.  Each shard protects its own visitor map independently.
type RateLimiter struct {
	shards [numRateLimitShards]*rateLimiterShard
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{}
	for i := range rl.shards {
		rl.shards[i] = &rateLimiterShard{
			visitors: make(map[string]*Visitor),
		}
	}
	return rl
}

func (rl *RateLimiter) shard(ip string) *rateLimiterShard {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return rl.shards[h.Sum32()%numRateLimitShards]
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
