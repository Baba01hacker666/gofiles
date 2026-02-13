package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxUploadSize = 100 * 1024 * 1024 // 100MB
	uploadDir     = "./uploads"
	staticDir     = "./static"
)

// Security configurations
var (
	// API key authentication (in production, use env vars or secrets manager)
	apiKey = generateAPIKey()
	
	// Rate limiting
	rateLimiter = &RateLimiter{
		visitors: make(map[string]*Visitor),
	}
	
	// Session management
	sessions = &SessionManager{
		sessions: make(map[string]*Session),
	}
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
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	IsDir        bool      `json:"isDir"`
	ModTime      time.Time `json:"modTime"`
	Permissions  string    `json:"permissions"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.Lock()
	defer rl.Unlock()
	
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
	
	if v.count >= 60 { // 60 requests per minute
		return false
	}
	
	v.count++
	return true
}

func (rl *RateLimiter) Cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 5*time.Minute {
				delete(rl.visitors, ip)
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

// Helper function to validate and get absolute path
func validatePath(requestPath string) (string, error) {
	cleanPath, err := filepath.Abs(filepath.Clean(requestPath))
	if err != nil {
		return "", err
	}
	
	baseUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		return "", err
	}
	
	// Ensure the resolved path is within the upload directory
	if !strings.HasPrefix(cleanPath, baseUploadDir) {
		return "", nil // nil indicates access denied
	}
	
	return cleanPath, nil
}

// Middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !rateLimiter.Allow(ip) {
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
		
		_, exists := sessions.Get(cookie.Value)
		if !exists {
			sendJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Message: "Invalid session",
			})
			return
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

// Handlers
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}
	
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request",
		})
		return
	}
	
	// Simple auth (in production, use bcrypt and database)
	expectedHash := sha256.Sum256([]byte("admin"))
	providedHash := sha256.Sum256([]byte(credentials.Password))
	
	if credentials.Username == "admin" && subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1 {
		session := sessions.Create(credentials.Username)
		
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			SameSite: http.SameSiteStrictMode,
		})
		
		sendJSON(w, http.StatusOK, Response{
			Success: true,
			Message: "Login successful",
			Data: map[string]string{
				"csrf_token": session.CSRFToken,
			},
		})
		return
	}
	
	sendJSON(w, http.StatusUnauthorized, Response{
		Success: false,
		Message: "Invalid credentials",
	})
}

func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = uploadDir
	}
	
	// Security: validate path using absolute path comparison
	cleanPath, err := validatePath(path)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid path",
		})
		return
	}
	
	if cleanPath == "" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Access denied",
		})
		return
	}
	
	files, err := os.ReadDir(cleanPath)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to read directory",
		})
		return
	}
	
	fileInfos := make([]FileInfo, 0, len(files))
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}
		
		fileInfos = append(fileInfos, FileInfo{
			Name:        file.Name(),
			Path:        filepath.Join(cleanPath, file.Name()),
			Size:        info.Size(),
			IsDir:       file.IsDir(),
			ModTime:     info.ModTime(),
			Permissions: info.Mode().String(),
		})
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    fileInfos,
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}
	
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "File too large",
		})
		return
	}
	
	file, handler, err := r.FormFile("file")
	if err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Failed to read file",
		})
		return
	}
	defer file.Close()
	
	// Security: sanitize filename
	filename := filepath.Base(handler.Filename)
	filename = strings.ReplaceAll(filename, "..", "")
	
	// Validate upload directory path
	baseUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Server error",
		})
		return
	}
	
	destPath := filepath.Join(baseUploadDir, filename)
	
	dest, err := os.Create(destPath)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create file",
		})
		return
	}
	defer dest.Close()
	
	if _, err := io.Copy(dest, file); err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to save file",
		})
		return
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "File uploaded successfully",
		Data: map[string]string{
			"filename": filename,
			"path":     destPath,
		},
	})
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "Path required", http.StatusBadRequest)
		return
	}
	
	// Security: validate path using absolute path comparison
	cleanPath, err := validatePath(path)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	if cleanPath == "" {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	info, err := os.Stat(cleanPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	if info.IsDir() {
		http.Error(w, "Cannot download directory", http.StatusBadRequest)
		return
	}
	
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(cleanPath))
	w.Header().Set("Content-Type", "application/octet-stream")
	
	http.ServeFile(w, r, cleanPath)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}
	
	path := r.URL.Query().Get("path")
	if path == "" {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Path required",
		})
		return
	}
	
	// Security: validate path using absolute path comparison
	cleanPath, err := validatePath(path)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid path",
		})
		return
	}
	
	if cleanPath == "" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Access denied",
		})
		return
	}
	
	if err := os.RemoveAll(cleanPath); err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to delete",
		})
		return
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Deleted successfully",
	})
}

func renameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}
	
	var req struct {
		OldPath string `json:"oldPath"`
		NewName string `json:"newName"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request",
		})
		return
	}
	
	// Security: validate old path using absolute path comparison
	cleanOldPath, err := validatePath(req.OldPath)
	if err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid path",
		})
		return
	}
	
	if cleanOldPath == "" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Access denied",
		})
		return
	}
	
	// Sanitize new name
	newName := filepath.Base(req.NewName)
	newPath := filepath.Join(filepath.Dir(cleanOldPath), newName)
	
	// Validate new path is still within upload dir
	validatedNewPath, err := validatePath(newPath)
	if err != nil || validatedNewPath == "" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Invalid new path",
		})
		return
	}
	
	if err := os.Rename(cleanOldPath, validatedNewPath); err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to rename",
		})
		return
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Renamed successfully",
		Data: map[string]string{
			"newPath": validatedNewPath,
		},
	})
}

func createDirHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}
	
	var req struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request",
		})
		return
	}
	
	// Security: validate base path using absolute path comparison
	basePath, err := validatePath(req.Path)
	if err != nil {
		basePath, _ = filepath.Abs(uploadDir)
	}
	
	if basePath == "" {
		basePath, _ = filepath.Abs(uploadDir)
	}
	
	dirName := filepath.Base(req.Name)
	fullPath := filepath.Join(basePath, dirName)
	
	// Validate new directory path is still within upload dir
	validatedPath, err := validatePath(fullPath)
	if err != nil || validatedPath == "" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Invalid path",
		})
		return
	}
	
	if err := os.MkdirAll(validatedPath, 0755); err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create directory",
		})
		return
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Directory created successfully",
		Data: map[string]string{
			"path": validatedPath,
		},
	})
}

func zipHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}
	
	var req struct {
		Paths []string `json:"paths"`
		Name  string   `json:"name"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid request",
		})
		return
	}
	
	zipName := filepath.Base(req.Name)
	if !strings.HasSuffix(zipName, ".zip") {
		zipName += ".zip"
	}
	
	baseUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Server error",
		})
		return
	}
	
	zipPath := filepath.Join(baseUploadDir, zipName)
	
	zipFile, err := os.Create(zipPath)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create zip file",
		})
		return
	}
	defer zipFile.Close()
	
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()
	
	for _, path := range req.Paths {
		cleanPath, err := validatePath(path)
		if err != nil || cleanPath == "" {
			continue
		}
		
		if err := addToZip(zipWriter, cleanPath, baseUploadDir); err != nil {
			log.Printf("Failed to add %s to zip: %v", cleanPath, err)
		}
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Zip created successfully",
		Data: map[string]string{
			"path": zipPath,
		},
	})
}

func addToZip(zipWriter *zip.Writer, filename, baseDir string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	
	if info.IsDir() {
		return filepath.Walk(filename, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			
			if info.IsDir() {
				return nil
			}
			
			relPath, err := filepath.Rel(baseDir, path)
			if err != nil {
				return err
			}
			
			return addFileToZip(zipWriter, path, relPath)
		})
	}
	
	relPath, err := filepath.Rel(baseDir, filename)
	if err != nil {
		return err
	}
	
	return addFileToZip(zipWriter, filename, relPath)
}

func addFileToZip(zipWriter *zip.Writer, filename, zipPath string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer, err := zipWriter.Create(zipPath)
	if err != nil {
		return err
	}
	
	_, err = io.Copy(writer, file)
	return err
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Query required",
		})
		return
	}
	
	var results []FileInfo
	
	baseUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Server error",
		})
		return
	}
	
	err = filepath.Walk(baseUploadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if strings.Contains(strings.ToLower(info.Name()), strings.ToLower(query)) {
			results = append(results, FileInfo{
				Name:        info.Name(),
				Path:        path,
				Size:        info.Size(),
				IsDir:       info.IsDir(),
				ModTime:     info.ModTime(),
				Permissions: info.Mode().String(),
			})
		}
		
		return nil
	})
	
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Search failed",
		})
		return
	}
	
	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    results,
	})
}

func sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func main() {
	// Ensure directories exist
	os.MkdirAll(uploadDir, 0755)
	
	// Start cleanup goroutines
	go rateLimiter.Cleanup()
	go sessions.Cleanup()
	
	// Routes
	http.HandleFunc("/", securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	}))
	
	http.HandleFunc("/api/login", securityHeadersMiddleware(rateLimitMiddleware(loginHandler)))
	http.HandleFunc("/api/files", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(listFilesHandler))))
	http.HandleFunc("/api/upload", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(uploadHandler))))
	http.HandleFunc("/api/download", securityHeadersMiddleware(authMiddleware(downloadHandler)))
	http.HandleFunc("/api/delete", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(deleteHandler))))
	http.HandleFunc("/api/rename", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(renameHandler))))
	http.HandleFunc("/api/mkdir", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(createDirHandler))))
	http.HandleFunc("/api/zip", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(zipHandler))))
	http.HandleFunc("/api/search", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(searchHandler))))
	
	// Static files
	fs := http.FileServer(http.Dir(staticDir))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	
	log.Printf("API Key (for reference): %s\n", apiKey)
	log.Printf("Default credentials: admin / admin\n")
	log.Println("Server starting on http://localhost:8080")
	
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
