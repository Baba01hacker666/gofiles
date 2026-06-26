package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxUploadSize = 100 * 1024 * 1024 // 100MB
	staticDir     = "./static"
)

var (
	uploadDir         = "./uploads"
	baseUploadDir     string
	serverPort        = "8080"
	adminUsername     = "admin"
	adminPasswordHash []byte
	certFile          = ""
	keyFile           = ""
)

func init() {
	if p := os.Getenv("PORT"); p != "" {
		serverPort = p
	}
	if u := os.Getenv("UPLOAD_DIR"); u != "" {
		uploadDir = u
	}
	baseUploadDir, _ = filepath.Abs(uploadDir)
	if u := os.Getenv("ADMIN_USERNAME"); u != "" {
		adminUsername = u
	}
	if p := os.Getenv("ADMIN_PASSWORD_HASH"); p != "" {
		adminPasswordHash = []byte(p)
	} else {
		// Default to bcrypt hash of "admin"
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		adminPasswordHash = hash
	}
	if c := os.Getenv("CERT_FILE"); c != "" {
		certFile = c
	}
	if k := os.Getenv("KEY_FILE"); k != "" {
		keyFile = k
	}
}

// Security configurations
var (
	apiKey = generateAPIKey()

	rateLimiter = NewRateLimiter()

	sessions = &SessionManager{
		sessions: make(map[string]*Session),
	}
)

func main() {
	os.MkdirAll(baseUploadDir, 0755)
	log.Printf("Upload directory: %s", baseUploadDir)

	go rateLimiter.Cleanup()
	go sessions.Cleanup()

	http.HandleFunc("/", securityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	}))

	http.HandleFunc("/api/csrf", securityHeadersMiddleware(rateLimitMiddleware(getCsrfTokenHandler)))
	http.HandleFunc("/api/login", securityHeadersMiddleware(rateLimitMiddleware(loginHandler)))
	http.HandleFunc("/api/logout", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(logoutHandler))))
	http.HandleFunc("/api/files", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(listFilesHandler))))
	http.HandleFunc("/api/upload", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(uploadHandler))))
	http.HandleFunc("/api/download", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(downloadHandler))))
	http.HandleFunc("/api/delete", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(deleteHandler))))
	http.HandleFunc("/api/rename", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(renameHandler))))
	http.HandleFunc("/api/mkdir", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(createDirHandler))))
	http.HandleFunc("/api/zip", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(zipHandler))))
	http.HandleFunc("/api/search", securityHeadersMiddleware(authMiddleware(rateLimitMiddleware(searchHandler))))

	fs := http.FileServer(http.Dir(staticDir))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Printf("API Key (for reference): %s\n", apiKey)
	log.Printf("Using configuration:")
	log.Printf(" - Port: %s\n", serverPort)
	log.Printf(" - Admin Username: %s\n", adminUsername)
	log.Printf(" - Upload Directory: %s\n", uploadDir)

	srv := &http.Server{
		Addr:              ":" + serverPort,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	if certFile != "" && keyFile != "" {
		log.Printf("Server starting on https://localhost:%s\n", serverPort)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("Server starting on http://localhost:%s\n", serverPort)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}
