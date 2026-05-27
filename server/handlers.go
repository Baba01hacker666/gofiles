package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func getCsrfTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

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

	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]string{
			"csrf_token": session.CSRFToken,
		},
	})
}

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

	if credentials.Username == adminUsername && bcrypt.CompareHashAndPassword(adminPasswordHash, []byte(credentials.Password)) == nil {
		session := sessions.Create(credentials.Username)

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
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
		path = "./uploads"
	}

	cleanPath, err := validatePath(path)
	if err != nil {
		log.Printf("listFilesHandler: validatePath error - %v", err)
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
		log.Printf("listFilesHandler: ReadDir error for path %s - %v", cleanPath, err)
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

		fullPath := filepath.Join(cleanPath, file.Name())
		relPath, _ := filepath.Rel(baseUploadDir, fullPath)

		fileInfos = append(fileInfos, FileInfo{
			Name:        file.Name(),
			Path:        relPath,
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
		log.Printf("uploadHandler: ParseMultipartForm error - %v", err)
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "File too large",
		})
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Printf("uploadHandler: FormFile error - %v", err)
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Failed to read file",
		})
		return
	}
	defer file.Close()

	// Read first 512 bytes for content type detection
	buff := make([]byte, 512)
	_, err = file.Read(buff)
	if err != nil && err != io.EOF {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to read file content",
		})
		return
	}
	// Reset the file pointer back to the beginning
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to seek file",
		})
		return
	}

	contentType := http.DetectContentType(buff)
	log.Printf("Detected content type: %s for file %s", contentType, handler.Filename)

	filename := filepath.Base(handler.Filename)

	// Basic security: restrict typical executable file extensions as DetectContentType
	// might just return 'application/octet-stream' for them.
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".exe" || ext == ".sh" || ext == ".elf" || ext == ".bin" || ext == ".bat" || ext == ".cmd" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Executable files are not allowed",
		})
		return
	}
	filename = strings.ReplaceAll(filename, "..", "")

	destDir := r.FormValue("path")
	if destDir == "" {
		destDir = "./uploads"
	}

	cleanDestDir, err := validatePath(destDir)
	if err != nil {
		log.Printf("uploadHandler: validatePath error for %s - %v", destDir, err)
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid path",
		})
		return
	}

	if cleanDestDir == "" {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Access denied",
		})
		return
	}

	if err := os.MkdirAll(cleanDestDir, 0755); err != nil {
		log.Printf("uploadHandler: MkdirAll error for %s - %v", cleanDestDir, err)
	}

	destPath := filepath.Join(cleanDestDir, filename)

	dest, err := os.Create(destPath)
	if err != nil {
		log.Printf("uploadHandler: Create error for %s - %v", destPath, err)
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create file",
		})
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		log.Printf("uploadHandler: Copy error - %v", err)
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to save file",
		})
		return
	}

	relPath, _ := filepath.Rel(baseUploadDir, destPath)

	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "File uploaded successfully",
		Data: map[string]string{
			"filename": filename,
			"path":     relPath,
		},
	})
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Path required",
		})
		return
	}

	cleanPath, err := validatePath(path)
	if err != nil {
		log.Printf("downloadHandler: validatePath error - %v", err)
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

	info, err := os.Stat(cleanPath)
	if err != nil {
		log.Printf("downloadHandler: Stat error for %s - %v", cleanPath, err)
		sendJSON(w, http.StatusNotFound, Response{
			Success: false,
			Message: "File not found",
		})
		return
	}

	if info.IsDir() {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Cannot download directory",
		})
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

	cleanPath, err := validatePath(path)
	if err != nil {
		log.Printf("deleteHandler: validatePath error - %v", err)
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

	if cleanPath == baseUploadDir {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Cannot delete root directory",
		})
		return
	}

	if err := os.RemoveAll(cleanPath); err != nil {
		log.Printf("deleteHandler: RemoveAll error for %s - %v", cleanPath, err)
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

	cleanOldPath, err := validatePath(req.OldPath)
	if err != nil {
		log.Printf("renameHandler: validatePath error - %v", err)
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

	if cleanOldPath == baseUploadDir {
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Cannot rename root directory",
		})
		return
	}

	newName := filepath.Base(req.NewName)
	newName = strings.TrimSpace(newName)

	if newName == "" {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "New name cannot be empty",
		})
		return
	}

	newPath := filepath.Join(filepath.Dir(cleanOldPath), newName)

	validatedNewPath, err := validatePath(newPath)
	if err != nil || validatedNewPath == "" {
		log.Printf("renameHandler: validatePath error for new path - %v", err)
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Invalid new path",
		})
		return
	}

	if err := os.Rename(cleanOldPath, validatedNewPath); err != nil {
		log.Printf("renameHandler: Rename error - %v", err)
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to rename",
		})
		return
	}

	relPath, _ := filepath.Rel(baseUploadDir, validatedNewPath)

	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Renamed successfully",
		Data: map[string]string{
			"newPath": relPath,
		},
	})
}

// FIXED: createDirHandler - prevents path doubling
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

	log.Printf("createDirHandler: Path=%s, Name=%s", req.Path, req.Name)

	// Sanitize folder name - remove any path separators and trim whitespace
	dirName := filepath.Base(req.Name)
	dirName = strings.TrimSpace(dirName)
	dirName = strings.ReplaceAll(dirName, "/", "")
	dirName = strings.ReplaceAll(dirName, "\\", "")
	dirName = strings.ReplaceAll(dirName, "..", "")

	if dirName == "" || dirName == "." {
		sendJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Message: "Invalid folder name",
		})
		return
	}

	// Determine the parent path where we're creating the folder
	var parentPath string
	if req.Path == "" || req.Path == "./uploads" || req.Path == "uploads" {
		// Creating in root of uploads
		parentPath = baseUploadDir
	} else {
		// Validate the parent path
		cleanBasePath, err := validatePath(req.Path)
		if err != nil {
			log.Printf("createDirHandler: validatePath error for base path %s - %v", req.Path, err)
			sendJSON(w, http.StatusBadRequest, Response{
				Success: false,
				Message: "Invalid base path",
			})
			return
		}

		if cleanBasePath == "" {
			sendJSON(w, http.StatusForbidden, Response{
				Success: false,
				Message: "Access denied to base path",
			})
			return
		}

		parentPath = cleanBasePath
	}

	// Build the full path for the new directory
	fullPath := filepath.Join(parentPath, dirName)

	log.Printf("createDirHandler: Full path to create: %s", fullPath)

	// Make sure the full path is still within upload directory
	if fullPath != baseUploadDir && !strings.HasPrefix(fullPath, baseUploadDir+string(filepath.Separator)) {
		log.Printf("createDirHandler: Security check failed. Base: %s, Tried: %s", baseUploadDir, fullPath)
		sendJSON(w, http.StatusForbidden, Response{
			Success: false,
			Message: "Access denied - would escape upload directory",
		})
		return
	}

	// Create the directory
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		log.Printf("createDirHandler: MkdirAll error for %s - %v", fullPath, err)
		sendJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Message: "Failed to create directory",
		})
		return
	}

	// Convert the absolute path to relative path for frontend response
	relPath, _ := filepath.Rel(baseUploadDir, fullPath)

	log.Printf("createDirHandler: Created directory. Absolute: %s, Relative: %s", fullPath, relPath)

	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Directory created successfully",
		Data: map[string]string{
			"path": relPath,
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

	zipPath := filepath.Join(baseUploadDir, zipName)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		log.Printf("zipHandler: Create error - %v", err)
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

	relZipPath, _ := filepath.Rel(baseUploadDir, zipPath)

	sendJSON(w, http.StatusOK, Response{
		Success: true,
		Message: "Zip created successfully",
		Data: map[string]string{
			"path": relZipPath,
		},
	})
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

	err := filepath.Walk(baseUploadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if strings.Contains(strings.ToLower(info.Name()), strings.ToLower(query)) {
			relPath, _ := filepath.Rel(baseUploadDir, path)

			results = append(results, FileInfo{
				Name:        info.Name(),
				Path:        relPath,
				Size:        info.Size(),
				IsDir:       info.IsDir(),
				ModTime:     info.ModTime(),
				Permissions: info.Mode().String(),
			})
		}

		return nil
	})

	if err != nil {
		log.Printf("searchHandler: Walk error - %v", err)
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
