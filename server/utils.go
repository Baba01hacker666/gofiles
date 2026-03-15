package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// FIXED: validatePath function - prevents path doubling issue
func validatePath(requestPath string) (string, error) {
	baseUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		return "", err
	}

	log.Printf("validatePath input: %s, baseUploadDir: %s", requestPath, baseUploadDir)

	// Clean the request path
	cleanedRequestPath := filepath.Clean(requestPath)

	// If the path already contains the full absolute path, extract just the relative part
	if strings.Contains(cleanedRequestPath, baseUploadDir) {
		log.Printf("Path already contains absolute path, extracting relative part")
		// Remove the base upload dir from the path
		cleanedRequestPath = strings.TrimPrefix(cleanedRequestPath, baseUploadDir)
		cleanedRequestPath = strings.TrimPrefix(cleanedRequestPath, string(filepath.Separator))
	}

	// Normalize the path - remove leading ./ and uploads/
	cleanedRequestPath = strings.TrimPrefix(cleanedRequestPath, "./")
	cleanedRequestPath = strings.TrimPrefix(cleanedRequestPath, "uploads/")
	cleanedRequestPath = strings.TrimPrefix(cleanedRequestPath, "uploads")
	cleanedRequestPath = strings.TrimPrefix(cleanedRequestPath, string(filepath.Separator))

	// Handle empty path (root uploads directory)
	if cleanedRequestPath == "" || cleanedRequestPath == "." {
		log.Printf("validatePath returning base upload dir")
		return baseUploadDir, nil
	}

	// Build target path relative to uploads directory
	targetPath := filepath.Join(baseUploadDir, cleanedRequestPath)

	log.Printf("validatePath targetPath: %s", targetPath)

	// Resolve to absolute path
	cleanPath, err := filepath.Abs(targetPath)
	if err != nil {
		return "", err
	}

	log.Printf("validatePath cleanPath: %s", cleanPath)

	// Ensure the resolved path is within the upload directory
	// Use proper path separator checking
	if cleanPath != baseUploadDir && !strings.HasPrefix(cleanPath, baseUploadDir+string(filepath.Separator)) {
		log.Printf("Security: Path traversal attempt denied. Base: %s, Tried: %s", baseUploadDir, cleanPath)
		return "", nil
	}

	log.Printf("validatePath returning: %s", cleanPath)
	return cleanPath, nil
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

func sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
