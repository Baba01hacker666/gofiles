package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// generateTwoKeys produces two independent tokens from a single 48-byte
// crypto/rand read (one syscall instead of two).
func generateTwoKeys() (string, string) {
	b := make([]byte, 48) // 24 bytes → 32 base64 chars each
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b[:24]),
		base64.URLEncoding.EncodeToString(b[24:])
}

// ---------------------------------------------------------------------------
// Pooled I/O buffers
// ---------------------------------------------------------------------------

var copyBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 256*1024) // 256 KB
		return &buf
	},
}

// pooledCopy is like io.Copy but uses a pooled 256 KB buffer instead of the
// default 32 KB, reducing syscall count for large transfers.
func pooledCopy(dst io.Writer, src io.Reader) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}

// ---------------------------------------------------------------------------
// Filename sanitisation
// ---------------------------------------------------------------------------

// sanitizeName normalises a user-supplied file or directory name.
// It converts backslashes to forward slashes (defending against Windows-style
// absolute paths like C:\Windows\System32\cmd.exe on a Linux host where
// filepath.Base would not strip the backslash path), then applies filepath.Base
// to collapse any remaining directory components. It rejects ".", "..",
// empty strings and trailing slashes.
func sanitizeName(name string) (string, error) {
	// Normalise backslashes to forward slashes so filepath.Base works uniformly
	normalised := strings.ReplaceAll(name, "\\", "/")

	// Strip any trailing slashes so filepath.Base doesn't return "."
	normalised = strings.TrimRight(normalised, "/")

	if normalised == "" {
		return "", fmt.Errorf("empty name")
	}

	cleaned := filepath.Base(normalised)

	if cleaned == "." || cleaned == ".." || cleaned == string(filepath.Separator) {
		return "", fmt.Errorf("invalid name: %s", name)
	}

	return cleaned, nil
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

// validatePath prevents path doubling and path traversal.
func validatePath(requestPath string) (string, error) {
	// Clean the request path
	cleanedRequestPath := filepath.Clean(requestPath)

	// If the path already contains the full absolute path, extract just the relative part
	if strings.HasPrefix(cleanedRequestPath, baseUploadDir) {
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
		return baseUploadDir, nil
	}

	// Build target path relative to uploads directory
	targetPath := filepath.Join(baseUploadDir, cleanedRequestPath)

	// Resolve to absolute path
	cleanPath, err := filepath.Abs(targetPath)
	if err != nil {
		return "", err
	}

	// Ensure the resolved path is within the upload directory
	if cleanPath != baseUploadDir && !strings.HasPrefix(cleanPath, baseUploadDir+string(filepath.Separator)) {
		return "", nil
	}

	return cleanPath, nil
}

// ---------------------------------------------------------------------------
// Zip helpers
// ---------------------------------------------------------------------------

func addToZip(zipWriter *zip.Writer, filename, baseDir string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return filepath.WalkDir(filename, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
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
	// Sanitize zip entry path to prevent zip slip attacks
	cleanZipPath := filepath.Clean(zipPath)
	if strings.HasPrefix(cleanZipPath, "..") || strings.HasPrefix(cleanZipPath, "/") {
		return fmt.Errorf("invalid zip entry path: %s", zipPath)
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer, err := zipWriter.Create(cleanZipPath)
	if err != nil {
		return err
	}

	_, err = pooledCopy(writer, file)
	return err
}

// ---------------------------------------------------------------------------
// JSON response helper
// ---------------------------------------------------------------------------

func sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if b, err := json.Marshal(data); err == nil {
		w.Write(b)
		w.Write([]byte{'\n'})
	}
}
