# Testing Guide

## Prerequisites
- Go 1.16 or higher installed
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Terminal/Command line access

## Quick Start

### 1. Build the Application
```bash
cd server
go build -o ../filemanager main.go
cd ..
```

Or use the build script:
```bash
chmod +x build.sh
./build.sh
```

### 2. Run the Application
```bash
./filemanager
```

You should see:
```
API Key (for reference): [random-key]
Default credentials: admin / admin
Server starting on http://localhost:8080
```

### 3. Access the Application
Open your browser to: **http://localhost:8080**

### 4. Login
- Username: `admin`
- Password: `admin`

## Feature Testing

### Upload Files
1. Click "Upload" button
2. Drag files into the upload area OR click "Select Files"
3. Watch upload progress
4. Files appear in the list

**Test cases:**
- Small files (< 1MB)
- Medium files (1-10MB)
- Large files (10-100MB)
- Multiple files at once
- Files with special characters in names

### Create Folder
1. Click "New Folder"
2. Enter folder name
3. Click "Create"
4. Folder appears in list

**Test cases:**
- Simple names (folder1, test)
- Names with spaces (My Documents)
- Names with special chars (files_2024)

### Navigate Folders
1. Click on folder name
2. Breadcrumb updates
3. Contents shown
4. Click breadcrumb to go back

### Delete Files
1. Check boxes next to files
2. Click "Delete"
3. Confirm deletion
4. Files removed

**Test cases:**
- Single file
- Multiple files
- Empty folder
- Folder with contents

### Rename Files
1. Click "Rename" on file row
2. Enter new name
3. Click "Rename"
4. Name updates

**Test cases:**
- Change extension
- Add spaces
- Special characters

### Download Files
1. Select ONE file
2. Click "Download"
3. File downloads

**Test cases:**
- Text files
- Images
- Archives
- Large files

### Create Zip
1. Select multiple files/folders
2. Click "Zip"
3. Enter archive name
4. Zip created in current folder

**Test cases:**
- Multiple files
- Folders with subfolders
- Mix of files and folders

### Search Files
1. Type in search box
2. Results filter in real-time
3. Clear search to return

**Test cases:**
- Partial names
- Extensions (.txt, .jpg)
- Case sensitivity

## Security Testing

### Authentication
```bash
# Test without login
curl http://localhost:8080/api/files
# Should return: 401 Unauthorized

# Test with login
curl -c cookies.txt -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Use session
curl -b cookies.txt http://localhost:8080/api/files
# Should return: file list
```

### Path Traversal Prevention
```bash
# Try to access parent directory
curl -b cookies.txt "http://localhost:8080/api/files?path=../"
# Should be blocked or sanitized

# Try absolute path
curl -b cookies.txt "http://localhost:8080/api/files?path=/etc/passwd"
# Should be blocked
```

### Rate Limiting
```bash
# Send many requests rapidly
for i in {1..70}; do
  curl -s -b cookies.txt http://localhost:8080/api/files > /dev/null
  echo "Request $i"
done
# After 60 requests, should get 429 Too Many Requests
```

### File Upload Size Limit
```bash
# Create large file (over 100MB)
dd if=/dev/zero of=largefile.bin bs=1M count=101

# Try to upload
curl -b cookies.txt -F "file=@largefile.bin" http://localhost:8080/api/upload
# Should be rejected
```

## Performance Testing

### Load Testing with Apache Bench
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test file listing
ab -n 1000 -c 10 http://localhost:8080/api/files

# Results show:
# - Requests per second
# - Response times
# - Success/failure rate
```

### Load Testing with wrk
```bash
# Install wrk
sudo apt-get install wrk

# Run load test
wrk -t12 -c400 -d30s http://localhost:8080/

# Results show:
# - Throughput
# - Latency percentiles
# - Request distribution
```

## Browser Testing

### Desktop
- [ ] Chrome/Chromium 90+
- [ ] Firefox 88+
- [ ] Safari 14+ (macOS)
- [ ] Edge 90+

### Mobile
- [ ] Mobile Safari (iOS)
- [ ] Chrome Mobile (Android)
- [ ] Firefox Mobile

### Features to Test
- [ ] Responsive layout
- [ ] Touch interactions
- [ ] File upload
- [ ] Modal dialogs
- [ ] Keyboard shortcuts (desktop only)

## API Testing with Postman/Insomnia

### 1. Login
```
POST http://localhost:8080/api/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin"
}
```

### 2. List Files
```
GET http://localhost:8080/api/files?path=./uploads
Cookie: session_id=[from-login]
```

### 3. Upload File
```
POST http://localhost:8080/api/upload
Cookie: session_id=[from-login]
Content-Type: multipart/form-data

file: [select file]
```

### 4. Create Folder
```
POST http://localhost:8080/api/mkdir
Cookie: session_id=[from-login]
Content-Type: application/json

{
  "path": "./uploads",
  "name": "testfolder"
}
```

### 5. Rename
```
POST http://localhost:8080/api/rename
Cookie: session_id=[from-login]
Content-Type: application/json

{
  "oldPath": "./uploads/oldname.txt",
  "newName": "newname.txt"
}
```

### 6. Delete
```
DELETE http://localhost:8080/api/delete?path=./uploads/file.txt
Cookie: session_id=[from-login]
```

### 7. Search
```
GET http://localhost:8080/api/search?query=document
Cookie: session_id=[from-login]
```

### 8. Create Zip
```
POST http://localhost:8080/api/zip
Cookie: session_id=[from-login]
Content-Type: application/json

{
  "paths": ["./uploads/file1.txt", "./uploads/file2.txt"],
  "name": "archive.zip"
}
```

## Automated Testing

### Unit Tests (Example)
```go
// server/main_test.go
package main

import (
    "testing"
)

func TestValidatePath(t *testing.T) {
    tests := []struct {
        path     string
        expected bool
    }{
        {"./uploads/file.txt", true},
        {"../etc/passwd", false},
        {"/etc/passwd", false},
        {"./uploads/../file.txt", false},
    }
    
    for _, test := range tests {
        result := isPathSafe(test.path)
        if result != test.expected {
            t.Errorf("Path %s: got %v, want %v", 
                test.path, result, test.expected)
        }
    }
}
```

## Common Issues & Solutions

### Port Already in Use
```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 [PID]
```

### Permission Denied
```bash
# Make sure uploads directory is writable
chmod 755 uploads/

# Or run with sudo (not recommended for production)
sudo ./filemanager
```

### Go Not Found
```bash
# Install Go
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### Build Errors
```bash
# Update dependencies
cd server
go mod tidy
go mod download

# Clean build
go clean
go build -o ../filemanager main.go
```

## Logging & Debugging

### Enable Debug Logging
Modify main.go:
```go
log.SetFlags(log.LstdFlags | log.Lshortfile)
```

### View Logs in Real-time
```bash
# Linux/Mac
tail -f /var/log/filemanager.log

# Or use journalctl for systemd
journalctl -u filemanager -f
```

### Common Log Patterns
```
# Successful login
Login successful: user=admin

# Failed login
Login failed: user=admin

# File upload
File uploaded: file=document.pdf size=1024KB

# Rate limit exceeded
Rate limit exceeded: ip=192.168.1.1
```

## Performance Benchmarks

Expected performance on modern hardware:
- File listing: < 100ms for 1000 files
- File upload: Network limited
- Search: < 200ms for 10000 files
- Zip creation: Depends on file sizes

## Security Checklist

Before production deployment:
- [ ] Change default password
- [ ] Enable HTTPS
- [ ] Configure firewall
- [ ] Set up rate limiting
- [ ] Enable logging
- [ ] Configure backups
- [ ] Test all security features
- [ ] Review SECURITY.md
- [ ] Perform penetration testing

## Reporting Issues

If you find bugs:
1. Check existing documentation
2. Verify it's reproducible
3. Note exact steps to reproduce
4. Include error messages
5. Specify browser/OS versions

---

Happy testing! 🚀
