# Secure File Manager

A professional, full-featured file manager with Go backend and modern web interface.

## Features

### Security
- **Session-based Authentication** - Secure login with session management
- **CSRF Protection** - Built-in CSRF token validation
- **Rate Limiting** - 60 requests/minute per IP
- **Path Traversal Prevention** - Sanitized file paths
- **Security Headers** - HSTS, CSP, X-Frame-Options, etc.
- **Input Validation** - All inputs sanitized and validated
- **Secure File Operations** - Protected upload/download/delete operations

### File Operations
- **Upload Files** - Drag & drop or click to upload (max 100MB)
- **Download Files** - Single file download
- **Delete Files/Folders** - Bulk delete support
- **Rename** - Rename files and folders
- **Create Folders** - Organize files in directories
- **Zip Creation** - Create archives from selected files
- **Search** - Real-time file search
- **Browse** - Navigate directory structure

### User Interface
- **Modern Design** - Clean, professional interface
- **Responsive** - Works on desktop and mobile
- **Keyboard Shortcuts** - Quick access to common actions
- **Drag & Drop** - Easy file uploads
- **Progress Indicators** - Real-time upload progress
- **Toast Notifications** - User-friendly feedback
- **File Icons** - Visual file/folder distinction
- **Breadcrumb Navigation** - Easy path navigation

## Installation

### Prerequisites
- Go 1.16 or higher
- Modern web browser

### Setup

1. **Extract the project**
   ```bash
   git clone https://github.com/Baba01hacker666/gofiles
   cd gofiles
   ```

2. **Build the server**
   ```bash
   cd server
   go build -o filemanager main.go
   ```

3. **Run the server**
   ```bash
   ./filemanager
   ```

4. **Access the application**
   - Open browser to: http://localhost:8080
   - Default credentials: `admin` / `admin`

## Usage

### Login
- Username: `admin`
- Password: `admin`

**⚠️ IMPORTANT**: Change the default password in production by modifying the authentication logic in `main.go`

### Keyboard Shortcuts
- `Ctrl/Cmd + U` - Upload files
- `Ctrl/Cmd + N` - New folder
- `Ctrl/Cmd + R` - Refresh
- `Delete` - Delete selected
- `Escape` - Close modals

### File Operations

#### Upload
1. Click "Upload" button or use `Ctrl+U`
2. Drag files or click to browse
3. Files upload automatically

#### Create Folder
1. Click "New Folder" or use `Ctrl+N`
2. Enter folder name
3. Click "Create"

#### Delete
1. Select files/folders using checkboxes
2. Click "Delete" button
3. Confirm deletion

#### Rename
1. Click "Rename" button on file row
2. Enter new name
3. Click "Rename"

#### Download
1. Select a single file
2. Click "Download" button

#### Zip
1. Select multiple files/folders
2. Click "Zip" button
3. Enter archive name
4. Zip file created in current directory

#### Search
1. Type in search box
2. Results filter in real-time
3. Clear search to return to normal view

## Security Considerations

### Production Deployment

1. **Enable HTTPS**
   - Modify `main.go` to use `http.ListenAndServeTLS()`
   - Set cookie `Secure` flag to `true`

2. **Change Default Credentials**
   - Replace hardcoded credentials with database
   - Use bcrypt for password hashing

3. **Environment Variables**
   - Store secrets in environment variables
   - Use `.env` file or secrets manager

4. **Database Integration**
   - Replace in-memory session storage
   - Use Redis or database for sessions

5. **File Upload Restrictions**
   - Add file type validation
   - Implement virus scanning
   - Configure max file sizes per user

6. **Logging**
   - Add comprehensive logging
   - Monitor suspicious activities
   - Log all file operations

7. **Backup**
   - Implement automated backups
   - Store backups off-site

### Security Headers
The application sets the following security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy`
- `Strict-Transport-Security`

### Rate Limiting
- 60 requests per minute per IP
- Automatic cleanup of old entries
- Configurable in `main.go`

## Architecture

### Backend (Go)
```
server/
└── main.go          # Main server with all endpoints
```

**Endpoints:**
- `POST /api/login` - Authentication
- `GET /api/files` - List files
- `POST /api/upload` - Upload file
- `GET /api/download` - Download file
- `DELETE /api/delete` - Delete file/folder
- `POST /api/rename` - Rename file/folder
- `POST /api/mkdir` - Create directory
- `POST /api/zip` - Create zip archive
- `GET /api/search` - Search files

### Frontend
```
static/
├── index.html       # Main HTML
├── css/
│   └── style.css    # Styles
└── js/
    └── app.js       # JavaScript application
```

### Data Flow
1. User authenticates via login form
2. Server creates session and returns cookie
3. Frontend makes authenticated API calls
4. Server validates session and processes requests
5. Results returned as JSON
6. Frontend updates UI accordingly

## Configuration

### Upload Limits
Edit in `main.go`:
```go
const maxUploadSize = 100 * 1024 * 1024 // 100MB
```

### Rate Limits
Edit in `main.go`:
```go
if v.count >= 60 { // 60 requests per minute
    return false
}
```

### Session Timeout
Edit in `main.go`:
```go
ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours
```

### Upload Directory
Edit in `main.go`:
```go
const uploadDir = "./uploads"
```

## API Reference

### Authentication

**POST /api/login**
```json
Request:
{
  "username": "admin",
  "password": "admin"
}

Response:
{
  "success": true,
  "message": "Login successful",
  "data": {
    "csrf_token": "..."
  }
}
```

### List Files

**GET /api/files?path=./uploads**
```json
Response:
{
  "success": true,
  "data": [
    {
      "name": "file.txt",
      "path": "./uploads/file.txt",
      "size": 1024,
      "isDir": false,
      "modTime": "2024-01-01T00:00:00Z",
      "permissions": "-rw-r--r--"
    }
  ]
}
```

### Upload File

**POST /api/upload**
- Content-Type: multipart/form-data
- Body: file field with file data

### Delete File

**DELETE /api/delete?path=./uploads/file.txt**

### Rename File

**POST /api/rename**
```json
{
  "oldPath": "./uploads/old.txt",
  "newName": "new.txt"
}
```

### Create Directory

**POST /api/mkdir**
```json
{
  "path": "./uploads",
  "name": "newfolder"
}
```

### Create Zip

**POST /api/zip**
```json
{
  "paths": ["./uploads/file1.txt", "./uploads/file2.txt"],
  "name": "archive.zip"
}
```

### Search Files

**GET /api/search?query=document**

## Browser Support
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

## License
MIT License - Free for personal and commercial use

## Contributing
This is a standalone project. Feel free to fork and modify.

## Support
For issues or questions, refer to the code comments and security best practices.

---

**⚠️ Security Notice**: This application is designed for trusted environments. For production use with untrusted users, implement additional security measures including user authentication via database, HTTPS, input validation, file type restrictions, and comprehensive logging.
