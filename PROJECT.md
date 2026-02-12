# File Manager Project Structure

```
filemanager/
├── server/
│   ├── main.go              # Main Go server with all functionality
│   └── go.mod               # Go module file
│
├── static/
│   ├── index.html           # Main HTML interface
│   ├── css/
│   │   └── style.css        # Complete styling
│   └── js/
│       └── app.js           # JavaScript application logic
│
├── uploads/                 # File upload directory
│   └── .gitkeep            # Keep directory in git
│
├── README.md               # Main documentation
├── SECURITY.md             # Security documentation
├── TESTING.md              # Testing guide
├── build.sh                # Build script
├── config.example.json     # Configuration example
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Docker build file
├── filemanager.service     # SystemD service file
└── .gitignore             # Git ignore file
```

## File Descriptions

### Backend (Go)
- **server/main.go** (850+ lines)
  - HTTP server implementation
  - Authentication & session management
  - Rate limiting
  - File operations (upload, download, delete, rename)
  - Folder management
  - Zip creation
  - Search functionality
  - Security middleware
  - CSRF protection
  - Path traversal prevention

### Frontend (HTML/CSS/JS)
- **static/index.html** (220+ lines)
  - Login interface
  - File browser
  - Upload modal
  - Rename modal
  - New folder modal
  - Breadcrumb navigation
  - Responsive layout

- **static/css/style.css** (700+ lines)
  - Modern design system
  - Responsive breakpoints
  - Animation & transitions
  - Component styling
  - Theme variables
  - Dark/light compatible

- **static/js/app.js** (800+ lines)
  - Application state management
  - API communication
  - File operations
  - Drag & drop upload
  - Real-time search
  - Modal management
  - Keyboard shortcuts
  - Toast notifications
  - Error handling

### Documentation
- **README.md** - Comprehensive usage guide
- **SECURITY.md** - Security implementation details
- **TESTING.md** - Testing procedures & checklists

### Deployment
- **Dockerfile** - Container build configuration
- **docker-compose.yml** - Container orchestration
- **filemanager.service** - SystemD service
- **build.sh** - Build automation script
- **config.example.json** - Configuration template

## Key Features

### Security ✅
- Session-based authentication
- CSRF token protection
- Rate limiting (60 req/min)
- Path traversal prevention
- Input sanitization
- Security headers (CSP, HSTS, etc.)
- HTTPOnly cookies
- Constant-time password comparison

### File Operations ✅
- Upload files (drag & drop)
- Download files
- Delete files/folders
- Rename files/folders
- Create folders
- Create zip archives
- Search files
- Browse directories

### User Experience ✅
- Modern, clean interface
- Responsive design
- Real-time feedback
- Progress indicators
- Toast notifications
- Keyboard shortcuts
- Drag & drop support
- Breadcrumb navigation

## Technology Stack

**Backend:**
- Go 1.21
- Standard library only (no external dependencies)
- HTTP server with middleware
- Session management
- File system operations

**Frontend:**
- Vanilla JavaScript (no frameworks)
- Modern CSS (CSS Variables, Grid, Flexbox)
- HTML5
- Responsive design

**Deployment:**
- Docker support
- SystemD integration
- Standalone binary
- Cross-platform (Linux, macOS, Windows)

## Quick Start

```bash
# 1. Extract files
unzip filemanager.zip
cd filemanager

# 2. Build
cd server
go build -o ../filemanager main.go
cd ..

# 3. Run
./filemanager

# 4. Access
# Open http://localhost:8080
# Login: admin / admin
```

## Production Deployment

See README.md for:
- HTTPS configuration
- Database integration
- Environment variables
- Security hardening
- Monitoring setup

## File Sizes (Approximate)

- server/main.go: ~25 KB
- static/index.html: ~10 KB
- static/css/style.css: ~17 KB
- static/js/app.js: ~22 KB
- Documentation: ~50 KB
- Total: ~125 KB (excluding uploads)

## Code Statistics

- Go code: ~850 lines
- JavaScript: ~800 lines
- HTML: ~220 lines
- CSS: ~700 lines
- Documentation: ~2000 lines
- **Total: ~4500+ lines**

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers

## Security Compliance

- OWASP Top 10 protection
- Input validation
- Output encoding
- Authentication
- Session management
- Access control
- Error handling
- Logging capability

## License

MIT License - Free for personal and commercial use

## Credits

Built with security and user experience in mind.
Designed for professional use in trusted environments.

---

For questions, refer to README.md, SECURITY.md, and TESTING.md
