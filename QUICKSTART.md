# QUICK START GUIDE

## 🚀 Get Started in 3 Steps

### Step 1: Extract
```bash
git clone https://github.com/Baba01hacker666/gofiles
cd gofiles
```

### Step 2: Build
```bash
chmod +x build.sh
./build.sh
```

**OR manually:**
```bash
cd server
go build -o ../filemanager main.go
cd ..
```

### Step 3: Run
```bash
./filemanager
```

Open your browser to: **http://localhost:8080**

**Default Login:**
- Username: `admin`
- Password: **Check server logs** for auto-generated password (or set via `ADMIN_PASSWORD` env var)

---

## 📁 What You Get

✅ **Full file manager** with web interface
✅ **Secure authentication** and session management  
✅ **Upload/download** files with drag & drop
✅ **Create folders** and organize files
✅ **Rename & delete** files and folders
✅ **Create zip archives** from multiple files
✅ **Search** through all your files
✅ **Rate limiting** and security headers
✅ **Responsive design** for desktop and mobile

---

## 🎯 Common Actions

### Upload Files
1. Click "Upload" button (or Ctrl+U)
2. Drag files or click "Select Files"
3. Files upload automatically

### Create Folder
1. Click "New Folder" (or Ctrl+N)
2. Enter folder name
3. Click "Create"

### Delete Files
1. Check boxes next to files
2. Click "Delete" (or press Delete key)
3. Confirm deletion

### Create Zip Archive
1. Select multiple files
2. Click "Zip" button
3. Enter archive name
4. Zip appears in current folder

---

## ⚙️ Configuration

Default settings in `main.go`:
- **Port**: 8080
- **Max Upload**: 100MB
- **Rate Limit**: 60 requests/minute
- **Upload Dir**: ./uploads
- **Session Timeout**: 24 hours

---

## 🔐 Security Features

- ✅ Session-based authentication
- ✅ CSRF protection
- ✅ Rate limiting (prevents brute force)
- ✅ Path traversal prevention
- ✅ Input sanitization
- ✅ Security headers (HSTS, CSP, etc.)
- ✅ HTTPOnly cookies
- ✅ File size limits

---

## 📖 Documentation

- **README.md** - Full documentation
- **SECURITY.md** - Security implementation
- **TESTING.md** - Testing procedures
- **PROJECT.md** - Project structure

---

## 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t filemanager .
docker run -p 8080:8080 -v $(pwd)/uploads:/app/uploads filemanager
```

---

## 🔧 Troubleshooting

**Port already in use:**
```bash
lsof -i :8080
kill -9 [PID]
```

**Permission denied:**
```bash
chmod 755 uploads/
```

**Go not installed:**
```bash
# Install Go from https://golang.org/dl/
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

---

## ⚠️ Production Checklist

Before deploying to production:
- [ ] Set a strong password via environment variables
- [ ] Enable HTTPS (configure TLS)
- [ ] Use environment variables for secrets
- [ ] Set up proper database for users
- [ ] Configure firewall rules
- [ ] Enable comprehensive logging
- [ ] Set up automated backups
- [ ] Review SECURITY.md thoroughly

---

## 🎮 Keyboard Shortcuts

- `Ctrl/Cmd + U` - Upload files
- `Ctrl/Cmd + N` - New folder  
- `Ctrl/Cmd + R` - Refresh
- `Delete` - Delete selected files
- `Escape` - Close modals

---

## 📊 Project Stats

- **Go code**: 850+ lines
- **JavaScript**: 800+ lines
- **CSS**: 700+ lines
- **HTML**: 220+ lines
- **Total**: 4500+ lines of code
- **Documentation**: 2000+ lines

---

## 🌟 Features Highlight

**File Operations:**
- Multi-file upload with progress
- Drag and drop support
- Folder creation and navigation
- File/folder rename and delete
- Zip archive creation
- Real-time file search
- Download individual files

**Security:**
- Session authentication
- Rate limiting
- CSRF protection
- Path sanitization
- Secure headers
- Input validation

**UI/UX:**
- Modern, clean design
- Responsive (mobile-friendly)
- Toast notifications
- Progress indicators
- Keyboard shortcuts
- Breadcrumb navigation

---

## 💡 Tips

1. **First time?** Start with small files to test upload
2. **Multiple files?** Use drag & drop for quick upload
3. **Organizing?** Create folders before uploading
4. **Large files?** Be patient, progress shown in real-time
5. **Finding files?** Use search box for instant filtering
6. **Quick delete?** Select files and press Delete key
7. **Archive files?** Select multiple and create zip

---

## 🚨 Security Notes

- No default password! Use the auto-generated one from server logs or set `ADMIN_PASSWORD`.
- Designed for **trusted environments** by default
- For internet-facing deployment, review **SECURITY.md**
- Always use HTTPS in production
- Consider implementing 2FA for sensitive use

---

## 📞 Need Help?

Check the documentation:
1. README.md - Complete guide
2. SECURITY.md - Security details
3. TESTING.md - Testing guide
4. PROJECT.md - Architecture overview

---

**Enjoy your secure file manager! 🎉**

Built with ❤️ for security and usability.
