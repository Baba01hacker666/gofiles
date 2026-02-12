# Security Documentation

## Overview
This file manager implements multiple layers of security to protect against common web vulnerabilities and attacks.

## Implemented Security Features

### 1. Authentication & Session Management

#### Session-Based Authentication
- Secure session creation with cryptographically random IDs
- HTTPOnly cookies prevent XSS cookie theft
- SameSite=Strict prevents CSRF via cookies
- Configurable session timeout (default: 24 hours)
- Automatic session cleanup

#### Password Security
- Constant-time password comparison prevents timing attacks
- SHA-256 hashing (upgrade to bcrypt for production)
- No password in logs or responses

### 2. Input Validation & Sanitization

#### Path Traversal Prevention
```go
cleanPath := filepath.Clean(path)
if !strings.HasPrefix(cleanPath, uploadDir) {
    // Reject request
}
```
- All paths cleaned with `filepath.Clean()`
- Prefix validation ensures files stay in allowed directory
- Filename sanitization removes dangerous characters

#### File Upload Validation
- Maximum file size limit (100MB default)
- `MaxBytesReader` prevents memory exhaustion
- Filename sanitization removes `..` and path separators
- Content-Type validation possible extension

### 3. Rate Limiting

#### IP-Based Rate Limiting
- 60 requests per minute per IP
- Automatic cleanup of old entries
- Prevents brute force and DoS attacks
- Configurable limits per endpoint

```go
if v.count >= 60 {
    return false
}
```

### 4. Security Headers

#### HTTP Security Headers
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
```

**Purpose:**
- Prevent MIME sniffing attacks
- Prevent clickjacking
- Enable browser XSS protection
- Restrict resource loading
- Force HTTPS (when enabled)

### 5. CSRF Protection

#### Token-Based CSRF Prevention
- Unique CSRF token per session
- Token required for state-changing operations
- Tokens expire with session

### 6. Access Control

#### Authorization Checks
- All protected endpoints require valid session
- Session validation on every request
- Automatic session expiration

### 7. Error Handling

#### Secure Error Messages
- Generic error messages to users
- Detailed errors only in server logs
- No stack traces exposed to clients
- No sensitive information in responses

## Threat Model & Mitigations

### 1. Path Traversal Attack
**Threat:** Attacker tries to access files outside allowed directory
**Mitigation:** 
- Path sanitization with `filepath.Clean()`
- Prefix validation
- Whitelist approach for allowed directories

### 2. Arbitrary File Upload
**Threat:** Attacker uploads malicious files
**Mitigation:**
- File size limits
- Filename sanitization
- Consider: File type validation, virus scanning

### 3. Cross-Site Scripting (XSS)
**Threat:** Inject malicious JavaScript
**Mitigation:**
- Content-Type headers
- CSP headers
- HTML escaping in frontend
- HTTPOnly cookies

### 4. Cross-Site Request Forgery (CSRF)
**Threat:** Trick user into unwanted actions
**Mitigation:**
- CSRF tokens
- SameSite cookies
- Origin validation

### 5. Brute Force Attacks
**Threat:** Password guessing attacks
**Mitigation:**
- Rate limiting
- Account lockout (to implement)
- Strong password requirements (to implement)

### 6. Session Hijacking
**Threat:** Steal or guess session IDs
**Mitigation:**
- Cryptographically random session IDs
- HTTPOnly cookies
- Secure cookies (when HTTPS enabled)
- Session expiration

### 7. Denial of Service (DoS)
**Threat:** Overwhelm server resources
**Mitigation:**
- Rate limiting
- File size limits
- Request body size limits
- Connection timeouts

### 8. Information Disclosure
**Threat:** Leak sensitive information
**Mitigation:**
- Generic error messages
- No stack traces
- Secure logging
- No directory listing

## Production Security Checklist

### Critical (Must Implement)

- [ ] **Enable HTTPS**
  ```go
  http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
  ```

- [ ] **Use bcrypt for passwords**
  ```go
  import "golang.org/x/crypto/bcrypt"
  hash, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
  ```

- [ ] **Store credentials in database**
  - PostgreSQL, MySQL, or MongoDB
  - Never hardcode credentials

- [ ] **Use environment variables**
  ```bash
  export DB_PASSWORD=secure_password
  export SESSION_SECRET=random_secret
  ```

- [ ] **Add comprehensive logging**
  - All authentication attempts
  - All file operations
  - Security events
  - Use structured logging (JSON)

### Important (Should Implement)

- [ ] **File type validation**
  ```go
  allowed := map[string]bool{
      "image/jpeg": true,
      "image/png": true,
      "application/pdf": true,
  }
  ```

- [ ] **Virus scanning**
  - ClamAV integration
  - Scan on upload

- [ ] **Account lockout**
  - Lock after N failed attempts
  - Time-based unlock

- [ ] **Audit logging**
  - Who did what, when
  - Tamper-proof logs

- [ ] **Database for sessions**
  - Redis for session storage
  - Enables distributed deployment

### Recommended (Nice to Have)

- [ ] **Two-factor authentication**
- [ ] **Password complexity requirements**
- [ ] **User roles and permissions**
- [ ] **File encryption at rest**
- [ ] **Backup and disaster recovery**
- [ ] **Security monitoring and alerts**
- [ ] **Penetration testing**
- [ ] **Content Security Policy refinement**

## Code Security Best Practices

### 1. Input Validation
```go
// Always validate and sanitize
func validateFilename(name string) error {
    if name == "" {
        return errors.New("empty filename")
    }
    if strings.Contains(name, "..") {
        return errors.New("invalid filename")
    }
    if len(name) > 255 {
        return errors.New("filename too long")
    }
    return nil
}
```

### 2. Error Handling
```go
// Don't expose internal errors
if err != nil {
    log.Printf("Internal error: %v", err)
    sendJSON(w, 500, Response{
        Success: false,
        Message: "Internal server error",
    })
    return
}
```

### 3. Constant-Time Comparison
```go
// Prevent timing attacks
if subtle.ConstantTimeCompare(expected, provided) != 1 {
    return false
}
```

### 4. Safe File Operations
```go
// Use filepath.Join for paths
path := filepath.Join(baseDir, userInput)

// Always clean paths
path = filepath.Clean(path)

// Validate before use
if !strings.HasPrefix(path, baseDir) {
    return errors.New("invalid path")
}
```

## Security Testing

### Manual Testing Checklist

1. **Authentication**
   - [ ] Test login with correct credentials
   - [ ] Test login with incorrect credentials
   - [ ] Test session expiration
   - [ ] Test concurrent sessions

2. **Path Traversal**
   - [ ] Try `../` in file paths
   - [ ] Try absolute paths
   - [ ] Try URL encoding
   - [ ] Try null bytes

3. **File Upload**
   - [ ] Upload normal files
   - [ ] Upload large files
   - [ ] Upload files with special names
   - [ ] Upload executable files

4. **Rate Limiting**
   - [ ] Send rapid requests
   - [ ] Verify 429 responses
   - [ ] Test from multiple IPs

5. **CSRF**
   - [ ] Try requests without session
   - [ ] Try requests with invalid tokens
   - [ ] Test SameSite cookie behavior

### Automated Testing Tools

- **OWASP ZAP** - Web application scanner
- **Burp Suite** - Security testing platform
- **SQLMap** - SQL injection testing
- **Nikto** - Web server scanner
- **GoSec** - Go security checker

```bash
# Run GoSec
gosec ./...

# Run Go vet
go vet ./...
```

## Incident Response

### Detection
1. Monitor logs for suspicious patterns
2. Set up alerts for security events
3. Regular security audits

### Response
1. Isolate affected systems
2. Investigate the incident
3. Contain the damage
4. Eradicate the threat
5. Recover systems
6. Document lessons learned

## Compliance Considerations

### Data Protection
- GDPR compliance for EU users
- CCPA compliance for California users
- Data retention policies
- Right to deletion

### Access Logs
- Keep logs for audit purposes
- Protect log integrity
- Regular log review

## Security Updates

### Dependencies
```bash
# Check for updates
go list -u -m all

# Update dependencies
go get -u ./...
go mod tidy
```

### Stay Informed
- Subscribe to security mailing lists
- Monitor CVE databases
- Follow Go security announcements
- Regular dependency audits

## Contact

For security issues, please report responsibly.

---

**Remember:** Security is a process, not a product. Regular updates, monitoring, and testing are essential.
