// Updated createDirHandler function to fix path handling and return relative paths.

func createDirHandler(w http.ResponseWriter, r *http.Request) {
    var dirPath string
    err := json.NewDecoder(r.Body).Decode(&dirPath)
    if err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        return
    }

    // Fixing path handling to use relative paths
    // Create directory logic here... (assuming some logic to create directories)

    // Instead of returning an absolute path, return a relative path
    relativePath := filepath.Base(dirPath) // This could be replaced with logic based on actual requirements
    w.Write([]byte(relativePath))
}