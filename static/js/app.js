// Global state
let currentPath = './uploads';
let selectedFiles = new Set();
let csrfToken = '';
let renameTarget = null;
let searchTimeout = null;

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    checkSession();
});

function initializeEventListeners() {
    // Login
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Toolbar
    document.getElementById('uploadBtn').addEventListener('click', openUploadModal);
    document.getElementById('newFolderBtn').addEventListener('click', openNewFolderModal);
    document.getElementById('refreshBtn').addEventListener('click', () => loadFiles(currentPath));
    document.getElementById('deleteBtn').addEventListener('click', handleDelete);
    document.getElementById('downloadBtn').addEventListener('click', handleDownload);
    document.getElementById('zipBtn').addEventListener('click', handleZip);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    
    // Search
    document.getElementById('searchInput').addEventListener('input', handleSearch);
    
    // Select all
    document.getElementById('selectAll').addEventListener('change', handleSelectAll);
    
    // Upload
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    fileInput.addEventListener('change', handleFileSelect);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

// Authentication
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('loginError');
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            csrfToken = data.data.csrf_token;
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('mainApp').style.display = 'flex';
            loadFiles(currentPath);
            showToast('Login successful', 'success');
        } else {
            errorEl.textContent = data.message;
            errorEl.classList.add('show');
        }
    } catch (error) {
        errorEl.textContent = 'Connection error';
        errorEl.classList.add('show');
    }
}

function handleLogout() {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('mainApp').style.display = 'none';
    selectedFiles.clear();
    currentPath = './uploads';
}

function checkSession() {
    // Check if session cookie exists
    const cookies = document.cookie.split(';');
    const hasSession = cookies.some(c => c.trim().startsWith('session_id='));
    
    if (hasSession) {
        // Try to load files to verify session
        loadFiles(currentPath).then(success => {
            if (success) {
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('mainApp').style.display = 'flex';
            }
        });
    }
}

// UPDATED loadFiles to normalize and handle paths correctly
async function loadFiles(path) {
    showLoading(true);
    
    // Normalize path
    let normalizedPath = path;
    if (!normalizedPath.startsWith('./')) {
        normalizedPath = './' + normalizedPath;
    }
    
    try {
        const response = await fetch(`/api/files?path=${encodeURIComponent(normalizedPath)}`);
        const data = await response.json();
        
        if (data.success) {
            currentPath = normalizedPath;
            renderFiles(data.data);
            updateBreadcrumb(normalizedPath);
            updateFileCount(data.data.length);
            showLoading(false);
            return true;
        } else {
            showToast(data.message, 'error');
            showLoading(false);
            return false;
        }
    } catch (error) {
        showToast('Failed to load files', 'error');
        showLoading(false);
        return false;
    }
}

// UPDATED renderFiles to show ".." (parent directory) button
function renderFiles(files) {
    const fileList = document.getElementById('fileList');
    const emptyState = document.getElementById('emptyState');
    
    selectedFiles.clear();
    updateActionButtons();
    
    if (files.length === 0 && currentPath === './uploads') {
        fileList.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }
    
    emptyState.style.display = 'none';
    
    // Sort: directories first, then by name
    files.sort((a, b) => {
        if (a.isDir && !b.isDir) return -1;
        if (!a.isDir && b.isDir) return 1;
        return a.name.localeCompare(b.name);
    });
    
    let htmlContent = '';
    
    // Add "Back/Up" button if not in root directory
    if (currentPath !== './uploads' && currentPath !== 'uploads') {
        const parentPath = currentPath.split('/').slice(0, -1).join('/');
        const validParentPath = parentPath || './uploads';
        htmlContent += `
            <tr style="background-color: var(--bg-tertiary);">
                <td></td>
                <td>
                    <div class="file-name" onclick="loadFiles('${escapeHtml(validParentPath)}')" style="font-weight: bold; color: var(--primary-color);">
                        📁 .. (Back)
                    </div>
                </td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td></td>
            </tr>
        `;
    }
    
    htmlContent += files.map(file => `
        <tr data-path="${escapeHtml(file.path)}">
            <td>
                <input type="checkbox" class="file-checkbox" data-path="${escapeHtml(file.path)}">
            </td>
            <td>
                <div class="file-name" onclick="handleFileClick('${escapeHtml(file.path)}', ${file.isDir})">
                    ${getFileIcon(file)}
                    <span>${escapeHtml(file.name)}</span>
                </div>
            </td>
            <td>${file.isDir ? '-' : formatFileSize(file.size)}</td>
            <td>${formatDate(file.modTime)}</td>
            <td><code>${file.permissions}</code></td>
            <td>
                <button class="btn action-btn" onclick="handleRename('${escapeHtml(file.path)}')">Rename</button>
            </td>
        </tr>
    `).join('');
    
    fileList.innerHTML = htmlContent;
    
    // Add checkbox listeners
    document.querySelectorAll('.file-checkbox').forEach(cb => {
        cb.addEventListener('change', handleFileSelection);
    });
}

function getFileIcon(file) {
    if (file.isDir) {
        return `<svg class="file-icon folder-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
        </svg>`;
    }
    
    return `<svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
        <polyline points="13 2 13 9 20 9"></polyline>
    </svg>`;
}

// UPDATED handleFileClick to properly handle paths
function handleFileClick(path, isDir) {
    if (isDir) {
        // Normalize path for loading
        let normalizedPath = path;
        if (!normalizedPath.startsWith('./')) {
            normalizedPath = './' + normalizedPath;
        }
        loadFiles(normalizedPath);
    }
}

function handleFileSelection(e) {
    const path = e.target.dataset.path;
    const row = e.target.closest('tr');
    
    if (e.target.checked) {
        selectedFiles.add(path);
        row.classList.add('selected');
    } else {
        selectedFiles.delete(path);
        row.classList.remove('selected');
    }
    
    updateActionButtons();
}

function handleSelectAll(e) {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = e.target.checked;
        cb.dispatchEvent(new Event('change'));
    });
}

function updateActionButtons() {
    const hasSelection = selectedFiles.size > 0;
    document.getElementById('deleteBtn').disabled = !hasSelection;
    document.getElementById('downloadBtn').disabled = selectedFiles.size !== 1;
    document.getElementById('zipBtn').disabled = !hasSelection;
}

// Upload
function openUploadModal() {
    document.getElementById('uploadModal').classList.add('show');
}

function closeUploadModal() {
    document.getElementById('uploadModal').classList.remove('show');
    document.getElementById('uploadList').innerHTML = '';
}

function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.currentTarget.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    
    const files = Array.from(e.dataTransfer.files);
    uploadFiles(files);
}

function handleFileSelect(e) {
    const files = Array.from(e.target.files);
    uploadFiles(files);
}

// UPDATED uploadFiles to include current path
async function uploadFiles(files) {
    const uploadList = document.getElementById('uploadList');
    
    for (const file of files) {
        const uploadItem = createUploadItem(file);
        uploadList.appendChild(uploadItem);
        
        const formData = new FormData();
        formData.append('file', file);
        formData.append('path', currentPath);  // ADD CURRENT PATH!
        
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                updateUploadItem(uploadItem, 100, 'success');
                showToast(`${file.name} uploaded`, 'success');
            } else {
                updateUploadItem(uploadItem, 0, 'error');
                showToast(`Failed to upload ${file.name}`, 'error');
            }
        } catch (error) {
            updateUploadItem(uploadItem, 0, 'error');
            showToast(`Failed to upload ${file.name}`, 'error');
        }
    }
    
    setTimeout(() => {
        closeUploadModal();
        loadFiles(currentPath);
    }, 1000);
}

function createUploadItem(file) {
    const div = document.createElement('div');
    div.className = 'upload-item';
    div.innerHTML = `
        <div class="upload-item-info">
            <div>
                <div class="upload-item-name">${escapeHtml(file.name)}</div>
                <div class="upload-item-size">${formatFileSize(file.size)}</div>
            </div>
        </div>
        <div class="upload-progress">
            <div class="upload-progress-bar" style="width: 0%"></div>
        </div>
        <div class="upload-status">Uploading...</div>
    `;
    return div;
}

function updateUploadItem(item, progress, status) {
    const progressBar = item.querySelector('.upload-progress-bar');
    const statusEl = item.querySelector('.upload-status');
    
    progressBar.style.width = `${progress}%`;
    
    if (status === 'success') {
        statusEl.textContent = 'Complete';
        statusEl.style.color = 'var(--success-color)';
    } else if (status === 'error') {
        statusEl.textContent = 'Failed';
        statusEl.style.color = 'var(--danger-color)';
    }
}

// Download
async function handleDownload() {
    if (selectedFiles.size !== 1) return;
    
    const path = Array.from(selectedFiles)[0];
    window.location.href = `/api/download?path=${encodeURIComponent(path)}`;
}

// Delete
async function handleDelete() {
    if (selectedFiles.size === 0) return;
    
    if (!confirm(`Delete ${selectedFiles.size} item(s)?`)) return;
    
    showLoading(true);
    
    for (const path of selectedFiles) {
        try {
            const response = await fetch(`/api/delete?path=${encodeURIComponent(path)}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (!data.success) {
                showToast(`Failed to delete ${path}`, 'error');
            }
        } catch (error) {
            showToast(`Failed to delete ${path}`, 'error');
        }
    }
    
    selectedFiles.clear();
    loadFiles(currentPath);
    showToast('Items deleted', 'success');
}

// Rename
function handleRename(path) {
    renameTarget = path;
    const filename = path.split('/').pop();
    document.getElementById('renameInput').value = filename;
    document.getElementById('renameModal').classList.add('show');
}

function closeRenameModal() {
    document.getElementById('renameModal').classList.remove('show');
    renameTarget = null;
}

async function confirmRename() {
    const newName = document.getElementById('renameInput').value.trim();
    
    if (!newName) {
        showToast('Name cannot be empty', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/rename', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                oldPath: renameTarget,
                newName: newName
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Renamed successfully', 'success');
            closeRenameModal();
            loadFiles(currentPath);
        } else {
            showToast(data.message, 'error');
        }
    } catch (error) {
        showToast('Failed to rename', 'error');
    }
}

// New Folder
function openNewFolderModal() {
    document.getElementById('folderNameInput').value = '';
    document.getElementById('newFolderModal').classList.add('show');
}

function closeNewFolderModal() {
    document.getElementById('newFolderModal').classList.remove('show');
}

async function confirmNewFolder() {
    const name = document.getElementById('folderNameInput').value.trim();
    
    if (!name) {
        showToast('Folder name cannot be empty', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/mkdir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                path: currentPath,
                name: name
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Folder created', 'success');
            closeNewFolderModal();
            loadFiles(currentPath);
        } else {
            showToast(data.message, 'error');
        }
    } catch (error) {
        showToast('Failed to create folder', 'error');
    }
}

// Zip
async function handleZip() {
    if (selectedFiles.size === 0) return;
    
    const zipName = prompt('Enter zip file name:', 'archive.zip');
    if (!zipName) return;
    
    showLoading(true);
    
    try {
        const response = await fetch('/api/zip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                paths: Array.from(selectedFiles),
                name: zipName
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Zip created successfully', 'success');
            loadFiles(currentPath);
        } else {
            showToast(data.message, 'error');
        }
    } catch (error) {
        showToast('Failed to create zip', 'error');
    }
    
    showLoading(false);
}

// Search
function handleSearch(e) {
    clearTimeout(searchTimeout);
    
    const query = e.target.value.trim();
    
    if (!query) {
        loadFiles(currentPath);
        return;
    }
    
    searchTimeout = setTimeout(async () => {
        try {
            const response = await fetch(`/api/search?query=${encodeURIComponent(query)}`);
            const data = await response.json();
            
            if (data.success) {
                renderFiles(data.data);
                updateFileCount(data.data.length);
                updateStatus(`Found ${data.data.length} results`);
            }
        } catch (error) {
            showToast('Search failed', 'error');
        }
    }, 300);
}

// UPDATED updateBreadcrumb to show clean paths
function updateBreadcrumb(path) {
    const breadcrumb = document.getElementById('breadcrumb');
    let cleanPath = path.replace(/^\.\//,'').replace(/\/$/, '');
    const parts = cleanPath.split('/').filter(p => p && p !== 'uploads');
    
    let breadcrumbHTML = `<span class="breadcrumb-item" onclick="loadFiles('./uploads')">uploads</span>`;
    
    if (parts.length > 0) {
        let currentBuildPath = 'uploads';
        breadcrumbHTML += parts.map((part, index) => {
            currentBuildPath += '/' + part;
            return `<span class="breadcrumb-item" onclick="loadFiles('${currentBuildPath}')">${escapeHtml(part)}</span>`;
        }).join('');
    }
    
    breadcrumb.innerHTML = breadcrumbHTML;
}

// Keyboard shortcuts
function handleKeyboardShortcuts(e) {
    // Ctrl/Cmd + U: Upload
    if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        e.preventDefault();
        openUploadModal();
    }
    
    // Ctrl/Cmd + N: New Folder
    if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
        e.preventDefault();
        openNewFolderModal();
    }
    
    // Delete: Delete selected
    if (e.key === 'Delete' && selectedFiles.size > 0) {
        handleDelete();
    }
    
    // Escape: Close modals
    if (e.key === 'Escape') {
        closeUploadModal();
        closeRenameModal();
        closeNewFolderModal();
    }
    
    // Ctrl/Cmd + R: Refresh
    if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        e.preventDefault();
        loadFiles(currentPath);
    }
}

// Utilities
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateStatus(message) {
    document.getElementById('statusText').textContent = message;
}

function updateFileCount(count) {
    document.getElementById('fileCount').textContent = `${count} item${count !== 1 ? 's' : ''}`;
}

function showLoading(show) {
    document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
}

function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : '⚠';
    
    toast.innerHTML = `
        <div class="toast-icon">${icon}</div>
        <div class="toast-message">${escapeHtml(message)}</div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// Make functions globally accessible
window.closeUploadModal = closeUploadModal;
window.closeRenameModal = closeRenameModal;
window.confirmRename = confirmRename;
window.closeNewFolderModal = closeNewFolderModal;
window.confirmNewFolder = confirmNewFolder;
window.handleFileClick = handleFileClick;
window.handleRename = handleRename;
window.loadFiles = loadFiles;
