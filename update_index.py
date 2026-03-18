import re

def process_html():
    with open('screens/login.html', 'r') as f:
        login_html = f.read()

    with open('screens/main.html', 'r') as f:
        main_html = f.read()

    with open('screens/modals.html', 'r') as f:
        modals_html = f.read()

    # Define our custom HTML structure based on the clean design.
    # We map IDs onto the structural elements provided by the Stitch generation
    # so that our `app.js` can continue to operate them.

    final_html = f"""<!DOCTYPE html>
<html class="light" lang="en">
<head>
    <meta charset="utf-8"/>
    <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
    <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght@100..700,0..1&display=swap" rel="stylesheet"/>

    <script id="tailwind-config">
        tailwind.config = {{
            darkMode: "class",
            theme: {{
                extend: {{
                    colors: {{
                        "primary": "#0052cc",
                        "background-light": "#ffffff",
                        "surface": "#f4f5f7",
                    }},
                    fontFamily: {{
                        "display": ["Inter", "sans-serif"]
                    }},
                    borderRadius: {{"DEFAULT": "0.375rem", "lg": "0.5rem", "xl": "0.75rem", "full": "9999px"}},
                }},
            }},
        }}
    </script>
    <title>Secure File Manager</title>
    <style>
        body {{
            min-height: max(884px, 100dvh);
            -webkit-font-smoothing: antialiased;
        }}
        .material-symbols-outlined {{
            font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
        }}
        .fill-icon {{
            font-variation-settings: 'FILL' 1;
        }}

        /* JS Toggle utilities */
        .hidden-modal {{ display: none !important; }}
        .flex-modal {{ display: flex !important; }}
        .selected-row {{ background-color: #f0f7ff !important; border-left: 3px solid #0052cc !important; }}
        .drag-over-area {{ border-color: #0052cc !important; background-color: #f0f7ff !important; }}
        .error-message-show {{ display: block !important; }}

        /* Toasts */
        .toast-container {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            z-index: 3000;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .toast {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            min-width: 300px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            border-radius: 0.5rem;
            animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            color: #334155;
            font-weight: 500;
        }}

        @keyframes slideUp {{
            from {{ transform: translateY(100%); opacity: 0; }}
            to {{ transform: translateY(0); opacity: 1; }}
        }}

        .toast.success {{ border-left: 4px solid #22c55e; }}
        .toast.error {{ border-left: 4px solid #ef4444; }}
        .toast.warning {{ border-left: 4px solid #eab308; }}

        .toast-icon {{
            font-family: var(--font-display);
            font-size: 1.5rem;
        }}

        .toast-message {{
            font-size: 0.9rem;
        }}
    </style>
</head>
<body class="bg-background-light font-display min-h-screen text-slate-800 flex items-center justify-center p-0 m-0">

<!-- Login Screen -->
<div id="loginScreen" class="w-full h-screen flex items-center justify-center bg-surface">
    <div class="w-full max-w-[440px] bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
        <div class="pt-12 pb-8 px-10 text-center">
            <div class="flex justify-center mb-6">
                <div class="size-14 bg-primary rounded-lg flex items-center justify-center text-white shadow-md">
                    <span class="material-symbols-outlined !text-[32px]">folder_open</span>
                </div>
            </div>
            <h1 class="text-2xl font-bold text-slate-900 mb-2">Sign in to FileCloud</h1>
            <p class="text-slate-500 text-sm">Enter your credentials to access your workspace.</p>
        </div>

        <form id="loginForm" class="px-10 pb-12 space-y-5">
            <div>
                <label class="block text-sm font-medium text-slate-700 mb-1.5" for="username">Email Address or Username</label>
                <input id="username" type="text" class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-primary focus:border-primary transition-shadow text-sm" placeholder="user@company.com" required>
            </div>
            <div>
                <div class="flex justify-between items-center mb-1.5">
                    <label class="block text-sm font-medium text-slate-700" for="password">Password</label>
                    <a href="#" class="text-sm font-medium text-primary hover:text-blue-700 transition-colors">Forgot password?</a>
                </div>
                <input id="password" type="password" class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-primary focus:border-primary transition-shadow text-sm" placeholder="••••••••" required>
            </div>

            <div id="loginError" class="hidden text-red-600 text-sm font-medium bg-red-50 p-3 rounded-lg border border-red-200"></div>

            <button type="submit" class="w-full bg-primary hover:bg-blue-700 text-white font-semibold py-2.5 rounded-lg shadow-sm hover:shadow transition-all mt-4">
                Sign In
            </button>
            <div class="text-center mt-6">
                <p class="text-slate-500 text-xs font-medium">Default: admin / admin</p>
            </div>
        </form>
    </div>
</div>

<!-- Main Application -->
<div id="mainApp" class="hidden-modal flex-col h-screen w-full bg-surface w-full">
    <!-- Header -->
    <header class="bg-white border-b border-slate-200 sticky top-0 z-20 shadow-sm w-full">
        <div class="flex items-center justify-between px-6 py-3">
            <div class="flex items-center gap-3">
                <div class="size-8 bg-primary rounded flex items-center justify-center text-white shadow-sm">
                    <span class="material-symbols-outlined !text-[20px] fill-icon">cloud</span>
                </div>
                <h1 class="text-lg font-semibold text-slate-800 tracking-tight">Enterprise Files</h1>
            </div>
            <div class="flex items-center gap-6">
                <div class="relative hidden md:block">
                    <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 !text-lg">search</span>
                    <input id="searchInput" type="text" placeholder="Search files, folders..." class="pl-10 pr-4 py-1.5 w-64 border border-slate-300 rounded-full text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent bg-slate-50 transition-all">
                </div>
                <button id="logoutBtn" class="flex items-center gap-2 text-slate-600 hover:text-red-600 transition-colors text-sm font-medium cursor-pointer">
                    <span class="material-symbols-outlined !text-lg">logout</span>
                    Sign Out
                </button>
            </div>
        </div>
    </header>

    <!-- Toolbar -->
    <div class="bg-white border-b border-slate-200 px-6 py-2 flex flex-wrap items-center gap-2 sticky top-[61px] z-10 w-full">
        <button id="uploadBtn" class="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors shadow-sm cursor-pointer">
            <span class="material-symbols-outlined !text-lg">upload</span>
            Upload
        </button>
        <button id="newFolderBtn" class="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 text-slate-700 rounded-md text-sm font-medium hover:bg-slate-50 hover:text-slate-900 transition-colors cursor-pointer">
            <span class="material-symbols-outlined !text-lg">create_new_folder</span>
            New Folder
        </button>
        <div class="w-px h-6 bg-slate-300 mx-2 hidden sm:block"></div>
        <button id="refreshBtn" class="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 text-slate-700 rounded-md text-sm font-medium hover:bg-slate-50 hover:text-slate-900 transition-colors cursor-pointer">
            <span class="material-symbols-outlined !text-lg">refresh</span>
            Refresh
        </button>
        <div class="flex-1"></div>
        <button id="downloadBtn" class="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 text-slate-700 rounded-md text-sm font-medium hover:bg-slate-50 hover:text-primary transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer" disabled>
            <span class="material-symbols-outlined !text-lg">download</span>
            Download
        </button>
        <button id="zipBtn" class="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 text-slate-700 rounded-md text-sm font-medium hover:bg-slate-50 hover:text-primary transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer" disabled>
            <span class="material-symbols-outlined !text-lg">folder_zip</span>
            Zip
        </button>
        <button id="deleteBtn" class="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-300 text-slate-700 rounded-md text-sm font-medium hover:bg-red-50 hover:text-red-600 hover:border-red-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer" disabled>
            <span class="material-symbols-outlined !text-lg">delete</span>
            Delete
        </button>
    </div>

    <!-- Breadcrumb -->
    <div class="px-6 py-3 border-b border-slate-200 bg-surface flex items-center text-sm w-full">
        <div id="breadcrumb" class="flex items-center gap-2 text-slate-600 font-medium w-full">
            <span class="material-symbols-outlined !text-lg text-slate-400">home</span>
            <span class="hover:text-primary cursor-pointer transition-colors">uploads</span>
        </div>
    </div>

    <!-- File List Content -->
    <main class="flex-1 overflow-y-auto px-6 py-4 w-full">
        <div class="bg-white border border-slate-200 rounded-lg shadow-sm overflow-hidden w-full">
            <table class="w-full text-left border-collapse">
                <thead class="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-500 uppercase tracking-wider">
                    <tr>
                        <th class="px-4 py-3 w-12 text-center">
                            <input type="checkbox" id="selectAll" class="rounded border-slate-300 text-primary focus:ring-primary cursor-pointer w-4 h-4">
                        </th>
                        <th class="px-4 py-3">Name</th>
                        <th class="px-4 py-3 text-right hidden sm:table-cell">Size</th>
                        <th class="px-4 py-3 text-right hidden md:table-cell">Modified</th>
                        <th class="px-4 py-3 text-center hidden lg:table-cell">Permissions</th>
                        <th class="px-4 py-3 text-center w-24">Actions</th>
                    </tr>
                </thead>
                <tbody id="fileList" class="text-sm divide-y divide-slate-100">
                    <!-- Files injected here -->
                </tbody>
            </table>

            <!-- Empty state -->
            <div id="emptyState" class="hidden-modal flex-col items-center justify-center py-16 text-slate-500 w-full">
                <div class="size-16 bg-slate-100 rounded-full flex items-center justify-center mb-4">
                    <span class="material-symbols-outlined text-3xl text-slate-400">folder_open</span>
                </div>
                <h3 class="text-lg font-medium text-slate-900 mb-1">This folder is empty</h3>
                <p class="text-sm mb-6 text-center max-w-sm">There are no files or folders here. Upload files or create a new folder to get started.</p>
                <button onclick="document.getElementById('uploadBtn').click()" class="bg-primary text-white px-5 py-2 rounded-md font-medium hover:bg-blue-700 transition-colors shadow-sm cursor-pointer">
                    Upload Files
                </button>
            </div>
        </div>
    </main>

    <!-- Status Bar -->
    <footer class="bg-white border-t border-slate-200 px-6 py-2 flex items-center justify-between text-xs font-medium text-slate-500 w-full">
        <div class="flex items-center gap-2">
            <div class="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_4px_rgba(34,197,94,0.6)]"></div>
            <span id="statusText">System Online & Secure</span>
        </div>
        <div id="fileCount">0 Items</div>
    </footer>
</div>

<!-- Upload Modal -->
<div id="uploadModal" class="hidden-modal fixed inset-0 z-[1000] items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4 w-full h-full">
    <div class="w-full max-w-lg bg-white rounded-xl shadow-xl overflow-hidden border border-slate-200">
        <div class="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
            <h2 class="text-lg font-semibold text-slate-800 flex items-center gap-2">
                <span class="material-symbols-outlined text-primary !text-xl">cloud_upload</span>
                Upload Files
            </h2>
            <button onclick="closeUploadModal()" class="text-slate-400 hover:text-slate-600 transition-colors p-1 rounded-md hover:bg-slate-100 cursor-pointer">
                <span class="material-symbols-outlined !text-xl">close</span>
            </button>
        </div>
        <div class="p-6">
            <div id="uploadArea" class="border-2 border-dashed border-slate-300 bg-slate-50 rounded-lg p-8 text-center cursor-pointer hover:border-primary hover:bg-blue-50/50 transition-all group">
                <div class="size-12 bg-white rounded-full shadow-sm border border-slate-200 flex items-center justify-center mx-auto mb-3 group-hover:scale-110 transition-transform">
                    <span class="material-symbols-outlined text-primary text-2xl">upload_file</span>
                </div>
                <h3 class="text-sm font-medium text-slate-900 mb-1">Click to browse or drag files here</h3>
                <p class="text-xs text-slate-500">Support for single or bulk upload</p>
                <input type="file" id="fileInput" multiple class="hidden">
            </div>

            <div id="uploadList" class="mt-4 max-h-40 overflow-y-auto space-y-2"></div>
        </div>
        <div class="px-6 py-4 bg-slate-50 border-t border-slate-100 flex justify-end gap-3">
            <button onclick="closeUploadModal()" class="px-4 py-2 text-sm font-medium text-slate-600 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors cursor-pointer">
                Cancel
            </button>
            <button onclick="document.getElementById('fileInput').click()" class="px-4 py-2 text-sm font-medium text-white bg-primary rounded-md hover:bg-blue-700 transition-colors shadow-sm cursor-pointer">
                Browse Files
            </button>
        </div>
    </div>
</div>

<!-- Rename Modal -->
<div id="renameModal" class="hidden-modal fixed inset-0 z-[1000] items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4 w-full h-full">
    <div class="w-full max-w-md bg-white rounded-xl shadow-xl overflow-hidden border border-slate-200">
        <div class="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
            <h2 class="text-lg font-semibold text-slate-800 flex items-center gap-2">
                <span class="material-symbols-outlined text-primary !text-xl">edit</span>
                Rename Item
            </h2>
            <button onclick="closeRenameModal()" class="text-slate-400 hover:text-slate-600 transition-colors p-1 rounded-md hover:bg-slate-100 cursor-pointer">
                <span class="material-symbols-outlined !text-xl">close</span>
            </button>
        </div>
        <div class="p-6">
            <label for="renameInput" class="block text-sm font-medium text-slate-700 mb-2">New name</label>
            <input type="text" id="renameInput" class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-primary focus:border-primary transition-shadow text-sm" placeholder="Enter new name...">
        </div>
        <div class="px-6 py-4 bg-slate-50 border-t border-slate-100 flex justify-end gap-3">
            <button onclick="closeRenameModal()" class="px-4 py-2 text-sm font-medium text-slate-600 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors cursor-pointer">
                Cancel
            </button>
            <button onclick="confirmRename()" class="px-4 py-2 text-sm font-medium text-white bg-primary rounded-md hover:bg-blue-700 transition-colors shadow-sm cursor-pointer">
                Save Changes
            </button>
        </div>
    </div>
</div>

<!-- New Folder Modal -->
<div id="newFolderModal" class="hidden-modal fixed inset-0 z-[1000] items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4 w-full h-full">
    <div class="w-full max-w-md bg-white rounded-xl shadow-xl overflow-hidden border border-slate-200">
        <div class="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
            <h2 class="text-lg font-semibold text-slate-800 flex items-center gap-2">
                <span class="material-symbols-outlined text-primary !text-xl">create_new_folder</span>
                Create Folder
            </h2>
            <button onclick="closeNewFolderModal()" class="text-slate-400 hover:text-slate-600 transition-colors p-1 rounded-md hover:bg-slate-100 cursor-pointer">
                <span class="material-symbols-outlined !text-xl">close</span>
            </button>
        </div>
        <div class="p-6">
            <label for="folderNameInput" class="block text-sm font-medium text-slate-700 mb-2">Folder name</label>
            <input type="text" id="folderNameInput" class="w-full px-4 py-2.5 rounded-lg border border-slate-300 focus:ring-2 focus:ring-primary focus:border-primary transition-shadow text-sm" placeholder="e.g. Q3 Reports">
        </div>
        <div class="px-6 py-4 bg-slate-50 border-t border-slate-100 flex justify-end gap-3">
            <button onclick="closeNewFolderModal()" class="px-4 py-2 text-sm font-medium text-slate-600 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition-colors cursor-pointer">
                Cancel
            </button>
            <button onclick="confirmNewFolder()" class="px-4 py-2 text-sm font-medium text-white bg-primary rounded-md hover:bg-blue-700 transition-colors shadow-sm cursor-pointer">
                Create
            </button>
        </div>
    </div>
</div>

<!-- Loading Overlay -->
<div id="loadingOverlay" class="hidden-modal fixed inset-0 z-[2000] bg-white/80 backdrop-blur-sm items-center justify-center flex-col w-full h-full">
    <div class="size-12 border-4 border-slate-200 border-t-primary rounded-full animate-spin mb-4"></div>
    <div class="text-slate-600 font-medium text-sm">Processing request...</div>
</div>

<!-- Toast Notifications -->
<div id="toastContainer" class="toast-container"></div>

<input type="file" id="hiddenFileInput" style="display: none;">

<script src="/static/js/app.js"></script>
</body>
</html>
"""

    with open('static/index.html', 'w') as f:
        f.write(final_html)

if __name__ == "__main__":
    process_html()
