import re

def main():
    # Read the content of the downloaded files
    with open('new_login.html', 'r') as f: login_html = f.read()
    with open('new_main.html', 'r') as f: main_html = f.read()
    with open('new_upload.html', 'r') as f: upload_html = f.read()
    with open('new_rename.html', 'r') as f: rename_html = f.read()
    with open('new_folder.html', 'r') as f: folder_html = f.read()
    with open('new_heatmap.html', 'r') as f: heatmap_html = f.read()

    # Extract the <head> portion, including Tailwind config and styles, from login_html
    head_match = re.search(r'<head>(.*?)</head>', login_html, re.DOTALL)
    head_content = head_match.group(1) if head_match else ""

    # Add any extra styles from main_html
    main_styles = re.findall(r'<style>(.*?)</style>', main_html, re.DOTALL)
    for style in main_styles:
        if style not in head_content:
            head_content += f"\n<style>{style}</style>\n"

    # Define the final HTML structure
    final_html = f"""<!DOCTYPE html>
<html class="dark" lang="en">
<head>
{head_content}
<title>Secure File Manager</title>
<style>
/* Utilities for JS toggles */
.hidden-modal {{ display: none !important; }}
.flex-modal {{ display: flex !important; }}
.selected-row {{ background-color: rgba(34, 197, 94, 0.1) !important; border-left: 2px solid #22c55e !important; }}
.drag-over-area {{ border-color: #22c55e !important; background-color: rgba(34, 197, 94, 0.05) !important; }}
.error-message-show {{ display: block !important; animation: blink 0.5s step-end infinite alternate; }}

@keyframes blink {{ 50% {{ opacity: 0.8; }} }}

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
    background: #0a0a0a;
    border: 1px solid #404040;
    padding: 1rem 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    min-width: 300px;
    box-shadow: 4px 4px 0px #050505, 4px 4px 0px 1px #404040;
    animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    color: #F5F5F5;
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
<body class="bg-background-dark font-display antialiased selection:bg-primary selection:text-background-dark overflow-x-hidden text-slate-100">

<!-- CRT Scanline & Noise Effect Overlays -->
<div class="fixed inset-0 crt-overlay z-[9999] pointer-events-none"></div>
<div class="fixed inset-0 noise z-[9998] pointer-events-none"></div>

<!-- Login Screen -->
<div id="loginScreen" class="relative flex h-screen w-full flex-col bg-background-dark overflow-hidden border-4 border-zinc-900">
    <!-- Header -->
    <div class="flex items-center bg-zinc-950 p-6 border-b-2 border-primary/20 justify-between">
        <div class="text-primary flex size-10 shrink-0 items-center justify-center border-2 border-primary">
            <span class="material-symbols-outlined !text-[24px]">terminal</span>
        </div>
        <h2 class="text-primary text-xs font-bold leading-tight tracking-[0.2em] flex-1 text-right">LC_AUTH_v4.02</h2>
    </div>
    <div class="flex-1 flex flex-col justify-center px-6">
        <!-- Branding -->
        <div class="mb-12">
            <div class="inline-block bg-primary text-background-dark px-2 py-1 text-[10px] font-black tracking-widest mb-2">SECURITY_LEVEL_HIGH</div>
            <h1 class="text-zinc-100 tracking-tighter text-6xl font-black leading-[0.85] uppercase break-words">
                System<br/>
                <span class="text-primary">Access</span>
            </h1>
            <div class="h-1 w-24 bg-primary mt-4"></div>
        </div>
        <!-- Login Form -->
        <form id="loginForm" class="space-y-6">
            <div class="flex flex-wrap items-end gap-2">
                <label class="flex flex-col flex-1">
                    <p class="text-primary text-[10px] font-bold leading-normal pb-2 tracking-[0.3em]">USER_ID</p>
                    <input id="username" name="username" required autocomplete="username" class="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-none text-primary focus:outline-0 focus:ring-0 border-2 border-zinc-800 bg-zinc-900/50 focus:border-primary h-16 placeholder:text-zinc-700 p-4 text-lg font-bold leading-normal uppercase tracking-widest" placeholder="REQUIRED_FIELD" type="text" />
                </label>
            </div>
            <div class="flex flex-wrap items-end gap-2">
                <label class="flex flex-col flex-1">
                    <p class="text-primary text-[10px] font-bold leading-normal pb-2 tracking-[0.3em]">ACCESS_KEY</p>
                    <div class="flex w-full flex-1 items-stretch">
                        <input id="password" name="password" required autocomplete="current-password" class="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-none text-primary focus:outline-0 focus:ring-0 border-2 border-zinc-800 border-r-0 bg-zinc-900/50 focus:border-primary h-16 placeholder:text-zinc-700 p-4 text-lg font-bold leading-normal tracking-widest" placeholder="********" type="password" />
                        <div class="text-zinc-600 flex border-2 border-zinc-800 bg-zinc-900/50 items-center justify-center px-4">
                            <span class="material-symbols-outlined">visibility</span>
                        </div>
                    </div>
                </label>
            </div>
            <div id="loginError" class="hidden bg-red-600 text-white p-2 text-xs font-bold uppercase tracking-widest mt-2 border-2 border-red-800"></div>
            <div class="pt-6">
                <button type="submit" class="group relative flex w-full cursor-pointer items-center justify-center overflow-hidden h-20 bg-primary text-background-dark text-xl font-black tracking-[0.2em] transition-all active:scale-[0.98]">
                    <span class="relative z-10">INITIATE_LOGIN</span>
                    <div class="absolute inset-0 bg-white opacity-0 group-hover:opacity-10 transition-opacity"></div>
                </button>
            </div>
            <div class="text-center mt-4">
                <p class="text-zinc-600 text-[10px] font-bold uppercase tracking-widest">Default: admin / admin</p>
            </div>
        </form>
    </div>
</div>

<!-- Main Application -->
<div id="mainApp" class="hidden flex-col h-screen w-full bg-background-dark overflow-hidden">
    <!-- Header -->
    <header class="flex flex-col border-b-4 border-slate-800">
        <div class="flex items-center justify-between p-4 bg-slate-900">
            <div class="flex items-center gap-2 text-primary">
                <span class="material-symbols-outlined scale-110">terminal</span>
                <h1 class="text-xl font-bold uppercase tracking-tighter">Main_File_Explorer</h1>
            </div>
            <button id="logoutBtn" class="bg-red-600/10 border-2 border-red-600 px-3 py-1 text-red-600 text-xs font-black hover:bg-red-600 hover:text-white transition-colors cursor-pointer">
                TERMINATE_SESSION
            </button>
        </div>
        <!-- Search Bar -->
        <div class="px-4 py-3 bg-background-dark">
            <div class="relative flex w-full items-stretch border-2 border-slate-700">
                <div class="flex items-center justify-center px-3 border-r-2 border-slate-700 bg-slate-800">
                    <span class="material-symbols-outlined text-sm text-primary">search</span>
                </div>
                <input id="searchInput" class="w-full bg-transparent p-3 text-sm font-bold uppercase placeholder:text-slate-500 focus:ring-0 border-none text-primary" placeholder="COMMAND_OR_FILE_NAME..."/>
            </div>
        </div>
    </header>

    <!-- Heavy Toolbar -->
    <div class="grid grid-cols-3 sm:grid-cols-6 gap-0 border-b-2 border-slate-800">
        <button id="uploadBtn" class="border-r-2 border-b-2 sm:border-b-0 border-slate-800 py-3 text-xs font-black uppercase text-slate-300 hover:bg-primary hover:text-background-dark transition-colors cursor-pointer"> [UPLOAD] </button>
        <button id="newFolderBtn" class="border-r-2 border-b-2 sm:border-b-0 border-slate-800 py-3 text-xs font-black uppercase text-slate-300 hover:bg-primary hover:text-background-dark transition-colors cursor-pointer"> [MKDIR] </button>
        <button id="refreshBtn" class="border-b-2 sm:border-b-0 sm:border-r-2 border-slate-800 py-3 text-xs font-black uppercase text-slate-300 hover:bg-primary hover:text-background-dark transition-colors cursor-pointer"> [REFRESH] </button>
        <button id="deleteBtn" class="border-r-2 border-slate-800 py-3 text-xs font-black uppercase text-slate-300 hover:bg-red-600 hover:text-white disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-slate-300 transition-colors cursor-pointer" disabled> [DEL] </button>
        <button id="downloadBtn" class="border-r-2 border-slate-800 py-3 text-xs font-black uppercase text-slate-300 hover:bg-primary hover:text-background-dark disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-slate-300 transition-colors cursor-pointer" disabled> [GET] </button>
        <button id="zipBtn" class="border-slate-800 py-3 text-xs font-black uppercase text-slate-300 hover:bg-primary hover:text-background-dark disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-slate-300 transition-colors cursor-pointer" disabled> [ZIP] </button>
    </div>

    <!-- Path Breadcrumb -->
    <div class="px-4 py-2 bg-slate-900/50 border-b border-slate-800 flex items-center">
        <p class="text-[10px] font-mono font-bold text-slate-400 mr-2">PATH:</p>
        <div id="breadcrumb" class="flex items-center gap-1 text-[10px] font-mono font-bold text-primary">
            <span class="breadcrumb-item active cursor-pointer hover:underline uppercase">/uploads</span>
        </div>
    </div>

    <!-- File List Content -->
    <main class="flex-1 overflow-y-auto bg-background-dark relative">
        <table class="w-full text-left border-collapse">
            <thead class="sticky top-0 bg-slate-800/90 backdrop-blur-sm border-b-2 border-slate-700 z-10">
                <tr class="text-[10px] font-black uppercase text-slate-400">
                    <th class="px-4 py-2 w-12 text-center">
                        <input type="checkbox" id="selectAll" class="size-4 border-2 border-slate-600 bg-transparent text-primary focus:ring-primary focus:ring-offset-0 cursor-pointer">
                    </th>
                    <th class="px-2 py-2">Name</th>
                    <th class="px-2 py-2 text-right hidden sm:table-cell">Size</th>
                    <th class="px-4 py-2 text-right hidden md:table-cell">Modified</th>
                    <th class="px-4 py-2 text-center hidden lg:table-cell">Permissions</th>
                    <th class="px-4 py-2 text-center w-24">Actions</th>
                </tr>
            </thead>
            <tbody id="fileList" class="mono-condensed text-sm divide-y divide-slate-800">
                <!-- Files injected here -->
            </tbody>
        </table>

        <div id="emptyState" class="hidden flex-col items-center justify-center py-20 text-slate-500 border-2 border-dashed border-slate-800 m-8">
            <span class="material-symbols-outlined text-6xl mb-4 opacity-50">folder_open</span>
            <p class="text-xl font-bold uppercase tracking-widest mb-6">DIRECTORY_EMPTY</p>
            <button onclick="document.getElementById('uploadBtn').click()" class="border-2 border-primary text-primary px-6 py-2 font-bold uppercase hover:bg-primary hover:text-background-dark transition-colors cursor-pointer">
                INITIATE_UPLOAD
            </button>
        </div>
    </main>

    <!-- Status Bar -->
    <div class="p-2 border-t-2 border-slate-800 flex justify-between items-center text-[10px] text-slate-500 font-bold uppercase tracking-widest bg-slate-900">
        <div class="flex items-center gap-2">
            <div class="size-2 bg-primary animate-pulse"></div>
            <span id="statusText">SYSTEM_STABLE</span>
        </div>
        <div id="fileCount">0_ENTITIES</div>
    </div>
</div>

<!-- Upload Modal -->
<div id="uploadModal" class="hidden-modal fixed inset-0 z-[1000] items-center justify-center bg-black/80 backdrop-blur-sm">
    <div class="w-full max-w-md bg-background-dark border-4 border-zinc-900 shadow-[12px_12px_0px_0px_rgba(255,255,255,0.1)] relative">
        <div class="absolute -top-3 -left-1 bg-white text-background-dark px-2 py-0.5 text-[10px] font-black tracking-widest z-10">UPLOAD_PAYLOAD</div>
        <div class="p-6">
            <div class="flex justify-between items-center border-b-2 border-zinc-800 pb-4 mb-6">
                <h2 class="text-2xl font-black uppercase text-white tracking-tighter">Transfer</h2>
                <button onclick="closeUploadModal()" class="text-zinc-500 hover:text-white hover:bg-red-600 size-8 border-2 border-zinc-800 hover:border-red-600 flex items-center justify-center transition-colors cursor-pointer">
                    <span class="material-symbols-outlined">close</span>
                </button>
            </div>

            <div id="uploadArea" class="border-2 border-dashed border-zinc-700 bg-zinc-900/50 p-8 text-center cursor-pointer hover:border-primary hover:bg-primary/5 transition-all mb-4">
                <span class="material-symbols-outlined text-zinc-500 text-4xl mb-2">upload_file</span>
                <p class="text-zinc-400 font-bold uppercase text-xs tracking-widest">AWAITING_DATA_INPUT</p>
                <p class="text-zinc-600 text-[10px] mt-2 font-mono">DRAG_DROP_OR_CLICK</p>
                <input type="file" id="fileInput" multiple class="hidden">
            </div>

            <div id="uploadList" class="max-h-40 overflow-y-auto space-y-2"></div>

            <div class="mt-6 flex justify-end">
                <button onclick="document.getElementById('fileInput').click()" class="bg-primary text-background-dark px-6 py-3 font-black uppercase tracking-widest text-sm hover:bg-white transition-colors cursor-pointer border-2 border-primary hover:border-white">
                    SELECT_FILES
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Rename Modal -->
<div id="renameModal" class="hidden-modal fixed inset-0 z-[1000] items-center justify-center bg-black/80 backdrop-blur-sm">
    <div class="w-full max-w-sm bg-background-dark border-4 border-zinc-900 shadow-[12px_12px_0px_0px_rgba(234,179,8,0.2)] relative">
        <div class="absolute -top-3 -left-1 bg-yellow-500 text-background-dark px-2 py-0.5 text-[10px] font-black tracking-widest z-10">RENAME_OBJECT</div>
        <div class="p-6">
            <h2 class="text-2xl font-black uppercase text-white tracking-tighter mb-6">Modify_Identifier</h2>
            <div class="mb-8 relative group">
                <div class="absolute inset-y-0 left-0 w-2 bg-yellow-500 group-focus-within:bg-white transition-colors"></div>
                <input type="text" id="renameInput" class="w-full bg-zinc-900 border-2 border-zinc-800 border-l-0 text-white p-4 pl-6 font-mono font-bold focus:outline-none focus:border-yellow-500 focus:ring-0 placeholder:text-zinc-600 uppercase" placeholder="NEW_IDENTIFIER_STR">
            </div>
            <div class="flex gap-4">
                <button onclick="closeRenameModal()" class="flex-1 border-2 border-zinc-800 text-zinc-400 py-3 font-black uppercase tracking-widest text-xs hover:bg-zinc-800 hover:text-white transition-colors cursor-pointer">
                    ABORT
                </button>
                <button onclick="confirmRename()" class="flex-1 bg-yellow-500 text-background-dark py-3 font-black uppercase tracking-widest text-xs hover:bg-white transition-colors cursor-pointer">
                    CONFIRM
                </button>
            </div>
        </div>
    </div>
</div>

<!-- New Folder Modal -->
<div id="newFolderModal" class="hidden-modal fixed inset-0 z-[1000] items-center justify-center bg-black/80 backdrop-blur-sm">
    <div class="w-full max-w-sm bg-background-dark border-4 border-zinc-900 shadow-[12px_12px_0px_0px_rgba(43,108,238,0.2)] relative">
        <div class="absolute -top-3 -left-1 bg-primary text-background-dark px-2 py-0.5 text-[10px] font-black tracking-widest z-10">CREATE_DIRECTORY</div>
        <div class="p-6">
            <h2 class="text-2xl font-black uppercase text-white tracking-tighter mb-6">Init_Dir</h2>
            <div class="mb-8 relative group">
                <div class="absolute inset-y-0 left-0 w-2 bg-primary group-focus-within:bg-white transition-colors"></div>
                <input type="text" id="folderNameInput" class="w-full bg-zinc-900 border-2 border-zinc-800 border-l-0 text-white p-4 pl-6 font-mono font-bold focus:outline-none focus:border-primary focus:ring-0 placeholder:text-zinc-600 uppercase" placeholder="DIR_NAME">
            </div>
            <div class="flex gap-4">
                <button onclick="closeNewFolderModal()" class="flex-1 border-2 border-zinc-800 text-zinc-400 py-3 font-black uppercase tracking-widest text-xs hover:bg-zinc-800 hover:text-white transition-colors cursor-pointer">
                    ABORT
                </button>
                <button onclick="confirmNewFolder()" class="flex-1 bg-primary text-background-dark py-3 font-black uppercase tracking-widest text-xs hover:bg-white transition-colors cursor-pointer">
                    EXECUTE
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Loading Overlay -->
<div id="loadingOverlay" class="hidden-modal fixed inset-0 z-[2000] bg-black/90 items-center justify-center flex-col">
    <div class="size-16 border-4 border-zinc-800 border-t-primary animate-spin mb-4"></div>
    <div class="text-primary font-mono text-xs tracking-[0.3em] uppercase animate-pulse">PROCESSING_DATA...</div>
</div>

<!-- Toast Notifications -->
<div id="toastContainer" class="toast-container"></div>

<input type="file" id="hiddenFileInput" style="display: none;">

<script src="/static/js/app.js"></script>
</body>
</html>"""

    with open('static/index.html', 'w') as f:
        f.write(final_html)

if __name__ == "__main__":
    main()
