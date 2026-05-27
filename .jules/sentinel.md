## [2026-04-26] XSS via HTML Entity Decoding in Attributes

**Vulnerability:** DOM-based XSS when using inline event handlers (e.g., `onclick`) even with HTML escaping.
**Context:** In `static/js/app.js`, file paths were escaped using `escapeHtml` and then placed into `onclick` attributes.
**Technical Detail:** Browsers decode HTML entities (like `&#039;` for a single quote) within attributes *before* the JavaScript engine executes the code. This allows an attacker to break out of a string literal and execute arbitrary code if they can control part of the attribute value (e.g., a filename).
**Mitigation:** Use `addEventListener` and event delegation combined with `data-*` attributes to handle interactions. This separates the data from the execution context and prevents the browser's attribute decoding from triggering script execution.
- Security Architecture: `validatePath` intentionally resolves empty paths (`""`, `"."`) to the global `baseUploadDir` to support root-level operations like listing files. Handlers executing destructive or filesystem-modifying operations (e.g., `deleteHandler`, `renameHandler`) must independently explicitly verify the validated path does not exactly equal `baseUploadDir` to prevent root directory compromise.
