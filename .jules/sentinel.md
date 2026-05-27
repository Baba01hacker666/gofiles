# Sentinel Security Journal

## Fix: Root Directory Deletion Vulnerability
**Issue**: Destructive operations like delete and rename on paths such as `""` or `"."` successfully validated but pointed to the global `baseUploadDir` (the root uploads directory), potentially allowing an attacker to delete or rename the entire root upload folder.
**Fix**: `deleteHandler` and `renameHandler` were updated to perform an exact string match check against `baseUploadDir` (`if cleanPath == baseUploadDir`), returning a 403 Forbidden to reject these attempts.
