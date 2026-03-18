import re

def process_csp():
    with open('server/middleware.go', 'r') as f:
        content = f.read()

    # The new design requires Inter from fonts.googleapis.com, tailwind script from cdn.tailwindcss.com
    # and possibly some images.
    new_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"

    content = re.sub(
        r'w\.Header\(\)\.Set\("Content-Security-Policy", ".*?"\)',
        f'w.Header().Set("Content-Security-Policy", "{new_csp}")',
        content
    )

    with open('server/middleware.go', 'w') as f:
        f.write(content)

if __name__ == "__main__":
    process_csp()
