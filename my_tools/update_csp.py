import re

def main():
    with open('server/middleware.go', 'r') as f:
        content = f.read()

    new_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://lh3.googleusercontent.com;"

    # We replace the old CSP string
    content = re.sub(
        r'w\.Header\(\)\.Set\("Content-Security-Policy", ".*?"\)',
        f'w.Header().Set("Content-Security-Policy", "{new_csp}")',
        content
    )

    with open('server/middleware.go', 'w') as f:
        f.write(content)

if __name__ == "__main__":
    main()
