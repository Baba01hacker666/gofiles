#!/bin/bash

echo "================================"
echo "Secure File Manager - Build Script"
echo "================================"
echo ""

# Navigate to server directory
cd server

# Build the application
echo "Building Go application..."
go build -o ../filemanager main.go

if [ $? -eq 0 ]; then
    echo "✓ Build successful!"
    echo ""
    echo "To run the application:"
    echo "  ./filemanager"
    echo ""
    echo "Then open: http://localhost:8080"
    echo "Default credentials: admin / admin"
else
    echo "✗ Build failed!"
    exit 1
fi
