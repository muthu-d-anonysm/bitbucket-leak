#!/bin/bash
echo "🏗️ Building BitBucket Scanner..."
mkdir -p bin

# Build for the current platform
go build -o bin/bitbucket-scanner main.go

if [ $? -eq 0 ]; then
  echo "✅ Build successful: bin/bitbucket-scanner"
else
  echo "❌ Build failed!"
  exit 1
fi
