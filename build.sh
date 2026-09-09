#!/bin/bash
set -e
cd "$(dirname "$0")"
go mod tidy
go build -ldflags="-s -w" -o wgtunnel wgtunnel.go
echo "✅ Build complete: ./wgtunnel"
ls -lh wgtunnel | awk '{print $5}'
