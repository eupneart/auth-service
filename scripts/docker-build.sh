#!/bin/bash
set -e

echo "Building Docker image..."
docker build -f auth-service.dockerfile -t eupneart/auth-service:latest .
docker tag eupneart/auth-service:latest eupneart/auth-service:1.0.0

echo "✓ Docker build complete"
echo "  Image: eupneart/auth-service:latest"
echo "  Image: eupneart/auth-service:1.0.0"
