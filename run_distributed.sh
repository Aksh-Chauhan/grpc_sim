#!/bin/bash
 
# Exit immediately if a command exits with a non-zero status.
set -e
 
echo "--- Building Docker Images ---"
 
# Build gRPC simulator image
echo "Building grpc-sim-peer image..."
docker-compose up 
echo "grpc-sim-peer image built."
