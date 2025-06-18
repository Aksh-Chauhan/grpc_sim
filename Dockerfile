# Use a Go base image for version 1.23
FROM golang:1.23.0
 
# Set the working directory inside the container
WORKDIR /app
 
# Install protoc
# Using apt-get for Debian/Ubuntu-based Go images
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
 
# Install Go gRPC plugins
# Ensure these are installed to a path accessible by PATH
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
 
# Add GOPATH/bin to PATH for protoc-gen-go and protoc-gen-go-grpc
# This is crucial so `protoc` can find the plugins
ENV PATH="/go/bin:${PATH}"
 
# Initialize Go module
# This MUST happen before copying other .go files if they depend on local packages
# The module name 'grpc_gossip_simulator' matches your import path
#RUN go mod init grpc_gossip_simulator
 
# Create the target directory for generated protobuf files *before* copying proto
# This ensures the 'gossip' package directory is part of the module structure
#RUN mkdir -p gossip
 
# Copy the .proto file into the working directory
#COPY . .
 
# Generate the Go gRPC code.
# The `go_package` option in gossip.proto will ensure it's placed in /app/gossip/
#RUN protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative gossip.proto
 
# Copy the main application file
#COPY main.go .
 
# Tidy up Go module dependencies (pulls in gRPC, protobuf, etc.)
# This is where dependencies are resolved based on go.mod and imports
#RUN go mod tidy

#RUN go build -o main .
# Build the Go application
# This will create an executable 'main' at /app/main
# RUN go build -o main .
 
# Expose the ports that the servers will listen on
# EXPOSE 50051
# EXPOSE 50052
 
# Command to run the application when the container starts
#CMD ["/bin/bash"]
