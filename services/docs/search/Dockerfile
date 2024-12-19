# Stage 1: Build the Go binary
FROM golang:1.23-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files
COPY src/go.mod src/go.sum ./

# Download the Go module dependencies
RUN go mod download

# Copy the rest of the application source code
COPY src .

# Build the Go binary
RUN go build -o /app/search

# Stage 2: Create a minimal image with the Go binary
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /root/

# Copy the Go binary from the builder stage
COPY --from=builder /app/search .

# Expose the port the service will run on
EXPOSE 8080

# Command to run the Go binary
CMD ["./search"]