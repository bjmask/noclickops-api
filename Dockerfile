# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
# (git might be needed if go.mod dependencies are private or complex)
RUN apk add --no-cache git

# Copy module files first to leverage cache
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
# CGO_ENABLED=0 creates a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o noclickops-api ./cmd/api/main.go

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install certificates for HTTPS calls
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /app/noclickops-api .

# Copy static assets (web UI)
COPY --from=builder /app/web ./web
COPY --from=builder /app/docs ./docs

# Copy migration/seed if needed (optional, depending on how you run migrations)
COPY --from=builder /app/seed.sql .

# Expose API port
EXPOSE 8080

# Run the application
CMD ["./noclickops-api"]
