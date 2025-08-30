# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o s3-encryption-proxy ./cmd/s3-encryption-proxy

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S s3proxy && \
    adduser -u 1001 -S s3proxy -G s3proxy

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/s3-encryption-proxy .

# Copy configuration templates
COPY --from=builder /app/config ./config

# Change ownership to non-root user
RUN chown -R s3proxy:s3proxy /root/

# Switch to non-root user
USER s3proxy

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Command to run
CMD ["./s3-encryption-proxy"]
