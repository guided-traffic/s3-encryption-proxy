# Build stage
FROM golang:1.25-alpine AS builder

# Build arguments for metadata
ARG BUILD_NUMBER
ARG GIT_COMMIT
ARG BUILD_TIME

# Set build arguments for cross-compilation
ARG TARGETOS
ARG TARGETARCH

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

# Build the application with cross-compilation support
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -a -installsuffix cgo \
    -ldflags="-w -s -X main.version=${BUILD_NUMBER:-dev} -X main.commit=${GIT_COMMIT:-unknown} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o s3-encryption-proxy ./cmd/s3-encryption-proxy

# Build the keygen tool
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -a -installsuffix cgo \
    -ldflags="-w -s -X main.version=${BUILD_NUMBER:-dev} -X main.commit=${GIT_COMMIT:-unknown} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o s3ep-keygen ./cmd/keygen

# Final stage
FROM alpine:3

# Build arguments for metadata
ARG BUILD_NUMBER
ARG GIT_COMMIT
ARG BUILD_TIME

# Add OCI labels for better metadata
LABEL org.opencontainers.image.title="S3 Encryption Proxy" \
      org.opencontainers.image.description="A transparent S3 proxy with client-side encryption capabilities" \
      org.opencontainers.image.vendor="Guided Traffic" \
      org.opencontainers.image.licenses="BSL-1.1" \
      org.opencontainers.image.documentation="https://github.com/guided-traffic/s3-encryption-proxy" \
      org.opencontainers.image.source="https://github.com/guided-traffic/s3-encryption-proxy" \
      org.opencontainers.image.version="${BUILD_NUMBER:-dev}" \
      org.opencontainers.image.revision="${GIT_COMMIT:-unknown}" \
      org.opencontainers.image.created="${BUILD_TIME:-0}"

# Install ca-certificates for HTTPS
RUN apk update && apk upgrade && apk --no-cache add ca-certificates curl

# Create non-root user
RUN addgroup -g 1001 -S s3proxy && \
    adduser -u 1001 -S s3proxy -G s3proxy

WORKDIR /root/

# Copy the binaries from builder stage
COPY --from=builder /app/s3-encryption-proxy .
COPY --from=builder /app/s3ep-keygen .

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
  CMD curl -f http://localhost:8080/health || exit 1

# Command to run
CMD ["./s3-encryption-proxy"]
