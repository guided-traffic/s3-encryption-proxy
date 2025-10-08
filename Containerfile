# buildtime stage
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

# Final stage - using distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

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

# distroless images run as non-root user 65532 (nonroot) by default
# distroless includes ca-certificates and tzdata

WORKDIR /app

# Copy the binaries from builder stage
COPY --from=builder /app/s3-encryption-proxy .
COPY --from=builder /app/s3ep-keygen .

# Copy configuration templates
COPY --from=builder /app/config ./config

# Expose port
EXPOSE 8080

CMD ["./s3-encryption-proxy"]
