# Migration to Distroless Base Image

## Overview
The S3 Encryption Proxy has been migrated from Alpine Linux to Google's distroless base image for improved security and reduced image size.

## Changes Summary

### Base Image
- **Before**: `alpine:3` (47.6 MB)
- **After**: `gcr.io/distroless/static-debian12:nonroot` (18.7 MB)
- **Size Reduction**: 60.7% smaller

### Security Improvements
- **Vulnerabilities**: 0 Critical, 0 High, 0 Medium, 0 Low
- **Busybox vulnerability removed**: The apk/alpine/busybox vulnerability is completely eliminated
- **Minimal attack surface**: No shell, no package manager, no unnecessary binaries
- **Non-root user**: Runs as UID 65532 (nonroot) by default

### What's Included in Distroless
- CA certificates (for HTTPS connections)
- Timezone data
- `/etc/passwd` and `/etc/group` files
- Static binary support

### What's NOT Included
- No shell (`/bin/sh`, `/bin/bash`)
- No package manager (`apk`)
- No debugging tools (`curl`, `wget`, `ps`, etc.)
- No `HEALTHCHECK` support in Dockerfile

## Health Check Configuration

Since distroless images don't include shell or HTTP clients, health checks must be implemented externally.

### Docker Compose
The demo configuration now includes a lightweight Alpine sidecar container (`proxy-healthcheck`) that performs health checks:

```yaml
proxy-healthcheck:
  image: alpine:3.21
  container_name: proxy-healthcheck
  depends_on:
    - s3-encryption-proxy
  networks:
    - s3-demo
  command: >
    sh -c '
    while true; do
      wget --quiet --tries=1 --spider http://s3-encryption-proxy:8080/health || exit 1
      sleep 10
    done
    '
  restart: unless-stopped
  deploy:
    resources:
      limits:
        memory: 32M
        cpus: '0.1'
```

### Kubernetes
Use built-in HTTP probes:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

## Debugging Distroless Containers

Since distroless containers have no shell, debugging requires different approaches:

### 1. Use Ephemeral Debug Container (Kubernetes)
```bash
kubectl debug -it <pod-name> --image=alpine:3.21 --target=<container-name>
```

### 2. Copy Files for Analysis
```bash
docker cp <container-id>:/app/config ./debug-config
```

### 3. Check Logs
```bash
docker logs <container-id>
kubectl logs <pod-name>
```

### 4. Use Distroless Debug Image (for development)
For development purposes, you can temporarily use the debug variant:
```dockerfile
FROM gcr.io/distroless/static-debian12:debug-nonroot
```
This includes busybox for basic debugging (not recommended for production).

## Building the Image

The build process remains the same:

```bash
# Via Makefile
make build

# Via Docker directly
docker build -f Containerfile -t s3-encryption-proxy:latest .

# Via Docker Compose
docker compose -f docker-compose.demo.yml build
```

## Migration Checklist

- [x] Update Containerfile to use distroless base image
- [x] Remove Alpine-specific commands (apk, adduser, etc.)
- [x] Remove HEALTHCHECK from Containerfile
- [x] Update Docker Compose with health check sidecar
- [x] Update documentation
- [ ] Update CI/CD pipelines (if needed)
- [ ] Update Kubernetes manifests (if applicable)
- [ ] Test deployment in production environment

## Rollback Plan

If issues arise, you can rollback by reverting the Containerfile changes:

```bash
git checkout main -- Containerfile docker-compose.demo.yml
docker compose -f docker-compose.demo.yml build
```

## References

- [Distroless Base Images](https://github.com/GoogleContainerTools/distroless)
- [Distroless Best Practices](https://github.com/GoogleContainerTools/distroless/blob/main/README.md)
- [Docker Health Checks](https://docs.docker.com/engine/reference/builder/#healthcheck)
- [Kubernetes Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
