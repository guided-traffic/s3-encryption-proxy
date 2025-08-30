# Release Setup Guide

## Overview
This project uses automated SemVer releases with Docker image publishing.

## Release Pipeline

### 1. Quality Gates
- ✅ Unit Tests (`make test-unit`)
- ✅ Security Scanning (`gosec`, `govulncheck`) 
- ✅ Code Linting (`golangci-lint`)
- ✅ Static Analysis (`go vet`, `gofmt`)

### 2. Semantic Versioning
Based on [Conventional Commits](https://www.conventionalcommits.org/):

| Commit Type | Version Bump | Example |
|-------------|-------------|---------|
| `feat:` | Minor (0.X.0) | `feat: add AES-256-GCM encryption` |
| `fix:` | Patch (0.0.X) | `fix: handle invalid KEK gracefully` |
| `perf:` | Patch (0.0.X) | `perf: optimize encryption buffer size` |
| `refactor:` | Patch (0.0.X) | `refactor: simplify config validation` |
| `BREAKING CHANGE:` | Major (X.0.0) | `feat!: change API interface` |

### 3. Release Process
1. **Trigger**: Push to `main` branch
2. **Test**: Run quality gates
3. **Version**: Calculate next version from commits
4. **Release**: Create GitHub release with changelog
5. **Docker**: Build and push multi-arch images

### 4. Docker Images
Published to GitHub Container Registry:
```
ghcr.io/guided-traffic/s3-encryption-proxy:latest
ghcr.io/guided-traffic/s3-encryption-proxy:v1.0.0
ghcr.io/guided-traffic/s3-encryption-proxy:v1.0
ghcr.io/guided-traffic/s3-encryption-proxy:v1
```

**Platforms**: linux/amd64, linux/arm64

## Files Created

### GitHub Actions
- `.github/workflows/release.yml` - Release pipeline
- `.github/workflows/ci.yml` - Existing CI pipeline

### Semantic Release
- `package.json` - npm dependencies and basic config
- `.releaserc.json` - Detailed semantic-release configuration
- `CHANGELOG.md` - Auto-generated changelog

### Docker
- `Dockerfile` - Multi-arch optimized build
- `.dockerignore` - Build optimization

### Make Targets
- `make security` - Security scanning
- `make quality` - All quality checks
- `make vuln` - Vulnerability scanning only

## Usage Examples

### Triggering Releases

**Patch Release (0.0.1 → 0.0.2):**
```bash
git commit -m "fix: handle empty S3 object keys"
git push origin main
```

**Minor Release (0.1.0 → 0.2.0):**
```bash
git commit -m "feat: add support for S3 server-side encryption"
git push origin main
```

**Major Release (1.0.0 → 2.0.0):**
```bash
git commit -m "feat!: change proxy API to REST

BREAKING CHANGE: The proxy now uses REST API instead of S3 API passthrough"
git push origin main
```

### Using Released Images

**Latest version:**
```bash
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_ENCRYPTION_TYPE=tink \
  -e S3EP_KEK_URI="gcp-kms://projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key" \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest
```

**Specific version:**
```bash
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_ENCRYPTION_TYPE=aes256-gcm \
  -e S3EP_AES_KEY=your-base64-key \
  ghcr.io/guided-traffic/s3-encryption-proxy:v1.2.3
```

## Local Testing

**Test quality pipeline:**
```bash
make quality        # Run all checks
make build-all      # Build binaries
make test          # Run all tests
```

**Test Docker build:**
```bash
docker build --platform linux/amd64 -t s3-encryption-proxy:test .
docker build --platform linux/arm64 -t s3-encryption-proxy:test-arm .
```

## First Release

After pushing the initial setup to `main`, the first release will be v1.0.0 due to the feature commits:
- feat: initial S3 encryption proxy implementation
- feat: add Tink envelope encryption support  
- feat: add AES-256-GCM direct encryption support
- feat: add key generation utility

## Monitoring Releases

- **GitHub Releases**: https://github.com/guided-traffic/s3-encryption-proxy/releases
- **Container Images**: https://github.com/guided-traffic/s3-encryption-proxy/pkgs/container/s3-encryption-proxy
- **Actions**: https://github.com/guided-traffic/s3-encryption-proxy/actions
