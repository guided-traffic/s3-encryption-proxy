# Release Setup Guide

## Overview
This project uses automated SemVer releases with Docker image publishing and integrated test coverage reporting.

## Release Pipeline

### Pipeline Structure

**1. Main Pipeline** (`.github/workflows/release.yml`)
- **Trigger**: Push to `main` branch
- **Jobs**:
  - `test` - Unit tests + coverage generation (parallel)
  - `security` - Security scans + linting (parallel)
  - `semantic-release` - SemVer calculation and Git tag creation (after test + security)

**2. Docker Pipeline** (`.github/workflows/docker.yml`)
- **Trigger**: Push of Git tags (`v*`)
- **Jobs**:
  - `docker-build-and-push` - Multi-arch Docker build and push to GHCR

**3. CI Pipeline** (`.github/workflows/ci.yml`)
- **Trigger**: Pull Requests only
- **Purpose**: Pre-merge validation

### 2. Semantic Versioning
### 2. Quality Gates & Coverage
- ✅ **Unit Tests** (`make test-unit`) - Parallel execution
- ✅ **Test Coverage** - Automatically calculated and included in release notes
- ✅ **Security Scanning** (`gosec`, `govulncheck`) - Parallel execution
- ✅ **Code Linting** (`golangci-lint`) - Part of security job
- ✅ **Static Analysis** (`go vet`, `gofmt`) - Part of security job

### 3. Semantic Versioning

Based on [Conventional Commits](https://www.conventionalcommits.org/):

| Commit Type | Version Bump | Example |
|-------------|-------------|---------|
| `feat:` | Minor (0.X.0) | `feat: add AES-256-GCM encryption` |
| `fix:` | Patch (0.0.X) | `fix: handle invalid KEK gracefully` |
| `perf:` | Patch (0.0.X) | `perf: optimize encryption buffer size` |
| `refactor:` | Patch (0.0.X) | `refactor: simplify config validation` |
| `BREAKING CHANGE:` | Major (X.0.0) | `feat!: change API interface` |

### 4. Release Process
1. **Push to main**: Triggers release pipeline
2. **Parallel execution**: Tests + Security scans
3. **SemVer release**: Creates Git tag and GitHub release
4. **Docker trigger**: Git tag triggers separate Docker build
5. **Multi-arch images**: Published to GHCR

### 5. Docker Images
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
- `.github/workflows/release.yml` - Main release pipeline (main branch)
- `.github/workflows/docker.yml` - Docker build pipeline (tags only)
- `.github/workflows/ci.yml` - CI pipeline (pull requests only)

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

### 3. Coverage Integration
The pipeline automatically:
1. **Generates coverage** during test execution
2. **Extracts percentage** from coverage report
3. **Passes to semantic-release** via environment variable
4. **Includes in release notes** with coverage badges
5. **Attaches coverage files** to GitHub release

**Coverage Files in Release:**
- `coverage-v1.0.0.out` - Go coverage profile
- `coverage-v1.0.0.txt` - Human-readable coverage report
