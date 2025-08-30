# Contributing to S3 Encryption Proxy

We welcome contributions to the S3 Encryption Proxy project! Please read this guide to understand how to contribute effectively.

## Development Setup

### Prerequisites

- Go 1.23 or later
- Docker and Docker Compose (for integration testing)
- Make

### Setup

1. Clone the repository:
```bash
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy
```

2. Install dependencies:
```bash
make deps
```

3. Install development tools:
```bash
make tools
```

## Development Workflow

### Building

```bash
make build
```

### Running Tests

```bash
# Run all tests
make test

# Run only unit tests
make test-unit

# Run only integration tests (requires Docker)
make test-integration

# Generate coverage report
make coverage
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint
```

### Development Server

```bash
# Run with live reload
make dev
```

## Testing

### Unit Tests

- Place unit tests in `*_test.go` files alongside the code they test
- Use table-driven tests where appropriate
- Mock external dependencies
- Aim for high test coverage

### Integration Tests

- Integration tests are in the `test/integration/` directory
- Tests use Docker Compose to set up MinIO for realistic S3 testing
- Run with `INTEGRATION_TESTS=true make test-integration`

## Code Style

- Follow standard Go conventions
- Use `gofmt` and `goimports`
- Write meaningful comments for exported functions and types
- Keep functions small and focused
- Use descriptive variable names

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `make test`
6. Run linting: `make lint`
7. Commit your changes with a clear message
8. Push to your fork
9. Create a pull request

### Pull Request Requirements

- All tests must pass
- Code coverage should not decrease
- New features must include tests
- Update documentation as needed
- Follow the existing code style

## Architecture

### Overview

The S3 Encryption Proxy is structured as follows:

```
cmd/                  # Main application entry points
internal/             # Private application code
├── config/          # Configuration management
├── encryption/      # Encryption management
├── proxy/           # HTTP proxy server
└── s3/              # S3 client wrapper
pkg/                 # Public reusable packages
└── envelope/        # Envelope encryption implementation
test/                # Integration tests
```

### Key Components

1. **Envelope Encryption** (`pkg/envelope/`): Implements envelope encryption using Google's Tink library
2. **Configuration** (`internal/config/`): Handles application configuration from files, environment variables, and CLI flags
3. **Proxy Server** (`internal/proxy/`): HTTP server that intercepts S3 API calls
4. **S3 Client** (`internal/s3/`): Wrapper around AWS SDK with encryption/decryption capabilities

## Security Considerations

- All cryptographic operations use Google's Tink library
- Keys are managed through envelope encryption
- No plaintext keys are stored or transmitted
- Associated data (object keys) are used for additional security

## Debugging

Enable debug logging:
```bash
./s3-encryption-proxy --log-level debug
```

## Getting Help

- Check existing issues on GitHub
- Read the documentation in the `docs/` directory
- Ask questions in discussions

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
