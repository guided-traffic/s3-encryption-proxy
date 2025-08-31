## [1.0.4](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.3...v1.0.4) (2025-08-31)


### Bug Fixes

* working on release process ([2ac5dd8](https://github.com/guided-traffic/s3-encryption-proxy/commit/2ac5dd865e72424047caa27e2a7c72552babd986))

## [1.0.3](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.2...v1.0.3) (2025-08-31)


### Bug Fixes

* working on release process ([9d76145](https://github.com/guided-traffic/s3-encryption-proxy/commit/9d7614576aaf66827c804427838f5da31b26615c))
* working on release process ([879ed9e](https://github.com/guided-traffic/s3-encryption-proxy/commit/879ed9e5d74af3e76deaff74b3688b34b1440123))

## [1.0.2](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.1...v1.0.2) (2025-08-30)


### Bug Fixes

* improve release process ([cc1b502](https://github.com/guided-traffic/s3-encryption-proxy/commit/cc1b50206e8edc8689d0e5e57498a2c79763692e))

## [1.0.1](https://github.com/guided-traffic/s3-encryption-proxy/compare/v1.0.0...v1.0.1) (2025-08-30)


### Bug Fixes

* improve release process ([ecaa3b0](https://github.com/guided-traffic/s3-encryption-proxy/commit/ecaa3b0ab1b12269d1f9bff89d0155c8081a7738))

# 1.0.0 (2025-08-30)


### Bug Fixes

* add LICENSE ([da7ed81](https://github.com/guided-traffic/s3-encryption-proxy/commit/da7ed81b0a4067ebd8d09a8f58fb576bc099818f))
* gh test workflow ([29da299](https://github.com/guided-traffic/s3-encryption-proxy/commit/29da2997ae17311f17d5c073b0f295d3a492ceba))
* gosec issues ([efaa577](https://github.com/guided-traffic/s3-encryption-proxy/commit/efaa577c62fb1934d6ecfd44dfe8949587283974))
* linter issues ([92f552a](https://github.com/guided-traffic/s3-encryption-proxy/commit/92f552ab3382b972b9ff3f281dbb197857cc5e88))
* release pipeline ([bbfeb60](https://github.com/guided-traffic/s3-encryption-proxy/commit/bbfeb60c42814e2756c004ffd78a2969df2cd7f0))
* release pipeline ([6308231](https://github.com/guided-traffic/s3-encryption-proxy/commit/6308231519cea4e8cbdaa43f1a913b0e4fe65418))
* security check ([3d80cd6](https://github.com/guided-traffic/s3-encryption-proxy/commit/3d80cd6e30819539de3d6b7df473e4f6862f5d59))
* security check ([7a34d5c](https://github.com/guided-traffic/s3-encryption-proxy/commit/7a34d5c6386dbc7af4540518aab843f4778750c5))
* security check ([f9a8786](https://github.com/guided-traffic/s3-encryption-proxy/commit/f9a87862176b2f956ad31cf531a28dca08a22082))
* security check ([d823447](https://github.com/guided-traffic/s3-encryption-proxy/commit/d823447ca785650d440705e525c6669d7196ed29))


### Features

* added AES256 file encryption ([4a04589](https://github.com/guided-traffic/s3-encryption-proxy/commit/4a04589f56fc8088e14770dc75c27ee412826595))
* create release process ([fbcacf3](https://github.com/guided-traffic/s3-encryption-proxy/commit/fbcacf3ea8dd2511725d011b78a397e31a4abd28))
* implementation starting point ([3dfcb87](https://github.com/guided-traffic/s3-encryption-proxy/commit/3dfcb87fec31653334fee0ad7de07da180763245))
* update configuration ([da86785](https://github.com/guided-traffic/s3-encryption-proxy/commit/da86785117dbf018342dd8150d592a74373f2a91))
* update to go 1.24.6 because 1.25.0 is not supported by different linters and vuln tools ([2ed4a06](https://github.com/guided-traffic/s3-encryption-proxy/commit/2ed4a06815af833d997a6d9271a14e7610bd4cf1))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of S3 encryption proxy
- Google Tink envelope encryption support
- AES-256-GCM direct encryption support
- Configurable encryption algorithms
- Comprehensive unit and integration tests
- Docker containerization
- CI/CD pipeline with security scanning
- Key generation utility
- Comprehensive documentation

### Security
- All cryptographic operations use industry-standard libraries
- Security scanning with gosec and govulncheck
- No secrets stored in repository
