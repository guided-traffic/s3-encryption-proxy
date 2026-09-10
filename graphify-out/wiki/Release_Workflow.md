# Release Workflow

> 20 nodes · cohesion 0.12

## Key Concepts

- **Test and Release Pipeline** (9 connections) — `.github/workflows/release.yml`
- **Integration Tests Against the Demo Stack** (6 connections) — `.github/workflows/release.yml`
- **Combined Unit and Integration Coverage** (5 connections) — `.github/workflows/release.yml`
- **Semantic Release Job** (5 connections) — `.github/workflows/release.yml`
- **Velero E2E as a Release Gate** (3 connections) — `.github/workflows/release.yml`
- **Unit Tests with Binary Coverage Data** (3 connections) — `.github/workflows/release.yml`
- **Commits Drive the Release** (3 connections) — `CONTRIBUTING.md`
- **Four Test Layers Matrix** (3 connections) — `CONTRIBUTING.md`
- **golangci-lint v2 Module Path Pin** (2 connections) — `.github/workflows/release.yml`
- **Performance Suite Run in Isolation** (2 connections) — `.github/workflows/release.yml`
- **TLS Integration Run** (2 connections) — `.github/workflows/release.yml`
- **Go Version in Exactly Two Files** (2 connections) — `CLAUDE.md`
- **Coverage Badge Committed by semantic-release** (1 connections) — `.github/workflows/release.yml`
- **GoSec Security Scan Job** (1 connections) — `.github/workflows/release.yml`
- **govulncheck Vulnerability Job** (1 connections) — `.github/workflows/release.yml`
- **GOCOVER Instrumented Proxy Build** (1 connections) — `.github/workflows/release.yml`
- **ClamAV Source Malware Scan** (1 connections) — `.github/workflows/release.yml`
- **A Breaking Change Is Declared by a Label** (1 connections) — `CONTRIBUTING.md`
- **make tools Installs the Wrong Linter Major** (1 connections) — `CONTRIBUTING.md`
- **The Suites Are Not Optional** (1 connections) — `CONTRIBUTING.md`

## Relationships

- [Operator Documentation](Operator_Documentation.md) (4 shared connections)
- [Breaking Change Guard](Breaking_Change_Guard.md) (2 shared connections)
- [Velero E2E Environment](Velero_E2E_Environment.md) (1 shared connections)
- [Performance Baseline Suite](Performance_Baseline_Suite.md) (1 shared connections)
- [Documentation Conventions](Documentation_Conventions.md) (1 shared connections)

## Source Files

- `.github/workflows/release.yml`
- `CLAUDE.md`
- `CONTRIBUTING.md`

## Audit Trail

- EXTRACTED: 25 (81%)
- INFERRED: 6 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*