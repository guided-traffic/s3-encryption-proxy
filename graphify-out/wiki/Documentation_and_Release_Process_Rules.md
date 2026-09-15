# Documentation and Release Process Rules

> 48 nodes · cohesion 0.05

## Key Concepts

- **ADR 0019 Integration and e2e tests are the product** (37 connections) — `CONTRIBUTING.md`
- **ADR 0022: Tickets are work lists that get archived; decisions live in ADRs** (19 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **ADR 0031: A test states the target and stays red until the product meets it** (15 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **ADR 0035 The README advertises, the reference lives under docs/** (10 connections) — `CLAUDE.md`
- **Documentation has five homes, a statement goes to exactly one** (5 connections) — `CLAUDE.md`
- **The release:major label declares a major (D3, D4)** (4 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **A Ticket Is A Work List** (4 connections) — `docs/tickets/README.md`
- **A test asserts the target behaviour, never today's** (3 connections) — `CLAUDE.md`
- **The license expiry is discovered by a build, not by an environment (D8, D9, D10)** (3 connections) — `docs/adr/0016-the-license-is-a-startup-gate.md`
- **Every e2e suite gates the release (D9)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **A test pinning soon-to-be-replaced behaviour carries an in-source marker (D16)** (3 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Five Homes, and a Durable Statement Goes to Exactly One** (3 connections) — `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- **Every design decision is recorded as an ADR** (2 connections) — `CLAUDE.md`
- **Nothing outside docs/tickets/ may reference a ticket** (2 connections) — `CLAUDE.md`
- **A ticket is a work list and nothing else** (2 connections) — `CLAUDE.md`
- **Documentation updated in the same change, in the right place** (2 connections) — `CONTRIBUTING.md`
- **The integration and e2e suites are the product's behaviour** (2 connections) — `CONTRIBUTING.md`
- **Breaking changes collect on one long-lived branch (D7, D8)** (2 connections) — `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- **The 2026-09-13 correction: expected-refusal tables are forbidden** (2 connections) — `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- **Every durable decision is an ADR, written when the decision is taken (D1, D2, D11)** (2 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **The archive stays out of the knowledge-graph corpus** (2 connections) — `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- **Enforced Known-Failure Manifest (Rejected Alternative)** (2 connections) — `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- **docs/operations/ — Operator and Client Reference** (2 connections) — `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- **One Page per Supported Client** (2 connections) — `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- **An ADR Is Not a Ticket** (2 connections) — `docs/adr/README.md`
- *... and 23 more nodes in this community*

## Relationships

- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (12 shared connections)
- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (9 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (4 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (3 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (3 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (3 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (3 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (2 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (2 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (2 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (1 shared connections)

## Source Files

- `CLAUDE.md`
- `CONTRIBUTING.md`
- `docs/adr/0016-the-license-is-a-startup-gate.md`
- `docs/adr/0018-a-major-release-is-declared-by-a-label.md`
- `docs/adr/0019-integration-and-e2e-tests-are-the-product.md`
- `docs/adr/0022-tickets-are-work-lists-that-get-archived.md`
- `docs/adr/0031-a-test-states-the-target-and-stays-red-until-the-product-meets-it.md`
- `docs/adr/0035-the-readme-advertises-the-reference-lives-under-docs.md`
- `docs/adr/README.md`
- `docs/tickets/README.md`

## Audit Trail

- EXTRACTED: 95 (92%)
- INFERRED: 8 (8%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*