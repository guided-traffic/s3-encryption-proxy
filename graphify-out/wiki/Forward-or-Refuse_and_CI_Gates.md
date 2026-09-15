# Forward-or-Refuse and CI Gates

> 61 nodes · cohesion 0.04

## Key Concepts

- **ADR 0007 Forward it or refuse it** (39 connections) — `DEVELOPER.md`
- **ADR 0023 Filename encryption encrypts directory segments (unbuilt)** (31 connections) — `README.md`
- **ADR 0027 Conformance is asserted against a backend that is not MinIO** (22 connections) — `DEVELOPER.md`
- **ADR 0007 D8: A refusal says what is true and names the header, parameter or element** (6 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **TestEveryBackendCallCarriesTheOwnerGuard()** (5 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **The Ownership Precondition Set in Every s3.*Input Literal** (4 connections) — `docs/developer/request-paths.md`
- **Checklist: every backend call carries the owner guard** (3 connections) — `DEVELOPER.md`
- **test-pipeline.yml continuous integration jobs** (3 connections) — `DEVELOPER.md`
- **Fifteen required checks are repository configuration, not a file** (3 connections) — `DEVELOPER.md`
- **ADR 0007 D1: A request is honoured or refused; accepting, discarding and answering success is forbidden** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D13: A raw query string containing a semicolon is refused with 400 InvalidArgument** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D14: x-amz-expected-bucket-owner is carried on every backend call, all or nothing** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D4: ?tagging, ?retention and ?legal-hold are passthrough to the backend** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D5: PUT ?acl and PUT ?cors carry their document to the backend in full** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D6: The three customer-key headers are refused with 501 NotImplemented** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **400 InvalidArgument** (3 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **x-amz-expected-bucket-owner Is Enforced by No Reachable Backend** (3 connections) — `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- **isOwnerHeaderCall()** (3 connections) — `internal/proxy/request/bucketowner_guard_test.go`
- **x-amz-expected-bucket-owner is carried on every backend call** (3 connections) — `SECURITY_ARCHITECTURE.md`
- **ADR 0007 D10: A malformed partNumber answers 400 InvalidArgument and never replaces the object** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D12: What is forwarded is documented as forwarded, together with its consequence** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D2: A request element the proxy does not need is forwarded to the backend unchanged** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D3: Every upload path forwards the same ten storage headers through one shared decision** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D7: Conditional request headers are honoured on GET, ranged GET, HEAD, PUT and Complete** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- **ADR 0007 D9: An unrouted query parameter is refused by name; the x-amz-* namespace is the allowlist** (2 connections) — `docs/adr/0007-forward-it-or-refuse-it.md`
- *... and 36 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (12 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (7 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (5 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (5 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (4 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (4 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (4 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (3 shared connections)
- [KEK Fingerprint and Client Checksums](KEK_Fingerprint_and_Client_Checksums.md) (3 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (3 shared connections)
- [Configuration Loading and Upload Sweeper](Configuration_Loading_and_Upload_Sweeper.md) (3 shared connections)
- [Network Boundary and HA Store](Network_Boundary_and_HA_Store.md) (3 shared connections)

## Source Files

- `CONTRIBUTING.md`
- `DEVELOPER.md`
- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `docs/adr/0007-forward-it-or-refuse-it.md`
- `docs/adr/0023-filename-encryption-encrypts-directory-segments.md`
- `docs/adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md`
- `docs/developer/request-paths.md`
- `docs/developer/testing.md`
- `internal/proxy/request/bucketowner_guard_test.go`

## Audit Trail

- EXTRACTED: 127 (96%)
- INFERRED: 5 (4%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*