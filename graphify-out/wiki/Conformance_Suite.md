# Conformance Suite

> 43 nodes · cohesion 0.12

## Key Concepts

- **Context()** (24 connections) — `test/integration/conformance/conformance.go`
- **ProxyClient()** (22 connections) — `test/integration/conformance/conformance.go`
- **refusal_test.go** (21 connections) — `test/integration/conformance/refusal_test.go`
- **Key()** (16 connections) — `test/integration/conformance/conformance.go`
- **read_test.go** (13 connections) — `test/integration/conformance/read_test.go`
- **TestSeed()** (11 connections) — `test/integration/conformance/a_seed_test.go`
- **seedClientMultipart()** (10 connections) — `test/integration/conformance/a_seed_test.go`
- **TestRangedReadsAddressPlaintextCoordinates()** (8 connections) — `test/integration/conformance/read_test.go`
- **TestWholeObjectReadStatesTheSealedChecksum()** (8 connections) — `test/integration/conformance/read_test.go`
- **Budget** (7 connections) — `test/integration/conformance/conformance.go`
- **Content()** (7 connections) — `test/integration/conformance/conformance.go`
- **TestObjectsRoundTripByHash()** (7 connections) — `test/integration/conformance/read_test.go`
- **TestStoredBytesAreCiphertext()** (7 connections) — `test/integration/conformance/read_test.go`
- **statusOf()** (7 connections) — `test/integration/conformance/refusal_test.go`
- **TestRefusedUploadsStoreNothing()** (7 connections) — `test/integration/conformance/refusal_test.go`
- **TestBudgetRefusesWhatItCannotPayFor()** (6 connections) — `test/integration/conformance/budget_test.go`
- **newClient()** (6 connections) — `test/integration/conformance/conformance.go`
- **TestBucketOwnerGuardIsForwarded()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestClientMetadataInsideTheProxyPrefixIsRefused()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestConditionalReadsAreHonoured()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestMissingObjectsAndBucketsAnswerS3Codes()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestServerSideCopyIsRefused()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestSSECustomerKeysAreRefusedByName()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestSeedIsComplete()** (5 connections) — `test/integration/conformance/a_seed_test.go`
- **BackendClient()** (5 connections) — `test/integration/conformance/conformance.go`
- *... and 18 more nodes in this community*

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (40 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (27 shared connections)
- [Streaming Integration Helpers](Streaming_Integration_Helpers.md) (4 shared connections)
- [Orchestration: Providers Coverage Test (2)](Orchestration-_Providers_Coverage_Test_2.md) (1 shared connections)
- [In-Process Provider Instances](In-Process_Provider_Instances.md) (1 shared connections)
- [Tampering Harness](Tampering_Harness.md) (1 shared connections)
- [Perf Harness and Report](Perf_Harness_and_Report.md) (1 shared connections)

## Source Files

- `test/integration/conformance/a_seed_test.go`
- `test/integration/conformance/budget_test.go`
- `test/integration/conformance/conformance.go`
- `test/integration/conformance/read_test.go`
- `test/integration/conformance/refusal_test.go`
- `test/integration/conformance/z_cost_test.go`

## Audit Trail

- EXTRACTED: 113 (61%)
- INFERRED: 73 (39%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*