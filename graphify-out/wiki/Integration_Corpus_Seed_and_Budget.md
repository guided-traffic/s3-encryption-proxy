# Integration Corpus Seed and Budget

> 51 nodes · cohesion 0.11

## Key Concepts

- **Context()** (24 connections) — `test/integration/conformance/conformance.go`
- **ProxyClient()** (22 connections) — `test/integration/conformance/conformance.go`
- **Key()** (16 connections) — `test/integration/conformance/conformance.go`
- **conformance.go** (15 connections) — `test/integration/conformance/conformance.go`
- **TestSeed()** (11 connections) — `test/integration/conformance/a_seed_test.go`
- **refusal_test.go** (10 connections) — `test/integration/conformance/refusal_test.go`
- **seedClientMultipart()** (9 connections) — `test/integration/conformance/a_seed_test.go`
- **TestRangedReadsAddressPlaintextCoordinates()** (8 connections) — `test/integration/conformance/read_test.go`
- **TestWholeObjectReadStatesTheSealedChecksum()** (8 connections) — `test/integration/conformance/read_test.go`
- **Budget** (7 connections) — `test/integration/conformance/conformance.go`
- **Content()** (7 connections) — `test/integration/conformance/conformance.go`
- **TestObjectsRoundTripByHash()** (7 connections) — `test/integration/conformance/read_test.go`
- **TestStoredBytesAreCiphertext()** (7 connections) — `test/integration/conformance/read_test.go`
- **statusOf()** (7 connections) — `test/integration/conformance/refusal_test.go`
- **TestRefusedUploadsStoreNothing()** (7 connections) — `test/integration/conformance/refusal_test.go`
- **newClient()** (6 connections) — `test/integration/conformance/conformance.go`
- **read_test.go** (6 connections) — `test/integration/conformance/read_test.go`
- **TestBucketOwnerGuardIsForwarded()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestClientMetadataInsideTheProxyPrefixIsRefused()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestConditionalReadsAreHonoured()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestMissingObjectsAndBucketsAnswerS3Codes()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestServerSideCopyIsRefused()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **TestSSECustomerKeysAreRefusedByName()** (6 connections) — `test/integration/conformance/refusal_test.go`
- **a_seed_test.go** (5 connections) — `test/integration/conformance/a_seed_test.go`
- **TestSeedIsComplete()** (5 connections) — `test/integration/conformance/a_seed_test.go`
- *... and 26 more nodes in this community*

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (28 shared connections)
- [Large Multipart and DEK Cache Tests](Large_Multipart_and_DEK_Cache_Tests.md) (4 shared connections)
- [Segmented Session Lifecycle](Segmented_Session_Lifecycle.md) (1 shared connections)
- [Server](Server.md) (1 shared connections)
- [DEK Cache and Provider Manager](DEK_Cache_and_Provider_Manager.md) (1 shared connections)
- [Complete](Complete.md) (1 shared connections)
- [MockS3Backend Bucket Operations](MockS3Backend_Bucket_Operations.md) (1 shared connections)
- [Performance Test Client](Performance_Test_Client.md) (1 shared connections)

## Source Files

- `test/integration/conformance/a_seed_test.go`
- `test/integration/conformance/budget_test.go`
- `test/integration/conformance/conformance.go`
- `test/integration/conformance/read_test.go`
- `test/integration/conformance/refusal_test.go`
- `test/integration/conformance/z_cost_test.go`

## Audit Trail

- EXTRACTED: 104 (60%)
- INFERRED: 70 (40%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*