# S3Enc: Helpers Test

> 17 nodes · cohesion 0.35

## Key Concepts

- **newStack()** (13 connections) — `test/integration/s3enc/helpers_test.go`
- **TestRoundTrip()** (11 connections) — `test/integration/s3enc/client_test.go`
- **objectKey()** (11 connections) — `test/integration/s3enc/helpers_test.go`
- **randomBytes()** (10 connections) — `test/integration/s3enc/helpers_test.go`
- **randomKey()** (10 connections) — `test/integration/s3enc/helpers_test.go`
- **TestLibraryReadsWhatTheProxyWrote()** (9 connections) — `test/integration/s3enc/interop_test.go`
- **TestGetRange()** (8 connections) — `test/integration/s3enc/client_test.go`
- **TestKeyRotation()** (8 connections) — `test/integration/s3enc/client_test.go`
- **TestTamperingIsRefused()** (8 connections) — `test/integration/s3enc/client_test.go`
- **digest()** (8 connections) — `test/integration/s3enc/helpers_test.go`
- **readObject()** (8 connections) — `test/integration/s3enc/helpers_test.go`
- **TestProxyReadsWhatTheLibraryWrote()** (7 connections) — `test/integration/s3enc/interop_test.go`
- **TestCopyOfCorruptSourceStoresNothing()** (6 connections) — `test/integration/s3enc/client_test.go`
- **TestForeignObjectIsRefused()** (5 connections) — `test/integration/s3enc/client_test.go`
- **TestReservedMetadataStoresNothing()** (5 connections) — `test/integration/s3enc/client_test.go`
- **proxyKey()** (4 connections) — `test/integration/s3enc/helpers_test.go`
- **crc32cBase64()** (3 connections) — `test/integration/s3enc/helpers_test.go`

## Relationships

- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (17 shared connections)
- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (15 shared connections)
- [Keygen and Encrypt Readers](Keygen_and_Encrypt_Readers.md) (2 shared connections)
- [Segment Codec and Range Planner](Segment_Codec_and_Range_Planner.md) (1 shared connections)
- [Storedobject: Storedobject](Storedobject-_Storedobject.md) (1 shared connections)
- [Checksum Verifier](Checksum_Verifier.md) (1 shared connections)
- [Delete and Checksum Integration](Delete_and_Checksum_Integration.md) (1 shared connections)

## Source Files

- `test/integration/s3enc/client_test.go`
- `test/integration/s3enc/helpers_test.go`
- `test/integration/s3enc/interop_test.go`

## Audit Trail

- EXTRACTED: 35 (41%)
- INFERRED: 51 (59%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*