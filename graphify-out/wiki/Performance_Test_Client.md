# Performance Test Client

> 24 nodes · cohesion 0.18

## Key Concepts

- **TestProxyMemory()** (16 connections) — `test/perf/memory_test.go`
- **TestCPUProfiles()** (13 connections) — `test/perf/memory_test.go`
- **memory_test.go** (11 connections) — `test/perf/memory_test.go`
- **ensureBucket()** (10 connections) — `test/perf/client.go`
- **TestUploadPathComparison()** (10 connections) — `test/perf/uploadpath_test.go`
- **net/http.Client** (9 connections)
- **emptyBucket()** (9 connections) — `test/perf/client.go`
- **SetStatus()** (9 connections) — `test/perf/harness.go`
- **client.go** (8 connections) — `test/perf/client.go`
- **legsFor()** (8 connections) — `test/perf/client.go`
- **newS3Client()** (5 connections) — `test/perf/client.go`
- **driveMemoryLoad()** (5 connections) — `test/perf/memory_test.go`
- **putGet()** (5 connections) — `test/perf/memory_test.go`
- **startRSSSampler()** (5 connections) — `test/perf/memory_test.go`
- **httpClientFor()** (4 connections) — `test/perf/client.go`
- **scrapeRSS()** (4 connections) — `test/perf/memory_test.go`
- **rssSampler** (3 connections) — `test/perf/memory_test.go`
- **testCAPool()** (3 connections) — `test/perf/client.go`
- **capturePprof()** (3 connections) — `test/perf/memory_test.go`
- **randomPayload()** (3 connections) — `test/perf/memory_test.go`
- **crypto/x509.CertPool** (2 connections)
- **.peak()** (2 connections) — `test/perf/memory_test.go`
- **isAlreadyOwned()** (2 connections) — `test/perf/client.go`
- **profileSeconds()** (2 connections) — `test/perf/memory_test.go`

## Relationships

- [Smallobject](Smallobject.md) (8 shared connections)
- [Harness](Harness.md) (7 shared connections)
- [Streaming Integration Test Harness](Streaming_Integration_Test_Harness.md) (5 shared connections)
- [MockS3Backend Tagging and Policy](MockS3Backend_Tagging_and_Policy.md) (4 shared connections)
- [Rangeread](Rangeread.md) (4 shared connections)
- [Throughput](Throughput.md) (4 shared connections)
- [Readme](Readme.md) (4 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (3 shared connections)
- [Report](Report.md) (3 shared connections)
- [Velero E2E Backup Suite](Velero_E2E_Backup_Suite.md) (2 shared connections)
- [Perf Stack Detection](Perf_Stack_Detection.md) (2 shared connections)
- [E2E Harness Backend Client](E2E_Harness_Backend_Client.md) (1 shared connections)

## Source Files

- `test/perf/client.go`
- `test/perf/harness.go`
- `test/perf/memory_test.go`
- `test/perf/uploadpath_test.go`

## Audit Trail

- EXTRACTED: 63 (62%)
- INFERRED: 38 (38%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*