# Multipart

> 17 nodes · cohesion 0.20

## Key Concepts

- **MpuNewExitEnv()** (15 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **.MpuExitUpload()** (12 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **multipart/checksum_echo_test.go** (7 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **MpuCrcwant()** (7 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuExitProviderAnswersSlowDownWhileTheShortPartBudgetIsSpent()** (7 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuExitProviderAnswersBadDigestForADeclaredPartThatDoesNotMatch()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuExitProviderAnswersBadDigestForAnEmptyPartThatDeclaredAChecksum()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuExitProviderForwardsADeclaredPartWhileItArrives()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuExitProviderHoldsNoMoreThanTheBudgetItClaimed()** (6 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCrcAReplacedPartAnswersTheNewChecksum()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcEveryPartAnswersItsOwnChecksum()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcTheCompletionAnswersTheWholeObjectChecksum()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcTheCompletionCoversAHeldShortPart()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuExitProviderRefusesAnUndeclaredPartAboveTheBudget()** (5 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`
- **TestMpuCrcARefusedPartStatesNoChecksum()** (4 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcTheExitProviderStatesNoChecksum()** (4 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **MpuBytesAllocated()** (2 connections) — `internal/proxy/handlers/multipart/multipart_coverage_test.go`

## Relationships

- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (36 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (14 shared connections)
- [Etag Marker](Etag_Marker.md) (1 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (1 shared connections)
- [DeleteObjects Handler Tests](DeleteObjects_Handler_Tests.md) (1 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/checksum_echo_test.go`
- `internal/proxy/handlers/multipart/multipart_coverage_test.go`

## Audit Trail

- EXTRACTED: 65 (81%)
- INFERRED: 15 (19%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*