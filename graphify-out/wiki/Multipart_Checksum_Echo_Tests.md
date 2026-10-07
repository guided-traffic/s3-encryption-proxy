# Multipart Checksum Echo Tests

> 8 nodes · cohesion 0.39

## Key Concepts

- **multipart/checksum_echo_test.go** (7 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **MpuCrcwant()** (7 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcAReplacedPartAnswersTheNewChecksum()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcEveryPartAnswersItsOwnChecksum()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcTheCompletionAnswersTheWholeObjectChecksum()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcTheCompletionCoversAHeldShortPart()** (5 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcARefusedPartStatesNoChecksum()** (4 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`
- **TestMpuCrcTheExitProviderStatesNoChecksum()** (4 connections) — `internal/proxy/handlers/multipart/checksum_echo_test.go`

## Relationships

- [Multipart Handler Coverage Tests](Multipart_Handler_Coverage_Tests.md) (14 shared connections)
- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (6 shared connections)

## Source Files

- `internal/proxy/handlers/multipart/checksum_echo_test.go`

## Audit Trail

- EXTRACTED: 17 (55%)
- INFERRED: 14 (45%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*