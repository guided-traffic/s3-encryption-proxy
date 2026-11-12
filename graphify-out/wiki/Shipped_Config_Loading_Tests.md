# Shipped Config Loading Tests

> 4 nodes · cohesion 0.50

## Key Concepts

- **cfgLoadFrom()** (7 connections) — `internal/config/default_config_test.go`
- **TestCfgDefaultConfigFailsClosedOnEveryVariable()** (4 connections) — `internal/config/default_config_test.go`
- **TestCfgShippedExamplesLoad()** (4 connections) — `internal/config/default_config_test.go`
- **Config** (1 connections)

## Relationships

- [Shutdown and Test Contexts](Shutdown_and_Test_Contexts.md) (3 shared connections)
- [Handler Core and Entry Points](Handler_Core_and_Entry_Points.md) (3 shared connections)
- [Configuration Loading](Configuration_Loading.md) (3 shared connections)
- [Misc (41)](Misc_41.md) (1 shared connections)

## Source Files

- `internal/config/default_config_test.go`

## Audit Trail

- EXTRACTED: 9 (69%)
- INFERRED: 4 (31%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*