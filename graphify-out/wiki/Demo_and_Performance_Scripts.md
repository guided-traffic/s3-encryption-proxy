# Demo and Performance Scripts

> 35 nodes · cohesion 0.16

## Key Concepts

- **start-demo.sh** (17 connections) — `start-demo.sh`
- **performance.sh** (16 connections) — `performance.sh`
- **main()** (16 connections) — `start-demo.sh`
- **main()** (10 connections) — `performance.sh`
- **log_info()** (10 connections) — `start-demo.sh`
- **log_info()** (9 connections) — `performance.sh`
- **log_success()** (8 connections) — `performance.sh`
- **run_performance_tests()** (7 connections) — `performance.sh`
- **log_success()** (7 connections) — `start-demo.sh`
- **check_services()** (6 connections) — `performance.sh`
- **build_project()** (5 connections) — `performance.sh`
- **check_dependencies()** (5 connections) — `performance.sh`
- **generate_markdown_report()** (5 connections) — `performance.sh`
- **log_error()** (5 connections) — `performance.sh`
- **check_dependencies()** (5 connections) — `start-demo.sh`
- **wait_for_health()** (5 connections) — `start-demo.sh`
- **show_summary()** (4 connections) — `performance.sh`
- **cleanup()** (4 connections) — `start-demo.sh`
- **ensure_certificates()** (4 connections) — `start-demo.sh`
- **log_error()** (4 connections) — `start-demo.sh`
- **rebuild_proxy()** (4 connections) — `start-demo.sh`
- **start_demo()** (4 connections) — `start-demo.sh`
- **setup_results_dir()** (3 connections) — `performance.sh`
- **log_warning()** (3 connections) — `start-demo.sh`
- **start-demo.sh script** (3 connections) — `start-demo.sh`
- *... and 10 more nodes in this community*

## Relationships

- No strong cross-community connections detected

## Source Files

- `performance.sh`
- `start-demo.sh`

## Audit Trail

- EXTRACTED: 95 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*