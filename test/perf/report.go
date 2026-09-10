//go:build perf

package perf

import (
	"fmt"
	"sort"
	"strings"
)

// unstableRSD is the relative standard deviation above which a row is marked as
// too noisy to compare against another run. It is a reporting mark, not a gate.
const unstableRSD = 10.0

func renderReport(r Run) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Performance baseline — %s\n\n", r.Run.Label)
	fmt.Fprintf(&b, "Run `%s`, schema %d. %s → %s (%.0f s), %d repetitions per point.\n\n",
		r.Run.ID, r.SchemaVersion, r.Run.StartedUTC, r.Run.FinishedUTC, r.Run.DurationSecs, r.Run.Repetitions)

	dirty := ""
	if r.Run.Git.Dirty {
		dirty = " **(working tree dirty)**"
	}
	fmt.Fprintf(&b, "Commit `%s` on `%s`%s.\n\n", r.Run.Git.Commit, r.Run.Git.Branch, dirty)

	b.WriteString("## Machine\n\n")
	b.WriteString("| Property | Value |\n|---|---|\n")
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "| %s | %s |\n", k, v)
		}
	}
	row("CPU", r.Hardware.CPUModel)
	row("Cores", fmt.Sprintf("%d physical / %d logical, GOMAXPROCS %d",
		r.Hardware.CPUPhysical, r.Hardware.CPULogical, r.Hardware.GOMAXPROCS))
	row("Memory", humanBytes(r.Hardware.MemoryBytes))
	row("OS", strings.TrimSpace(r.Hardware.OS+" "+r.Hardware.OSVersion+" ("+r.Hardware.Kernel+")"))
	row("Arch", r.Hardware.Arch)
	row("Go", r.Hardware.GoVersion)
	row("Docker", r.Hardware.Docker)
	row("Power source", r.Hardware.OnBattery)
	row("Load average before", fmtFloats(r.Hardware.LoadBefore))
	row("Load average after", fmtFloats(r.Hardware.LoadAfter))
	b.WriteString("\n")

	b.WriteString("## Stack\n\n")
	if r.Stack.Available {
		b.WriteString("| Property | Value |\n|---|---|\n")
		for _, k := range sortedKeys(r.Stack.Endpoints) {
			row("endpoint "+k, r.Stack.Endpoints[k])
		}
		for _, k := range sortedKeys(r.Stack.Images) {
			row("image "+k, r.Stack.Images[k])
		}
		for _, k := range sortedKeys(r.Stack.ProxyConfig) {
			row("config "+k, r.Stack.ProxyConfig[k])
		}
	} else {
		fmt.Fprintf(&b, "No proxy stack was measured: %s\n", orDash(r.Stack.Reason))
	}
	b.WriteString("\n")

	b.WriteString("## Instruments\n\n")
	b.WriteString("| Instrument | Status | Reason |\n|---|---|---|\n")
	for _, s := range r.Instruments {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", s.ID, s.Status, orDash(s.Reason))
	}
	b.WriteString("\n")

	renderRatioSection(&b, r, "throughput", "Throughput — proxy against direct backend")
	renderRatioSection(&b, r, "rangeread", "Ranged read — proxy against direct backend")
	renderRatioSection(&b, r, "smallobject", "Small objects — request rate")
	renderRatioSection(&b, r, "uploadpath", "Upload write paths — streaming against auto-multipart")
	renderPlainSection(&b, r, "selfcopy", "Backend self-copy (single-leg profiling harness)")
	renderPlainSection(&b, r, "unwrap", "Key unwrap")
	renderPlainSection(&b, r, "cryptofloor", "In-process crypto floor")
	renderPlainSection(&b, r, "memory", "Proxy resident memory")

	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "A row marked unstable has a relative standard deviation above %.0f %%; "+
		"it carries no comparison value against another run.\n", unstableRSD)
	return b.String()
}

// ratioKey groups the measurements that belong in one row: same transport, same
// operation, same size. Every subject measured under that key is compared
// against the reference leg.
type ratioKey struct {
	transport string
	operation string
	size      int64
}

// referenceSubject is the leg every other subject is divided by. A measurement
// without it is reported on its own rather than silently dropped.
const referenceSubject = "direct"

func renderRatioSection(b *strings.Builder, r Run, instrument, title string) {
	rows := map[ratioKey]map[string]Measurement{}
	subjects := map[string]bool{}
	for _, m := range r.Measurements {
		if m.Instrument != instrument {
			continue
		}
		k := ratioKey{m.Transport, m.Operation, m.SizeBytes}
		if rows[k] == nil {
			rows[k] = map[string]Measurement{}
		}
		rows[k][m.Subject] = m
		subjects[m.Subject] = true
	}
	if len(rows) == 0 {
		return
	}

	// Deterministic subject order, reference last so a row reads
	// "this against that".
	others := make([]string, 0, len(subjects))
	for s := range subjects {
		if s != referenceSubject {
			others = append(others, s)
		}
	}
	sort.Strings(others)

	keys := make([]ratioKey, 0, len(rows))
	unit := ""
	for k, bySubject := range rows {
		keys = append(keys, k)
		for _, m := range bySubject {
			unit = m.Unit
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].transport != keys[j].transport {
			return keys[i].transport < keys[j].transport
		}
		if keys[i].operation != keys[j].operation {
			return keys[i].operation < keys[j].operation
		}
		return keys[i].size < keys[j].size
	})

	fmt.Fprintf(b, "## %s\n\n", title)
	fmt.Fprintf(b, "| Transport | Operation | Size | Subject | %s | %s (%s) | Ratio | RSD | Stable |\n",
		unit, referenceSubject, unit)
	b.WriteString("|---|---|---|---|---:|---:|---:|---:|:--:|\n")
	for _, k := range keys {
		ref, hasRef := rows[k][referenceSubject]
		for _, subject := range others {
			m, ok := rows[k][subject]
			if !ok {
				continue
			}
			ratio, refCell := "—", "—"
			if hasRef && ref.Median != 0 {
				ratio = fmt.Sprintf("%.1f %%", m.Median/ref.Median*100)
				refCell = fmt.Sprintf("%.1f", ref.Median)
			}
			stable := "yes"
			if m.RSDPercent > unstableRSD || (hasRef && ref.RSDPercent > unstableRSD) {
				stable = "**no**"
			}
			fmt.Fprintf(b, "| %s | %s | %s | %s | %.1f | %s | %s | %.1f %% | %s |\n",
				k.transport, k.operation, humanBytes(k.size), subject,
				m.Median, refCell, ratio, m.RSDPercent, stable)
		}
	}
	b.WriteString("\n")
}

func renderPlainSection(b *strings.Builder, r Run, instrument, title string) {
	var rows []Measurement
	for _, m := range r.Measurements {
		if m.Instrument == instrument {
			rows = append(rows, m)
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Operation != rows[j].Operation {
			return rows[i].Operation < rows[j].Operation
		}
		if rows[i].Subject != rows[j].Subject {
			return rows[i].Subject < rows[j].Subject
		}
		return rows[i].SizeBytes < rows[j].SizeBytes
	})

	fmt.Fprintf(b, "## %s\n\n", title)
	b.WriteString("| Subject | Operation | Size | Median | Unit | RSD | n | Note |\n")
	b.WriteString("|---|---|---|---:|---|---:|---:|---|\n")
	for _, m := range rows {
		size := "—"
		if m.SizeBytes > 0 {
			size = humanBytes(m.SizeBytes)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %.1f %% | %d | %s |\n",
			m.Subject, m.Operation, size, fmtValue(m.Median), m.Unit, m.RSDPercent, m.N, orDash(m.Note))
	}
	b.WriteString("\n")
}

func fmtValue(v float64) string {
	switch {
	case v >= 1000:
		return fmt.Sprintf("%.0f", v)
	case v >= 10:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.3f", v)
	}
}

func fmtFloats(f []float64) string {
	if len(f) == 0 {
		return ""
	}
	parts := make([]string, len(f))
	for i, v := range f {
		parts[i] = fmt.Sprintf("%.2f", v)
	}
	return strings.Join(parts, " / ")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
