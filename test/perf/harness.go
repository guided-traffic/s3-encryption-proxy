//go:build perf

// Package perf is the local performance baseline suite (ADR 0020 D17).
//
// It is deliberately outside the `integration` build tag and is referenced by
// no CI workflow: the baseline is a local instrument, run on demand against two
// commits on the same machine. Run it with `make perf-baseline`.
//
// Every instrument writes Measurement values into the package recorder; TestMain
// emits one run.json and one REPORT.md per run so two runs can be diffed
// mechanically.
package perf

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is bumped whenever the shape of run.json changes in a way that
// breaks a mechanical diff against an older run.
const SchemaVersion = 1

// Measurement is the single uniform record every instrument produces. Keeping
// one shape for throughput, request rates and nanosecond microbenchmarks is what
// makes a future run diffable without per-instrument parsing.
type Measurement struct {
	Instrument string    `json:"instrument"`
	Transport  string    `json:"transport"`
	Operation  string    `json:"operation"`
	Subject    string    `json:"subject"`
	SizeBytes  int64     `json:"size_bytes"`
	Unit       string    `json:"unit"`
	Samples    []float64 `json:"samples"`
	N          int       `json:"n"`
	Median     float64   `json:"median"`
	Mean       float64   `json:"mean"`
	Min        float64   `json:"min"`
	Max        float64   `json:"max"`
	P90        float64   `json:"p90"`
	StdDev     float64   `json:"stddev"`
	RSDPercent float64   `json:"rsd_pct"`
	Note       string    `json:"note,omitempty"`
}

// InstrumentStatus records why an instrument produced nothing, so a report can
// never be mistaken for a complete run.
type InstrumentStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"` // ok | blocked | skipped
	Reason string `json:"reason,omitempty"`
}

type GitInfo struct {
	Commit   string `json:"commit"`
	Branch   string `json:"branch"`
	Dirty    bool   `json:"dirty"`
	Describe string `json:"describe"`
}

type Hardware struct {
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	OSVersion   string    `json:"os_version"`
	Kernel      string    `json:"kernel"`
	CPUModel    string    `json:"cpu_model"`
	CPUPhysical int       `json:"cpu_physical"`
	CPULogical  int       `json:"cpu_logical"`
	MemoryBytes int64     `json:"memory_bytes"`
	GoVersion   string    `json:"go_version"`
	GOMAXPROCS  int       `json:"gomaxprocs"`
	Docker      string    `json:"docker,omitempty"`
	LoadBefore  []float64 `json:"load_before,omitempty"`
	LoadAfter   []float64 `json:"load_after,omitempty"`
	OnBattery   string    `json:"power_source,omitempty"`
}

type StackInfo struct {
	Available   bool              `json:"available"`
	Reason      string            `json:"reason,omitempty"`
	Endpoints   map[string]string `json:"endpoints,omitempty"`
	Images      map[string]string `json:"images,omitempty"`
	ProxyConfig map[string]string `json:"proxy_config,omitempty"`
}

type RunInfo struct {
	ID           string  `json:"id"`
	Label        string  `json:"label"`
	StartedUTC   string  `json:"started_utc"`
	FinishedUTC  string  `json:"finished_utc"`
	DurationSecs float64 `json:"duration_s"`
	Repetitions  int     `json:"repetitions"`
	Git          GitInfo `json:"git"`
}

type Run struct {
	SchemaVersion int                `json:"schema_version"`
	Run           RunInfo            `json:"run"`
	Hardware      Hardware           `json:"hardware"`
	Stack         StackInfo          `json:"stack"`
	Instruments   []InstrumentStatus `json:"instruments"`
	Measurements  []Measurement      `json:"measurements"`
}

var (
	recMu        sync.Mutex
	measurements []Measurement
	statuses     []InstrumentStatus
	runStart     time.Time
	hardware     Hardware
	stack        StackInfo
)

// Record stores a finished measurement. Safe for concurrent use.
func Record(m Measurement) {
	m.fill()
	recMu.Lock()
	defer recMu.Unlock()
	measurements = append(measurements, m)
}

// SetStatus records an instrument's outcome exactly once.
func SetStatus(id, status, reason string) {
	recMu.Lock()
	defer recMu.Unlock()
	for i := range statuses {
		if statuses[i].ID == id {
			statuses[i] = InstrumentStatus{ID: id, Status: status, Reason: reason}
			return
		}
	}
	statuses = append(statuses, InstrumentStatus{ID: id, Status: status, Reason: reason})
}

func (m *Measurement) fill() {
	s := append([]float64(nil), m.Samples...)
	sort.Float64s(s)
	m.N = len(s)
	if m.N == 0 {
		return
	}
	m.Min, m.Max = s[0], s[len(s)-1]
	m.Median = quantile(s, 0.5)
	m.P90 = quantile(s, 0.9)
	var sum float64
	for _, v := range s {
		sum += v
	}
	m.Mean = sum / float64(m.N)
	if m.N > 1 {
		var acc float64
		for _, v := range s {
			acc += (v - m.Mean) * (v - m.Mean)
		}
		m.StdDev = math.Sqrt(acc / float64(m.N-1))
	}
	if m.Mean != 0 {
		m.RSDPercent = m.StdDev / m.Mean * 100
	}
}

// quantile interpolates on an already-sorted slice.
func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	return sorted[lo] + (sorted[hi]-sorted[lo])*(pos-float64(lo))
}

// Reps is the repetition count every instrument uses. Higher than the three of
// ADR 0020 D7 because this run is local and unattended.
func Reps() int {
	if v := os.Getenv("S3EP_PERF_REPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 7
}

// RunLabel names the run in the report, e.g. "pre-v2".
func RunLabel() string {
	if v := os.Getenv("S3EP_PERF_LABEL"); v != "" {
		return v
	}
	return "unlabelled"
}

// OutDir is the directory this run writes into.
func OutDir() string {
	if v := os.Getenv("S3EP_PERF_OUTDIR"); v != "" {
		return v
	}
	return filepath.Join("..", "..", "perf-baseline")
}

func sh(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func collectGit() GitInfo {
	return GitInfo{
		Commit:   sh("git", "rev-parse", "HEAD"),
		Branch:   sh("git", "rev-parse", "--abbrev-ref", "HEAD"),
		Dirty:    sh("git", "status", "--porcelain") != "",
		Describe: sh("git", "describe", "--tags", "--always", "--dirty"),
	}
}

func collectHardware() Hardware {
	h := Hardware{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		GoVersion:  runtime.Version(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		CPULogical: runtime.NumCPU(),
		Kernel:     sh("uname", "-sr"),
		Docker:     sh("docker", "--version"),
	}
	switch runtime.GOOS {
	case "darwin":
		h.CPUModel = sh("sysctl", "-n", "machdep.cpu.brand_string")
		h.OSVersion = sh("sw_vers", "-productVersion")
		if v := sh("sysctl", "-n", "hw.physicalcpu"); v != "" {
			h.CPUPhysical, _ = strconv.Atoi(v)
		}
		if v := sh("sysctl", "-n", "hw.memsize"); v != "" {
			h.MemoryBytes, _ = strconv.ParseInt(v, 10, 64)
		}
		// Thermal/power state changes the numbers on a laptop; record it.
		if p := sh("pmset", "-g", "ps"); p != "" {
			if strings.Contains(p, "AC Power") {
				h.OnBattery = "AC"
			} else {
				h.OnBattery = "battery"
			}
		}
	case "linux":
		if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "model name") {
					if i := strings.Index(line, ":"); i >= 0 {
						h.CPUModel = strings.TrimSpace(line[i+1:])
					}
					break
				}
			}
		}
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "MemTotal:") {
					f := strings.Fields(line)
					if len(f) >= 2 {
						kb, _ := strconv.ParseInt(f[1], 10, 64)
						h.MemoryBytes = kb * 1024
					}
					break
				}
			}
		}
		h.OSVersion = sh("sh", "-c", ". /etc/os-release 2>/dev/null && echo $PRETTY_NAME")
	}
	if h.CPUPhysical == 0 {
		h.CPUPhysical = h.CPULogical
	}
	h.LoadBefore = loadAverage()
	return h
}

func loadAverage() []float64 {
	out := sh("uptime")
	i := strings.LastIndex(out, "average")
	if i < 0 {
		return nil
	}
	fields := strings.FieldsFunc(out[i:], func(r rune) bool {
		return r == ' ' || r == ',' || r == ':'
	})
	var res []float64
	for _, f := range fields {
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			res = append(res, v)
			if len(res) == 3 {
				break
			}
		}
	}
	return res
}

// Init prepares the recorder. Called from TestMain before any instrument runs.
func Init() {
	runStart = time.Now()
	hardware = collectHardware()
}

// SetStack records what the measured stack was, or why there was none.
func SetStack(s StackInfo) {
	recMu.Lock()
	defer recMu.Unlock()
	stack = s
}

// ErrNothingMeasured is returned when a run produced no measurement at all — a
// filtered or fully skipped invocation. Such a run is not written: an empty
// record beside real ones is noise a later reader has to rule out.
var ErrNothingMeasured = errors.New("perf: no measurement was recorded")

// Emit writes run.json and REPORT.md and returns the run directory.
func Emit() (string, error) {
	recMu.Lock()
	defer recMu.Unlock()

	if len(measurements) == 0 && len(statuses) == 0 {
		return "", ErrNothingMeasured
	}

	git := collectGit()
	finish := time.Now()
	short := git.Commit
	if len(short) > 7 {
		short = short[:7]
	}
	id := fmt.Sprintf("%s-%s", runStart.UTC().Format("20060102T150405Z"), short)
	hardware.LoadAfter = loadAverage()

	run := Run{
		SchemaVersion: SchemaVersion,
		Run: RunInfo{
			ID:           id,
			Label:        RunLabel(),
			StartedUTC:   runStart.UTC().Format(time.RFC3339),
			FinishedUTC:  finish.UTC().Format(time.RFC3339),
			DurationSecs: finish.Sub(runStart).Seconds(),
			Repetitions:  Reps(),
			Git:          git,
		},
		Hardware:     hardware,
		Stack:        stack,
		Instruments:  statuses,
		Measurements: measurements,
	}

	dir := filepath.Join(OutDir(), id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(renderReport(run)), 0o600); err != nil {
		return "", err
	}
	// A stable path so a follow-up run can be diffed without looking up the id.
	_ = os.WriteFile(filepath.Join(OutDir(), "LATEST"), []byte(id+"\n"), 0o600)
	return dir, nil
}
