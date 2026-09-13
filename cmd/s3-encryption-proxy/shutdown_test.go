package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The order is the decision (ADR 0029 D1): what cannot be finished is swept
// while the listener is still up, so a readiness probe arriving during the
// sweep reads 503 rather than a connection refusal. The code did it the other
// way round until 5.0.0.
func TestMainShutdownSweepsBeforeClosingTheListener(t *testing.T) {
	var order []string

	runShutdownTail(shutdownTail{
		deadline: time.Now().Add(30 * time.Second),
		budget:   30 * time.Second,
		sweep: func(context.Context) error {
			order = append(order, "sweep")
			return nil
		},
		closeListener: func(time.Time) { order = append(order, "close") },
	})

	assert.Equal(t, []string{"sweep", "close"}, order)
}

// The phases are sequential, so their budgets add up. A drain that used part of
// the operator's budget must leave the sweep the rest of it and not a second
// full copy — the pod's termination grace period is derived from one budget, so
// two is how a shutdown is killed halfway through cleaning up (ADR 0029 D3).
func TestMainShutdownSweepGetsWhatIsLeftOfTheBudget(t *testing.T) {
	const budget = 30 * time.Second
	// As if the drain had already spent twenty of the thirty seconds.
	deadline := time.Now().Add(budget - 20*time.Second)

	var got time.Duration
	runShutdownTail(shutdownTail{
		deadline: deadline,
		budget:   budget,
		sweep: func(ctx context.Context) error {
			d, ok := ctx.Deadline()
			require.True(t, ok, "the sweep must be bounded")
			got = time.Until(d)
			return nil
		},
		closeListener: func(time.Time) {},
	})

	assert.InDelta(t, (10 * time.Second).Seconds(), got.Seconds(), 1.0,
		"the sweep got %s of a %s budget", got, budget)
	assert.Less(t, got, budget, "a second full budget is what ADR 0029 D3 forbids")
}

// A drain that used everything still has to close the listener, and the sweep
// still has to be attempted rather than skipped: an upload ended late is better
// than one left at the backend, and the context it gets says it is out of time.
func TestMainShutdownExhaustedBudgetStillSweepsAndCloses(t *testing.T) {
	var order []string
	var deadlineSet bool

	runShutdownTail(shutdownTail{
		deadline: time.Now().Add(-5 * time.Second),
		budget:   30 * time.Second,
		sweep: func(ctx context.Context) error {
			order = append(order, "sweep")
			_, deadlineSet = ctx.Deadline()
			return nil
		},
		closeListener: func(time.Time) { order = append(order, "close") },
	})

	assert.Equal(t, []string{"sweep", "close"}, order)
	assert.True(t, deadlineSet)
}

// A sweep that reports an error must not cost the listener its close: the
// process is exiting either way, and a listener left open is a pod that never
// terminates.
func TestMainShutdownClosesTheListenerEvenWhenTheSweepFails(t *testing.T) {
	var closed bool

	runShutdownTail(shutdownTail{
		deadline:      time.Now().Add(30 * time.Second),
		budget:        30 * time.Second,
		sweep:         func(context.Context) error { return errors.New("backend unreachable") },
		closeListener: func(time.Time) { closed = true },
	})

	assert.True(t, closed)
}

// The listener close is bounded by the same deadline the sweep was, and that
// deadline is the shutdown's one anchor: the moment the signal arrived plus the
// operator's budget. It used to be spelled out twice by hand at the call site,
// where two ends of one budget can drift apart without anything noticing
// (ADR 0029 D3).
func TestMainShutdownListenerGetsTheSameDeadlineAsTheSweep(t *testing.T) {
	anchor := time.Now().Add(17 * time.Second)

	var sweepDeadline, listenerDeadline time.Time
	runShutdownTail(shutdownTail{
		deadline: anchor,
		budget:   30 * time.Second,
		sweep: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			require.True(t, ok, "the sweep must be bounded")
			sweepDeadline = deadline
			return nil
		},
		closeListener: func(deadline time.Time) { listenerDeadline = deadline },
	})

	assert.Equal(t, anchor, listenerDeadline, "the listener close is bounded by the shutdown's anchor")
	assert.WithinDuration(t, anchor, sweepDeadline, 100*time.Millisecond,
		"and so is the sweep, from the same value")
}

// pprof stands on its own: it is a different security surface from the metrics
// endpoint - its heap dump holds data keys - so monitoring.enabled must not gate
// it in either direction (ADR 0013 D8). Re-nesting the two restores a knob that
// silently does nothing, which is the defect the comment in main.go records.
func TestMainMonitoringPlanKeepsPprofIndependent(t *testing.T) {
	cases := map[string]struct {
		metrics, pprof bool
	}{
		"neither":       {false, false},
		"metrics only":  {true, false},
		"pprof only":    {false, true},
		"both together": {true, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Monitoring.Enabled = tc.metrics
			cfg.Monitoring.PprofEnabled = tc.pprof

			metrics, pprof := monitoringPlan(cfg)
			assert.Equal(t, tc.metrics, metrics)
			assert.Equal(t, tc.pprof, pprof, "pprof_enabled decides pprof, and nothing else does")
		})
	}
}

// The startup warning is the only thing that tells an operator this proxy is
// storing plaintext (ADR 0025 D10). Nothing asserted it, so a configuration
// could go quiet on it. The plain-HTTP warning that used to stand beside it is
// gone with the configuration it described: that combination refuses the start
// under every provider now (ADR 0013 D5).
func TestMainStartupWarnings(t *testing.T) {
	exitCfg := func(endpoint string) *config.Config {
		return &config.Config{
			S3Backend: config.S3BackendConfig{TargetEndpoint: endpoint},
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "way-out",
				Providers:             []config.EncryptionProvider{{Alias: "way-out", Type: "exit"}},
			},
		}
	}

	t.Run("an encrypting provider warns about nothing", func(t *testing.T) {
		cfg := &config.Config{
			S3Backend: config.S3BackendConfig{TargetEndpoint: "https://backend:9000"},
			Encryption: config.EncryptionConfig{
				EncryptionMethodAlias: "aes",
				Providers: []config.EncryptionProvider{{
					Alias: "aes", Type: "aes",
					Config: map[string]interface{}{"aes_key": "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="},
				}},
			},
		}
		assert.Empty(t, startupWarnings(cfg))
	})

	t.Run("the exit provider says objects are stored unencrypted", func(t *testing.T) {
		warnings := startupWarnings(exitCfg("https://backend:9000"))
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0].message, "new objects are stored unencrypted")
		assert.Equal(t, "way-out", warnings[0].fields["provider"])
	})

	t.Run("the endpoint scheme adds no second warning", func(t *testing.T) {
		// A plain-HTTP backend cannot reach this function any more: validation
		// refuses that configuration before the server is built, so a warning
		// here would describe a proxy that never starts.
		warnings := startupWarnings(exitCfg("http://backend:9000"))
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0].message, "new objects are stored unencrypted")
	})
}
