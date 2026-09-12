package main

import (
	"context"
	"errors"
	"testing"
	"time"

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
		closeListener: func() { order = append(order, "close") },
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
		closeListener: func() {},
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
		closeListener: func() { order = append(order, "close") },
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
		closeListener: func() { closed = true },
	})

	assert.True(t, closed)
}
