//go:build conformance

package conformance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The budget is the only thing between this suite and an invoice, and until now
// nothing exercised it: the ceiling refusal had no test, and the zero-budget
// branch was unreachable because the one caller runs in a seeding process, where
// the limit is never zero (ADR 0027 D4, D5).
func TestBudgetRefusesWhatItCannotPayFor(t *testing.T) {
	t.Run("a zero budget refuses the first byte", func(t *testing.T) {
		b := &Budget{limit: 0}

		err := b.Reserve("some/key", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "this run may not write",
			"the refusal has to say which run is allowed to write")
		assert.Zero(t, b.Spent(), "a refused reservation spends nothing")
	})

	t.Run("the ceiling refuses what would cross it", func(t *testing.T) {
		b := &Budget{limit: 1000}

		require.NoError(t, b.Reserve("first", 600))
		assert.Equal(t, int64(600), b.Spent())

		err := b.Reserve("second", 500)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "byte budget exhausted")
		assert.Equal(t, int64(600), b.Spent(),
			"the refused reservation must be given back, or the run misreports what it spent")

		// Exactly the remainder still fits: the ceiling is inclusive.
		require.NoError(t, b.Reserve("third", 400))
		assert.Equal(t, int64(1000), b.Spent())

		require.Error(t, b.Reserve("fourth", 1))
	})

	t.Run("nothing costs nothing", func(t *testing.T) {
		b := &Budget{limit: 0}
		require.NoError(t, b.Reserve("empty", 0), "a zero-byte object is free even under a zero budget")
		assert.Zero(t, b.Spent())
	})

	t.Run("a read-only process gets a zero budget", func(t *testing.T) {
		t.Setenv("S3EP_CONFORMANCE_SEED", "")
		require.False(t, IsSeedRun())
		assert.Error(t, NewBudget().Reserve("anything", 1))

		t.Setenv("S3EP_CONFORMANCE_SEED", "1")
		require.True(t, IsSeedRun())
		assert.NoError(t, NewBudget().Reserve("anything", 1))
	})
}
