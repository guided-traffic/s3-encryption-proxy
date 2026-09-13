package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UtlCtxKey is the context key used to prove that CleanupContext keeps the
// values of the request context while dropping its cancellation.
type UtlCtxKey struct{}

// CleanupContext must survive the client disconnect that makes it necessary in
// the first place, keep the request values, and still be bounded.
func TestUtlCleanupContext(t *testing.T) {
	reqCtx, cancelReq := context.WithCancel(context.WithValue(context.Background(), UtlCtxKey{}, "carried"))
	defer cancelReq()

	r := httptest.NewRequest(http.MethodDelete, "/bucket/key", nil).WithContext(reqCtx)

	before := time.Now()
	ctx, cancel := CleanupContext(r)
	defer cancel()

	assert.Equal(t, "carried", ctx.Value(UtlCtxKey{}), "request values must survive into the cleanup context")

	deadline, ok := ctx.Deadline()
	require.True(t, ok, "cleanup work must be bounded by a deadline")
	assert.WithinDuration(t, before.Add(cleanupTimeout), deadline, time.Second)
	assert.Equal(t, 30*time.Second, cleanupTimeout, "cleanup budget is part of the contract with the backend")

	// The client goes away: the request context dies, the cleanup context must not.
	cancelReq()
	<-reqCtx.Done()
	require.ErrorIs(t, r.Context().Err(), context.Canceled)
	require.NoError(t, ctx.Err(), "a client disconnect must not cancel the cleanup context")

	cancel()
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "the returned cancel func must still stop the work")
}
