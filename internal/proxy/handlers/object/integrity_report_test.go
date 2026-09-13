package object

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/monitoring"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// ---------------------------------------------------------------------------
// What a failed read leaves behind (ADR 0003 D15).
//
// The proxy streams, so a fault found after the status line is out can only cut
// the body - there is no error document left to write. The whole point of that
// trade is that the truncation is not silent: it has to name the object in the
// log and move a counter that is otherwise zero, because the request itself is
// still counted as the 200 it announced.
// ---------------------------------------------------------------------------

// ObjIntcapture swaps the handler's logger for one that records, and returns the
// hook.
func ObjIntcapture(h *Handler) *logrustest.Hook {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetOutput(io.Discard)
	hook := logrustest.NewLocal(logger)
	h.logger = logrus.NewEntry(logger)
	return hook
}

// ObjIntcount reads one series of the integrity counter.
func ObjIntcount(reason, phase string) float64 {
	return testutil.ToFloat64(monitoring.ObjectIntegrityFailures.WithLabelValues(reason, phase))
}

// ObjIntentry finds the first entry at the given level.
func ObjIntentry(t *testing.T, hook *logrustest.Hook, level logrus.Level) *logrus.Entry {
	t.Helper()
	for _, entry := range hook.AllEntries() {
		if entry.Level == level {
			return entry
		}
	}
	t.Fatalf("no %s entry was logged, got %d entries", level, len(hook.AllEntries()))
	return nil
}

// A segment that does not authenticate is found after the status line is out,
// because the trailer is read and verified first. The body is cut, and that is
// the one failure the request metric cannot show.
func TestObjIntAMidStreamFaultIsLoggedAndCounted(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	plaintext := ObjGetpayload(3 * dataencryption.SegmentSize)
	ciphertext, metadata := ObjGetstore(t, h, "k", plaintext)

	// One byte of the first segment's ciphertext. The trailer still opens, so
	// the refusal cannot be taken before the response begins.
	corrupt := append([]byte(nil), ciphertext...)
	corrupt[17] ^= 0xff
	ObjGetserve(backend, corrupt, metadata)

	hook := ObjIntcapture(h)
	before := ObjIntcount("authentication", monitoring.IntegrityPhaseMidStream)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	// The status was announced before the fault and cannot be taken back.
	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotEqual(t, ObjGetdigest(plaintext), ObjGetdigest(rr.Body.Bytes()),
		"a corrupt object must not be served as if it were whole")

	assert.Equal(t, before+1, ObjIntcount("authentication", monitoring.IntegrityPhaseMidStream),
		"a truncated read is invisible in s3ep_requests_total, so it has to move this counter")

	entry := ObjIntentry(t, hook, logrus.ErrorLevel)
	assert.Contains(t, entry.Message, "truncated")
	assert.Equal(t, "b", entry.Data["bucket"])
	assert.Equal(t, "k", entry.Data["key"])
	assert.Equal(t, "authentication", entry.Data["reason"],
		"the log line has to say what failed, not only that something did")
}

// A refusal taken before the response is the same failure at a different moment,
// and the phase is what tells them apart.
func TestObjIntARefusalIsCountedBeforeTheResponse(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	plaintext := ObjGetpayload(2 * dataencryption.SegmentSize)
	ciphertext, metadata := ObjGetstore(t, h, "k", plaintext)

	// The trailer itself, which the tail-first read opens before it answers.
	corrupt := append([]byte(nil), ciphertext...)
	corrupt[len(corrupt)-3] ^= 0xff
	ObjGetserve(backend, corrupt, metadata)

	before := ObjIntcount("authentication", monitoring.IntegrityPhaseBeforeResponse)

	rr := ObjGetdo(h, httptest.NewRequest(http.MethodGet, "/b/k", nil), "b", "k")

	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Equal(t, "InvalidObjectState", ObjGetparseError(t, rr.Body.Bytes()).Code)
	assert.Equal(t, before+1, ObjIntcount("authentication", monitoring.IntegrityPhaseBeforeResponse))
}

// A client that hangs up is not an integrity failure, and counting it as one
// would make the metric that is supposed to stay at zero useless.
func TestObjIntAClientDisconnectIsNotAnIntegrityFailure(t *testing.T) {
	backend := new(MockS3Backend)
	h := ObjGetnewHandler(t, backend)

	plaintext := ObjGetpayload(2 * dataencryption.SegmentSize)
	ciphertext, metadata := ObjGetstore(t, h, "k", plaintext)
	ObjGetserve(backend, ciphertext, metadata)

	hook := ObjIntcapture(h)
	before := ObjIntcount("authentication", monitoring.IntegrityPhaseMidStream)

	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/b/k", nil),
		map[string]string{"bucket": "b", "key": "k"})
	h.Handle(&ObjIntfailingWriter{header: http.Header{}}, req)

	assert.Equal(t, before, ObjIntcount("authentication", monitoring.IntegrityPhaseMidStream),
		"a client that went away did not corrupt anything")

	entry := ObjIntentry(t, hook, logrus.WarnLevel)
	assert.Contains(t, entry.Message, "stopped before the object ended")
}

// ObjIntfailingWriter is a ResponseWriter whose body writes always fail, which
// is what a client that disconnected looks like to a handler.
type ObjIntfailingWriter struct {
	header http.Header
	status int
}

func (w *ObjIntfailingWriter) Header() http.Header  { return w.header }
func (w *ObjIntfailingWriter) WriteHeader(code int) { w.status = code }
func (w *ObjIntfailingWriter) Write([]byte) (int, error) {
	return 0, assert.AnError
}
