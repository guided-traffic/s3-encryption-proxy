package orchestration

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// ===== Multipart fixtures (OrcPart token; helpers shared with singlepart) =====

// OrcPartUploadID is the upload id used by the multipart tests.
const OrcPartUploadID = "orcpart-upload"

// OrcPartNewMultipartOps builds MultipartOperations on real providers; only the
// failure injection below is faked.
func OrcPartNewMultipartOps(t *testing.T, cfg *config.Config) *MultipartOperations {
	t.Helper()
	providerManager, err := NewProviderManager(cfg)
	require.NoError(t, err)
	return NewMultipartOperations(
		providerManager,
		validation.NewHMACManager(cfg),
		NewMetadataManager(cfg, ""),
		cfg,
	)
}

// OrcPartInitiate starts a session and asserts the invariants every caller relies on.
func OrcPartInitiate(t *testing.T, mpo *MultipartOperations, objectKey string) *MultipartSession {
	t.Helper()
	session, err := mpo.InitiateSession(context.Background(), OrcPartUploadID, objectKey, "bucket")
	require.NoError(t, err)
	require.NotNil(t, session)
	require.Equal(t, 1, session.ExpectedPartNumber)
	return session
}

// OrcPartProcessPart uploads one part and drains the ciphertext it produced.
func OrcPartProcessPart(t *testing.T, mpo *MultipartOperations, partNumber int, data []byte) []byte {
	t.Helper()
	result, err := mpo.ProcessPart(context.Background(), OrcPartUploadID, partNumber, OrcPartReader(data))
	require.NoError(t, err)
	require.NotNil(t, result)
	ciphertext, err := io.ReadAll(result.EncryptedData)
	require.NoError(t, err)
	return ciphertext
}

// OrcPartWaitForPending blocks until partNumber sits in the session's pending
// map, so a test can act on a part that is provably parked.
func OrcPartWaitForPending(t *testing.T, session *MultipartSession, partNumber int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		session.OrderingMutex.Lock()
		_, buffered := session.PendingParts[partNumber]
		session.OrderingMutex.Unlock()
		if buffered {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("part %d was never buffered", partNumber)
}

// OrcPartExpectedHMAC computes the HMAC the proxy must store for plaintext
// under dek.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func OrcPartExpectedHMAC(t *testing.T, mpo *MultipartOperations, dek, plaintext []byte) string {
	t.Helper()
	calculator, err := mpo.hmacManager.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = calculator.Add(plaintext)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(mpo.hmacManager.FinalizeCalculator(calculator))
}

// ===== The session lifecycle, from the caller's point of view =====

// TestOrcPartMultipartLifecycleRoundTrip runs the whole documented lifecycle -
// initiate, several parts, ETags, finalize - and asserts the client contract:
// no part is stored in the clear, and the concatenated parts decrypt back to
// exactly what was uploaded.
func TestOrcPartMultipartLifecycleRoundTrip(t *testing.T) {
	ctx := context.Background()

	for _, mode := range []string{config.HMACVerificationStrict, config.HMACVerificationOff} {
		t.Run(mode, func(t *testing.T) {
			mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(mode))
			session := OrcPartInitiate(t, mpo, "bucket/big-object")
			assert.Equal(t, 1, mpo.GetSessionCount())

			var plaintext, ciphertext []byte
			for i, size := range []int{1000, 3000, 512} {
				part := OrcPartPayload(size + i)
				encrypted := OrcPartProcessPart(t, mpo, i+1, part)
				assert.Len(t, encrypted, len(part), "CTR keeps the part length")
				assert.NotEqual(t, OrcPartSHA256(part), OrcPartSHA256(encrypted),
					"a part must never reach the backend as plaintext")

				require.NoError(t, mpo.StorePartETag(OrcPartUploadID, i+1, fmt.Sprintf("etag-%d", i+1)))
				plaintext = append(plaintext, part...)
				ciphertext = append(ciphertext, encrypted...)
			}

			assert.Equal(t, 4, session.ExpectedPartNumber)
			assert.Len(t, session.PartETags, 3)

			metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
			require.NoError(t, err)
			assert.Equal(t, "aes-ctr", metadata["s3ep-dek-algorithm"])
			assert.NotEmpty(t, metadata["s3ep-encrypted-dek"])
			assert.NotEmpty(t, metadata["s3ep-kek-fingerprint"])
			if mode == config.HMACVerificationStrict {
				assert.Contains(t, metadata, "s3ep-hmac")
			} else {
				assert.NotContains(t, metadata, "s3ep-hmac")
			}

			decrypted, err := mpo.DecryptMultipartWithHMACVerification(
				ctx, "bucket/big-object", metadata, OrcPartReader(ciphertext))
			require.NoError(t, err)
			got, err := io.ReadAll(decrypted)
			require.NoError(t, err)
			assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))

			require.NoError(t, mpo.CleanupSession(OrcPartUploadID))
			assert.Equal(t, 0, mpo.GetSessionCount())
		})
	}
}

// TestOrcPartMultipartHMACCoversPartsInAscendingOrder delivers the parts to the
// proxy out of order (3, then 2, then 1) and asserts that both the stored HMAC
// and the CTR keystream follow ascending part numbers, not arrival order.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcPartMultipartHMACCoversPartsInAscendingOrder(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	session := OrcPartInitiate(t, mpo, "bucket/out-of-order")
	dek := append([]byte(nil), session.DEK...)

	part1 := OrcPartPayload(700)
	part2 := OrcPartPayload(1300)
	part3 := OrcPartPayload(900)

	type partResult struct {
		data []byte
		err  error
	}
	upload := func(partNumber int, data []byte) chan partResult {
		out := make(chan partResult, 1)
		go func() {
			result, err := mpo.ProcessPart(ctx, OrcPartUploadID, partNumber, OrcPartReader(data))
			if err != nil {
				out <- partResult{err: err}
				return
			}
			encrypted, readErr := io.ReadAll(result.EncryptedData)
			out <- partResult{data: encrypted, err: readErr}
		}()
		return out
	}

	third := upload(3, part3)
	OrcPartWaitForPending(t, session, 3)
	second := upload(2, part2)
	OrcPartWaitForPending(t, session, 2)

	cipher1 := OrcPartProcessPart(t, mpo, 1, part1)
	result2 := <-second
	require.NoError(t, result2.err)
	result3 := <-third
	require.NoError(t, result3.err)

	metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)

	plaintext := append(append(append([]byte(nil), part1...), part2...), part3...)
	assert.Equal(t, OrcPartExpectedHMAC(t, mpo, dek, plaintext), metadata["s3ep-hmac"],
		"the stored HMAC is taken over the parts in ascending part-number order")

	ascending := append(append(append([]byte(nil), cipher1...), result2.data...), result3.data...)
	decrypted, err := mpo.DecryptMultipartWithHMACVerification(
		ctx, "bucket/out-of-order", metadata, OrcPartReader(ascending))
	require.NoError(t, err)
	got, err := io.ReadAll(decrypted)
	require.NoError(t, err)
	assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))

	// Assembling the same ciphertext in arrival order must not verify: it proves
	// the keystream position is bound to the part order, not to the upload order.
	arrival := append(append(append([]byte(nil), result3.data...), result2.data...), cipher1...)
	broken, err := mpo.DecryptMultipartWithHMACVerification(
		ctx, "bucket/out-of-order", metadata, OrcPartReader(arrival))
	require.NoError(t, err)
	_, err = io.ReadAll(broken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

// TestOrcPartMultipartTamperedPartIsRejected: one flipped ciphertext bit must
// stop the download before the final chunk is released.
func TestOrcPartMultipartTamperedPartIsRejected(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/tampered")

	part := OrcPartPayload(4096)
	ciphertext := OrcPartProcessPart(t, mpo, 1, part)
	metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)

	ciphertext[10] ^= 0x01
	reader, err := mpo.DecryptMultipartWithHMACVerification(
		ctx, "bucket/tampered", metadata, OrcPartReader(ciphertext))
	require.NoError(t, err)

	got, err := io.ReadAll(reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed")
	assert.NotEqual(t, OrcPartSHA256(part), OrcPartSHA256(got))
}

// ===== Failure modes of the session API =====

// TestOrcPartSessionOperationsRejectUnknownUploadID pins the exact error text
// every entry point produces for an upload id that was never initiated.
func TestOrcPartSessionOperationsRejectUnknownUploadID(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	want := "multipart upload ghost not found"

	_, err := mpo.ProcessPart(ctx, "ghost", 1, OrcPartReader(OrcPartPayload(16)))
	require.EqualError(t, err, want)

	_, err = mpo.FinalizeSession(ctx, "ghost")
	require.EqualError(t, err, want)

	require.EqualError(t, mpo.AbortSession(ctx, "ghost"), want)
	require.EqualError(t, mpo.CleanupSession("ghost"), want)
	require.EqualError(t, mpo.StorePartETag("ghost", 1, "etag"), want)

	_, err = mpo.GetSession("ghost")
	require.EqualError(t, err, want)
}

// TestOrcPartInitiateSessionRejectsDuplicateUploadID: a second CreateMultipartUpload
// under the same id must not silently reset the session state of the first.
func TestOrcPartInitiateSessionRejectsDuplicateUploadID(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	first := OrcPartInitiate(t, mpo, "bucket/key")

	_, err := mpo.InitiateSession(context.Background(), OrcPartUploadID, "bucket/other", "bucket")
	require.EqualError(t, err, "multipart upload "+OrcPartUploadID+" already exists")

	still, err := mpo.GetSession(OrcPartUploadID)
	require.NoError(t, err)
	assert.Same(t, first, still)
	assert.Equal(t, 1, mpo.GetSessionCount())
}

// TestOrcPartProcessPartRejectsOutOfRangePartNumbers pins the S3 part-number
// range (1..10000) and its exact error text.
func TestOrcPartProcessPartRejectsOutOfRangePartNumbers(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")

	for _, partNumber := range []int{0, -1, 10001} {
		_, err := mpo.ProcessPart(context.Background(), OrcPartUploadID, partNumber,
			OrcPartReader(OrcPartPayload(8)))
		require.Error(t, err)
		assert.Equal(t,
			fmt.Sprintf("invalid part number %d: must be between 1 and 10000", partNumber),
			err.Error())
	}
}

// TestOrcPartProcessPartPropagatesBodyReadError: a part whose body dies must
// fail, never be stored short.
func TestOrcPartProcessPartPropagatesBodyReadError(t *testing.T) {
	boom := errors.New("connection reset by peer")
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")

	src := bufio.NewReader(&OrcPartFailingReader{payload: OrcPartPayload(128), err: boom})
	_, err := mpo.ProcessPart(context.Background(), OrcPartUploadID, 1, src)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "failed to read part data")
}

// TestOrcPartProcessPartFailsOnBrokenSessionState covers the two ways a part can
// fail after its bytes were read.
func TestOrcPartProcessPartFailsOnBrokenSessionState(t *testing.T) {
	ctx := context.Background()

	t.Run("no CTR encryptor", func(t *testing.T) {
		mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
		session := OrcPartInitiate(t, mpo, "bucket/key")
		session.CTREncryptor = nil

		_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 1, OrcPartReader(OrcPartPayload(64)))
		require.Error(t, err)
		assert.Equal(t, "CTR encryptor not initialized for session "+OrcPartUploadID, err.Error())
	})

	t.Run("HMAC calculator already released", func(t *testing.T) {
		mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
		session := OrcPartInitiate(t, mpo, "bucket/key")
		require.NotNil(t, session.HMACCalculator)
		session.HMACCalculator.Cleanup()

		_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 1, OrcPartReader(OrcPartPayload(64)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update HMAC")
	})
}

// TestOrcPartProcessBufferedPartsReportsFailureToTheWaiter: when a buffered part
// cannot be processed once its turn comes, the goroutine parked on it must be
// woken with that error instead of waiting forever.
func TestOrcPartProcessBufferedPartsReportsFailureToTheWaiter(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	session := OrcPartInitiate(t, mpo, "bucket/key")

	buffered := &PartBuffer{
		PartNumber: 2,
		Data:       OrcPartPayload(64),
		ResultChan: make(chan *EncryptionResult, 1),
		ErrorChan:  make(chan error, 1),
	}
	session.OrderingMutex.Lock()
	session.PendingParts[2] = buffered
	session.OrderingMutex.Unlock()

	session.CTREncryptor = nil
	mpo.processBufferedPartsData(session)

	select {
	case err := <-buffered.ErrorChan:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CTR encryptor not initialized")
	case result := <-buffered.ResultChan:
		t.Fatalf("expected a failure, got a result: %+v", result)
	default:
		t.Fatal("the waiting part was never notified")
	}
	assert.Empty(t, session.PendingParts)
}

// TestOrcPartFinalizeSessionFailsWhenTheKEKIsGone: without a usable KEK the DEK
// cannot be wrapped, and finalizing must fail rather than emit metadata that
// cannot decrypt the object.
func TestOrcPartFinalizeSessionFailsWhenTheKEKIsGone(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	OrcPartProcessPart(t, mpo, 1, OrcPartPayload(128))

	mpo.providerManager.activeFingerprint = "fingerprint-of-a-key-that-is-gone"
	_, err := mpo.FinalizeSession(context.Background(), OrcPartUploadID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to encrypt DEK")
}

// TestOrcPartFinalizeSessionWithoutAnyPart records that finalizing a session
// that never received a part succeeds and returns complete metadata, with an
// HMAC over zero bytes. Rejecting the empty upload is left to the handler.
func TestOrcPartFinalizeSessionWithoutAnyPart(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	session := OrcPartInitiate(t, mpo, "bucket/empty")
	dek := append([]byte(nil), session.DEK...)

	metadata, err := mpo.FinalizeSession(context.Background(), OrcPartUploadID)
	require.NoError(t, err)
	assert.Equal(t, "aes-ctr", metadata["s3ep-dek-algorithm"])
	assert.Equal(t, OrcPartExpectedHMAC(t, mpo, dek, nil), metadata["s3ep-hmac"],
		"the HMAC of an upload with no parts is the HMAC of the empty stream")
}

// TestOrcPartFinalizeSessionTwiceDropsTheHMAC records that FinalizeSession is
// not idempotent: the first call consumes and releases the HMAC calculator, so a
// second call - a retried CompleteMultipartUpload - returns metadata WITHOUT
// s3ep-hmac while the proxy runs in strict mode. The object then stores no
// integrity tag at all, and nothing in the return value says so.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcPartFinalizeSessionTwiceDropsTheHMAC(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	OrcPartProcessPart(t, mpo, 1, OrcPartPayload(256))

	first, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)
	require.Contains(t, first, "s3ep-hmac")

	second, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err, "the second finalize is accepted")
	assert.NotContains(t, second, "s3ep-hmac", "the integrity tag is silently gone")
	assert.Equal(t, first["s3ep-kek-fingerprint"], second["s3ep-kek-fingerprint"])
	assert.NotEqual(t, first["s3ep-encrypted-dek"], second["s3ep-encrypted-dek"],
		"the DEK is re-wrapped under a fresh IV on every finalize")
}

// TestOrcPartFinalizeSessionDoesNotReleaseTheSession: the session map is only
// drained by CleanupSession, AbortSession or the expiry sweep. A caller that
// finalizes and then fails before cleaning up keeps the session - with its DEK -
// alive until the background sweep removes it.
func TestOrcPartFinalizeSessionDoesNotReleaseTheSession(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	OrcPartProcessPart(t, mpo, 1, OrcPartPayload(64))

	_, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)
	assert.Equal(t, 1, mpo.GetSessionCount(), "finalize leaves the session in place")

	session, err := mpo.GetSession(OrcPartUploadID)
	require.NoError(t, err)
	assert.NotEmpty(t, session.DEK, "the DEK is still resident after finalize")

	require.NoError(t, mpo.CleanupSession(OrcPartUploadID))
	assert.Equal(t, 0, mpo.GetSessionCount())
	assert.Equal(t, make([]byte, 32), session.DEK, "cleanup zeroes the DEK")
}

// TestOrcPartAbortSessionIsNotIdempotent: the second abort of the same upload
// reports "not found", so a handler that retries its own cleanup has to absorb
// that error. It also pins that the abort wipes the key material it held.
func TestOrcPartAbortSessionIsNotIdempotent(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	session := OrcPartInitiate(t, mpo, "bucket/key")
	OrcPartProcessPart(t, mpo, 1, OrcPartPayload(64))

	require.NoError(t, mpo.AbortSession(ctx, OrcPartUploadID))
	assert.Equal(t, 0, mpo.GetSessionCount())
	assert.Equal(t, make([]byte, 32), session.DEK, "abort zeroes the DEK")
	assert.Equal(t, make([]byte, 16), session.IV, "abort zeroes the IV")

	err := mpo.AbortSession(ctx, OrcPartUploadID)
	require.EqualError(t, err, "multipart upload "+OrcPartUploadID+" not found")
}

// TestOrcPartProcessPartAfterAbortFails: no part may be encrypted into a session
// that was already torn down.
func TestOrcPartProcessPartAfterAbortFails(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	require.NoError(t, mpo.AbortSession(ctx, OrcPartUploadID))

	_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 1, OrcPartReader(OrcPartPayload(32)))
	require.EqualError(t, err, "multipart upload "+OrcPartUploadID+" not found")
}

// ===== Out-of-order parking: who wakes a parked part, and when =====

// TestOrcPartRetriedPartNumberParksUntilTheSessionEnds is a liveness defect.
// S3 lets a client re-upload a part number to replace it, but this
// implementation compares against a monotonically increasing "expected part"
// counter: a part number that was already processed lands in the out-of-order
// buffer, where nothing will ever pick it up again. ProcessPart has no timeout
// ("the proxy handles request timeouts"), so the UploadPart goroutine and its
// buffered part data stay parked until the session is aborted, cleaned up, or
// swept by the expiry job (default max age: 1 hour).
func TestOrcPartRetriedPartNumberParksUntilTheSessionEnds(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	session := OrcPartInitiate(t, mpo, "bucket/key")

	OrcPartProcessPart(t, mpo, 1, OrcPartPayload(64))
	OrcPartProcessPart(t, mpo, 2, OrcPartPayload(64))
	require.Equal(t, 3, session.ExpectedPartNumber)

	done := make(chan error, 1)
	go func() {
		_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 1, OrcPartReader(OrcPartPayload(128)))
		done <- err
	}()
	OrcPartWaitForPending(t, session, 1)

	select {
	case err := <-done:
		t.Fatalf("the retried part returned instead of parking: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	require.NoError(t, mpo.AbortSession(ctx, OrcPartUploadID))
	select {
	case err := <-done:
		require.EqualError(t, err, "session aborted")
	case <-time.After(3 * time.Second):
		t.Fatal("abort did not release the parked part")
	}
}

// TestOrcPartPendingPartsAreReleasedByEveryTeardownPath pins which message a
// parked part receives from each of the three teardown routes.
func TestOrcPartPendingPartsAreReleasedByEveryTeardownPath(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		teardown func(t *testing.T, mpo *MultipartOperations)
		wantErr  string
	}{
		{
			name: "abort",
			teardown: func(t *testing.T, mpo *MultipartOperations) {
				require.NoError(t, mpo.AbortSession(ctx, OrcPartUploadID))
			},
			wantErr: "session aborted",
		},
		{
			name: "cleanup",
			teardown: func(t *testing.T, mpo *MultipartOperations) {
				require.NoError(t, mpo.CleanupSession(OrcPartUploadID))
			},
			wantErr: "session cleaned up",
		},
		{
			name: "expiry sweep",
			teardown: func(t *testing.T, mpo *MultipartOperations) {
				assert.Equal(t, 1, mpo.CleanupExpiredSessions(0))
			},
			wantErr: "session expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
			session := OrcPartInitiate(t, mpo, "bucket/key")

			done := make(chan error, 1)
			go func() {
				_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 2, OrcPartReader(OrcPartPayload(64)))
				done <- err
			}()
			OrcPartWaitForPending(t, session, 2)

			tc.teardown(t, mpo)

			select {
			case err := <-done:
				require.EqualError(t, err, tc.wantErr)
			case <-time.After(3 * time.Second):
				t.Fatal("the parked part was never released")
			}
			assert.Equal(t, 0, mpo.GetSessionCount())
		})
	}
}

// TestOrcPartCleanupExpiredSessionsKeepsFreshSessions: the sweep must only take
// sessions older than maxAge.
func TestOrcPartCleanupExpiredSessionsKeepsFreshSessions(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")

	assert.Equal(t, 0, mpo.CleanupExpiredSessions(time.Hour))
	assert.Equal(t, 1, mpo.GetSessionCount())

	assert.Equal(t, 1, mpo.CleanupExpiredSessions(0))
	assert.Equal(t, 0, mpo.GetSessionCount())
	assert.Equal(t, 0, mpo.CleanupExpiredSessions(0), "an empty registry sweeps to zero")
}

// ===== The none provider: pass-through by configuration =====

// TestOrcPartNoneProviderMultipartStoresPlaintext documents what the "none"
// provider does on the multipart path: the part reader is handed to the backend
// unchanged, no metadata is produced, and finalizing returns nil metadata. This
// is the configured behaviour, and it is the one configuration in which object
// data is NOT encrypted at rest.
func TestOrcPartNoneProviderMultipartStoresPlaintext(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartNoneConfig())

	session, err := mpo.InitiateSession(ctx, OrcPartUploadID, "bucket/key", "bucket")
	require.NoError(t, err)
	assert.Equal(t, "none-provider-fingerprint", session.KeyFingerprint)
	assert.Nil(t, session.DEK)
	assert.Nil(t, session.CTREncryptor)

	part := OrcPartPayload(2048)
	result, err := mpo.ProcessPart(ctx, OrcPartUploadID, 1, OrcPartReader(part))
	require.NoError(t, err)
	assert.Equal(t, "none", result.Algorithm)
	assert.Nil(t, result.Metadata)

	stored, err := io.ReadAll(result.EncryptedData)
	require.NoError(t, err)
	assert.Equal(t, OrcPartSHA256(part), OrcPartSHA256(stored),
		"the none provider stores the plaintext verbatim")

	metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)
	assert.Nil(t, metadata)

	require.NoError(t, mpo.AbortSession(ctx, OrcPartUploadID))
	assert.Equal(t, 0, mpo.GetSessionCount())
}

// ===== The multipart download reader =====

// TestOrcPartDecryptMultipartRejectsBrokenMetadata walks the metadata fields the
// multipart read path needs.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcPartDecryptMultipartRejectsBrokenMetadata(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	ciphertext := OrcPartProcessPart(t, mpo, 1, OrcPartPayload(512))
	base, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)

	tests := []struct {
		name    string
		mutate  func(md map[string]string)
		wantMsg string
	}{
		{"no encrypted dek", func(md map[string]string) { delete(md, "s3ep-encrypted-dek") }, "failed to get encrypted DEK"},
		{"no fingerprint", func(md map[string]string) { delete(md, "s3ep-kek-fingerprint") }, "failed to get key fingerprint"},
		{"unknown fingerprint", func(md map[string]string) { md["s3ep-kek-fingerprint"] = "0000dead" }, "failed to decrypt DEK"},
		{"no iv", func(md map[string]string) { delete(md, "s3ep-aes-iv") }, "failed to get IV"},
		{"no hmac", func(md map[string]string) { delete(md, "s3ep-hmac") }, "failed to get HMAC from metadata"},
		{"truncated iv", func(md map[string]string) {
			md["s3ep-aes-iv"] = base64.StdEncoding.EncodeToString([]byte("short"))
		}, "failed to create CTR decryptor"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			md := make(map[string]string, len(base))
			for k, v := range base {
				md[k] = v
			}
			tc.mutate(md)

			_, err := mpo.DecryptMultipartWithHMACVerification(ctx, "bucket/key", md, OrcPartReader(ciphertext))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestOrcPartDecryptMultipartWithoutHMACMode: with integrity verification off
// the object is decrypted without any verification, and an object stored
// without an HMAC is served without complaint.
func TestOrcPartDecryptMultipartWithoutHMACMode(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationOff))
	OrcPartInitiate(t, mpo, "bucket/key")

	part := OrcPartPayload(3000)
	ciphertext := OrcPartProcessPart(t, mpo, 1, part)
	metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)
	require.NotContains(t, metadata, "s3ep-hmac")

	reader, err := mpo.DecryptMultipartWithHMACVerification(ctx, "bucket/key", metadata, OrcPartReader(ciphertext))
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, OrcPartSHA256(part), OrcPartSHA256(got))
}

// TestOrcPartDecryptMultipartPropagatesBodyErrors: a backend body that dies
// mid-stream must surface, not truncate.
func TestOrcPartDecryptMultipartPropagatesBodyErrors(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("backend stream closed")
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	ciphertext := OrcPartProcessPart(t, mpo, 1, OrcPartPayload(4096))
	metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)

	src := bufio.NewReader(&OrcPartFailingReader{payload: ciphertext, err: boom})
	reader, err := mpo.DecryptMultipartWithHMACVerification(ctx, "bucket/key", metadata, src)
	require.NoError(t, err)
	_, err = io.ReadAll(reader)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

// TestOrcPartMultipartSessionAccessorsExposeTheSessionState pins what the
// handler can read back from a live session.
func TestOrcPartMultipartSessionAccessorsExposeTheSessionState(t *testing.T) {
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	created := OrcPartInitiate(t, mpo, "bucket/key")

	assert.Len(t, created.DEK, 32)
	assert.Len(t, created.IV, 16)
	assert.Equal(t, "bucket", created.BucketName)
	assert.Equal(t, "bucket/key", created.ObjectKey)
	assert.Equal(t, "aes-ctr", created.Metadata["s3ep-dek-algorithm"])
	assert.False(t, created.IsCompleted)
	assert.NotNil(t, created.HMACCalculator)

	require.NoError(t, mpo.StorePartETag(OrcPartUploadID, 7, "\"etag-7\""))
	fetched, err := mpo.GetSession(OrcPartUploadID)
	require.NoError(t, err)
	assert.Equal(t, "\"etag-7\"", fetched.PartETags[7])
}

// TestOrcPartDecryptMultipartWithAMalformedWrappedDEK: a wrapped DEK that is
// too short to be one is rejected while unwrapping, and the error says so
// instead of surfacing further down as a failure to derive some other key
// (ADR 0004).
func TestOrcPartDecryptMultipartWithAMalformedWrappedDEK(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	OrcPartInitiate(t, mpo, "bucket/key")
	ciphertext := OrcPartProcessPart(t, mpo, 1, OrcPartPayload(256))
	metadata, err := mpo.FinalizeSession(ctx, OrcPartUploadID)
	require.NoError(t, err)

	// 16 bytes: the salt of a wrap and nothing else.
	metadata["s3ep-encrypted-dek"] = base64.StdEncoding.EncodeToString(make([]byte, 16))

	_, err = mpo.DecryptMultipartWithHMACVerification(ctx, "bucket/key", metadata, OrcPartReader(ciphertext))
	require.Error(t, err)
	assert.ErrorIs(t, err, keyencryption.ErrWrappedDEKAuth)
}

// TestOrcPartFailedPartStrandsTheBufferedFollowers: when the expected part
// fails, processPartOrdered returns without advancing ExpectedPartNumber and
// without notifying the parts already parked behind it, so every later part
// waits for a teardown that may never come from the client.
func TestOrcPartFailedPartStrandsTheBufferedFollowers(t *testing.T) {
	ctx := context.Background()
	mpo := OrcPartNewMultipartOps(t, OrcPartAESConfig(config.HMACVerificationStrict))
	session := OrcPartInitiate(t, mpo, "bucket/key")

	parked := make(chan error, 1)
	go func() {
		_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 2, OrcPartReader(OrcPartPayload(64)))
		parked <- err
	}()
	OrcPartWaitForPending(t, session, 2)

	session.CTREncryptor = nil
	_, err := mpo.ProcessPart(ctx, OrcPartUploadID, 1, OrcPartReader(OrcPartPayload(64)))
	require.Error(t, err, "part 1 fails")

	select {
	case err := <-parked:
		t.Fatalf("part 2 returned instead of staying parked: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	assert.Equal(t, 1, session.ExpectedPartNumber, "the sequence never advanced past the failure")

	require.NoError(t, mpo.AbortSession(ctx, OrcPartUploadID))
	select {
	case err := <-parked:
		require.EqualError(t, err, "session aborted")
	case <-time.After(3 * time.Second):
		t.Fatal("abort did not release the stranded part")
	}
}
