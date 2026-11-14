// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package adminclaim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// #172: the claim's completion is atomic across platformd instances that
// share one store, through a compare-and-swap lease on that store.

// fakeTxnStore is one store shared by several instances: a key/value map
// that runs compare-and-swap transactions atomically.
type fakeTxnStore struct {
	mu    sync.Mutex
	kv    map[string][]byte
	err   error
	calls int
}

func newFakeTxnStore() *fakeTxnStore {
	return &fakeTxnStore{kv: map[string][]byte{}}
}

func (f *fakeTxnStore) Execute(_ context.Context, req *quicbaassdk.TxnRequest) (*quicbaassdk.TxnResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	ok := true
	for _, c := range req.Compare {
		if c.Result != quicbaassdk.CompareEqual {
			return nil, fmt.Errorf("fake store: unsupported compare result %v", c.Result)
		}
		value, present := f.kv[c.Key]
		switch c.Target {
		case quicbaassdk.CompareVersion:
			ok = ok && present == (c.Revision != 0)
		case quicbaassdk.CompareValue:
			ok = ok && present && bytes.Equal(value, c.Value)
		default:
			return nil, fmt.Errorf("fake store: unsupported compare target %v", c.Target)
		}
	}
	ops := req.Success
	if !ok {
		ops = req.Failure
	}
	resp := &quicbaassdk.TxnResponse{Succeeded: ok}
	for _, op := range ops {
		r := quicbaassdk.TxnOpResponse{Type: op.Type}
		switch op.Type {
		case quicbaassdk.TxnOpPut:
			f.kv[op.Key] = bytes.Clone(op.Value)
		case quicbaassdk.TxnOpGet:
			r.Value = bytes.Clone(f.kv[op.Key])
		case quicbaassdk.TxnOpDelete:
			delete(f.kv, op.Key)
		}
		resp.Responses = append(resp.Responses, r)
	}
	return resp, nil
}

func (f *fakeTxnStore) get(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.kv[key]
	return v, ok
}

func (f *fakeTxnStore) put(key string, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kv[key] = value
}

func (f *fakeTxnStore) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.kv)
}

func testCompletionKey() string {
	return completionKey(testTenantID, "admin")
}

func leaseJSON(t *testing.T, holder string, expires time.Time) []byte {
	t.Helper()
	b, err := json.Marshal(completionLease{Holder: holder, ExpiresAt: expires})
	require.NoError(t, err)
	return b
}

// multiInstance returns harness params for one of several instances
// sharing store and factors.
func multiInstance(store *fakeTxnStore, factors *fakeFactors) func(*ServiceParams) {
	return func(p *ServiceParams) {
		p.MultiInstance = true
		p.Transactions = store
		p.Factors = factors
	}
}

func TestFinishPasskey_MultiInstanceCompletesOnceAcrossInstances(t *testing.T) {
	store := newFakeTxnStore()
	factors := &fakeFactors{resp: &quicbaassdk.AuthFactorListResponse{}}
	first := newHarnessWith(t, multiInstance(store, factors))
	second := newHarnessWith(t, multiInstance(store, factors))

	firstToken := first.claimTo(t)
	secondToken := second.claimTo(t)

	// The first instance is mid-enrolment when the second completes.
	entered, proceed := make(chan struct{}), make(chan struct{})
	first.ceremony.onFinish = func() {
		close(entered)
		<-proceed
		factors.enrolFIDO2()
	}
	second.ceremony.onFinish = factors.enrolFIDO2

	done := make(chan error, 1)
	go func() {
		_, err := first.svc.FinishPasskey(context.Background(), firstToken,
			&quicbaassdk.FIDO2FinishRegistrationRequest{})
		done <- err
	}()
	<-entered

	_, err := second.svc.FinishPasskey(context.Background(), secondToken,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.ErrorAs(t, err, &ErrClaimInProgress{},
		"another instance holds the completion lease")
	assert.Zero(t, second.ceremony.finishCalls.Load(),
		"the second instance must not enrol a second authenticator")

	close(proceed)
	require.NoError(t, <-done)
	assert.Zero(t, store.size(), "the lease is released once the claim completes")

	// Once the lease is gone the factor history keeps the claim closed.
	_, _, err = second.svc.Challenge(context.Background())
	require.ErrorAs(t, err, &ErrAlreadyClaimed{})
}

func TestFinishPasskey_ReleasesTheLeaseWhatever(t *testing.T) {
	for name, ceremony := range map[string]func(*fakeCeremony){
		"ceremony error": func(c *fakeCeremony) { c.finishErr = errors.New("attestation failed") },
		"ceremony rejected": func(c *fakeCeremony) {
			c.finishResp = &quicbaassdk.FIDO2FinishRegistrationResponse{Success: false}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeTxnStore()
			h := newHarnessWith(t, multiInstance(store, &fakeFactors{resp: &quicbaassdk.AuthFactorListResponse{}}))
			ceremony(h.ceremony)
			token := h.claimTo(t)

			_, err := h.svc.FinishPasskey(context.Background(), token,
				&quicbaassdk.FIDO2FinishRegistrationRequest{})

			require.Error(t, err)
			assert.Equal(t, int64(1), h.ceremony.finishCalls.Load())
			assert.Zero(t, store.size(), "a failed completion must not leave the claim locked")
		})
	}
}

func TestFinishPasskey_FailsClosedWithoutTheLease(t *testing.T) {
	store := newFakeTxnStore()
	h := newHarnessWith(t, multiInstance(store, &fakeFactors{resp: &quicbaassdk.AuthFactorListResponse{}}))
	token := h.claimTo(t)
	store.err = errors.New("embedded: invalid request type")

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})

	var unavailable ErrCompletionLockUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.ErrorIs(t, err, store.err)
	assert.Zero(t, h.ceremony.finishCalls.Load(), "no enrolment without the lease")
	h.users.mu.Lock()
	defer h.users.mu.Unlock()
	assert.Empty(t, h.users.byID, "no admin record without the lease")
}

func TestFinishPasskey_SingleInstanceTakesTheLeaseWhenWired(t *testing.T) {
	store := newFakeTxnStore()
	h := newHarnessWith(t, func(p *ServiceParams) { p.Transactions = store })
	token := h.claimTo(t)
	h.ceremony.onFinish = func() {
		_, held := store.get(testCompletionKey())
		assert.True(t, held, "the enrolment runs under the lease")
	}

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})

	require.NoError(t, err)
	assert.Zero(t, store.size())
}

func TestCompletionLock_ExpiredLeaseIsTakenOver(t *testing.T) {
	store := newFakeTxnStore()
	stale := leaseJSON(t, "dead-instance", time.Now().Add(-time.Second))
	store.put(testCompletionKey(), stale)
	lock := newCompletionLock(store, testTenantID, "admin")

	release, err := lock.acquire(context.Background())

	require.NoError(t, err)
	held, ok := store.get(testCompletionKey())
	require.True(t, ok)
	assert.NotEqual(t, stale, held, "the lease is now this instance's")
	require.NoError(t, release(context.Background()))
	assert.Zero(t, store.size())
}

func TestCompletionLock_LiveLeaseIsRefused(t *testing.T) {
	store := newFakeTxnStore()
	live := leaseJSON(t, "other-instance", time.Now().Add(time.Minute))
	store.put(testCompletionKey(), live)
	lock := newCompletionLock(store, testTenantID, "admin")

	_, err := lock.acquire(context.Background())

	require.ErrorAs(t, err, &ErrClaimInProgress{})
	held, _ := store.get(testCompletionKey())
	assert.Equal(t, live, held, "a live lease is never overwritten")
}

func TestCompletionLock_ReleaseLeavesASuccessorsLease(t *testing.T) {
	store := newFakeTxnStore()
	lock := newCompletionLock(store, testTenantID, "admin")
	release, err := lock.acquire(context.Background())
	require.NoError(t, err)

	// Our lease expired and another instance took it over.
	successor := leaseJSON(t, "successor", time.Now().Add(time.Minute))
	store.put(testCompletionKey(), successor)

	require.NoError(t, release(context.Background()))
	held, ok := store.get(testCompletionKey())
	require.True(t, ok, "the release must not delete another holder's lease")
	assert.Equal(t, successor, held)
}

func TestProbeTransactions(t *testing.T) {
	require.ErrorAs(t, ProbeTransactions(context.Background(), nil, testTenantID),
		&ErrDependencyRequired{})

	failing := newFakeTxnStore()
	failing.err = errors.New("embedded: invalid request type")
	assert.ErrorIs(t, ProbeTransactions(context.Background(), failing, testTenantID), failing.err)

	store := newFakeTxnStore()
	require.NoError(t, ProbeTransactions(context.Background(), store, testTenantID))
	assert.Equal(t, 1, store.calls)
	assert.Zero(t, store.size(), "the probe writes nothing")
}

func TestWriteClaimError_CompletionLease(t *testing.T) {
	h := newHarness(t)
	handler, err := NewRestHandler(testLogger(), response.NewResponseWriter(testLogger(), nil), h.svc)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	handler.writeClaimError(rec, httptest.NewRequest(http.MethodPost, "/", nil), ErrClaimInProgress{})
	assert.Equal(t, http.StatusConflict, rec.Code)

	rec = httptest.NewRecorder()
	handler.writeClaimError(rec, httptest.NewRequest(http.MethodPost, "/", nil),
		ErrCompletionLockUnavailable{Err: errors.New("store internals")})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotContains(t, rec.Body.String(), "store internals",
		"the store's error is logged, not returned")
}
