// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package quicbaas

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	sdkparamstore "github.com/jeremyhahn/go-quicbaas/sdk/go/client/parameterstore"
	quicbaasErrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	xkmsstorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Fake ParameterStore client
// =============================================================================

// fakeParamStore is an in-memory implementation of sdkparamstore.Client used
// exclusively in tests. It stores values in a simple map with no encryption.
type fakeParamStore struct {
	mu     sync.RWMutex
	data   map[string][]byte
	getErr error
	putErr error
	delErr error
}

func newFakeParamStore() *fakeParamStore {
	return &fakeParamStore{data: make(map[string][]byte)}
}

func (f *fakeParamStore) GetParameter(_ context.Context, req *sdkparamstore.GetParameterRequest) (*sdkparamstore.GetParameterResponse, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.data[req.Path]
	if !ok {
		return nil, quicbaasErrors.NewNotFound("parameterstore.GetParameter", "not found: "+req.Path)
	}
	return &sdkparamstore.GetParameterResponse{
		Parameter: &sdkparamstore.ParameterValue{
			Path:  req.Path,
			Value: v,
		},
		Timestamp: time.Now(),
	}, nil
}

func (f *fakeParamStore) SetParameter(_ context.Context, req *sdkparamstore.SetParameterRequest) (*sdkparamstore.SetParameterResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.putErr != nil {
		return nil, f.putErr
	}
	if !req.Overwrite {
		if _, ok := f.data[req.Path]; ok {
			return nil, quicbaasErrors.NewAlreadyExists("parameterstore.SetParameter", "already exists: "+req.Path)
		}
	}
	f.data[req.Path] = req.Value
	return &sdkparamstore.SetParameterResponse{
		Path:      req.Path,
		Created:   true,
		Timestamp: time.Now(),
	}, nil
}

func (f *fakeParamStore) DeleteParameter(_ context.Context, req *sdkparamstore.DeleteParameterRequest) (*sdkparamstore.DeleteParameterResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.delErr != nil {
		return nil, f.delErr
	}
	_, ok := f.data[req.Path]
	if !ok {
		return &sdkparamstore.DeleteParameterResponse{Path: req.Path, Deleted: false}, nil
	}
	delete(f.data, req.Path)
	return &sdkparamstore.DeleteParameterResponse{Path: req.Path, Deleted: true, Timestamp: time.Now()}, nil
}

func (f *fakeParamStore) GetParameters(_ context.Context, req *sdkparamstore.GetParametersRequest) (*sdkparamstore.GetParametersResponse, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	params := make([]*sdkparamstore.ParameterValue, 0, len(req.Paths))
	errs := make(map[string]string)
	for _, path := range req.Paths {
		v, ok := f.data[path]
		if !ok {
			errs[path] = "not found"
			continue
		}
		params = append(params, &sdkparamstore.ParameterValue{Path: path, Value: v})
	}
	return &sdkparamstore.GetParametersResponse{Parameters: params, Errors: errs}, nil
}

func (f *fakeParamStore) SetParameters(_ context.Context, req *sdkparamstore.SetParametersRequest) (*sdkparamstore.SetParametersResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	results := make([]*sdkparamstore.SetParameterResult, 0, len(req.Parameters))
	for _, p := range req.Parameters {
		f.data[p.Path] = p.Value
		results = append(results, &sdkparamstore.SetParameterResult{Path: p.Path, Created: true, Success: true})
	}
	return &sdkparamstore.SetParametersResponse{Results: results}, nil
}

func (f *fakeParamStore) DeleteParameters(_ context.Context, req *sdkparamstore.DeleteParametersRequest) (*sdkparamstore.DeleteParametersResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	results := make([]*sdkparamstore.DeleteParameterResult, 0, len(req.Paths))
	for _, path := range req.Paths {
		_, ok := f.data[path]
		delete(f.data, path)
		results = append(results, &sdkparamstore.DeleteParameterResult{Path: path, Deleted: ok})
	}
	return &sdkparamstore.DeleteParametersResponse{Results: results}, nil
}

func (f *fakeParamStore) ListParameters(_ context.Context, req *sdkparamstore.ListParametersRequest) (*sdkparamstore.ListParametersResponse, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var params []*sdkparamstore.ParameterValue
	for k, v := range f.data {
		if req.Prefix == "" || (len(k) >= len(req.Prefix) && k[:len(req.Prefix)] == req.Prefix) {
			pv := &sdkparamstore.ParameterValue{Path: k}
			if req.WithValues {
				pv.Value = v
			}
			params = append(params, pv)
		}
	}
	return &sdkparamstore.ListParametersResponse{Parameters: params}, nil
}

func (f *fakeParamStore) SearchByTags(_ context.Context, _ *sdkparamstore.SearchByTagsRequest) (*sdkparamstore.SearchByTagsResponse, error) {
	return &sdkparamstore.SearchByTagsResponse{}, nil
}

// newTestBackend wraps a fakeParamStore in a pinStoreBackend for testing.
func newTestBackend(fake *fakeParamStore) *pinStoreBackend {
	return &pinStoreBackend{ps: fake}
}

// =============================================================================
// NewPinStoreBackend constructor tests
// =============================================================================

func TestNewPinStoreBackend_NilSDKClient(t *testing.T) {
	t.Parallel()
	_, err := NewPinStoreBackend(nil)
	require.Error(t, err)
	var nilErr ErrNilPinStoreBackend
	assert.ErrorAs(t, err, &nilErr)
}

// =============================================================================
// Get
// =============================================================================

func TestPinStoreBackend_Get_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeParamStore()
	b := newTestBackend(fake)

	require.NoError(t, b.Put(ctx, "trust/tofu/pins/host:8443", []byte(`{"host":"host"}`)))

	got, err := b.Get(ctx, "trust/tofu/pins/host:8443")
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"host":"host"}`), got)
}

func TestPinStoreBackend_Get_MissingKeyReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	_, err := b.Get(ctx, "trust/tofu/pins/absent:443")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkmsstorage.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

// TestPinStoreBackend_Get_NilParameterFieldReturnsErrNotFound pins the dual-signal
// behaviour: some transports return a successful response with Parameter=nil
// for absent keys instead of a CodeNotFound error. The adapter must translate
// this to ErrNotFound so StoragePinStore semantics are preserved.
func TestPinStoreBackend_Get_NilParameterFieldReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A ParameterStore fake that returns nil response (no error, no parameter)
	// to simulate the embedded transport short-circuit path.
	nilRespPS := &nilResponseParamStore{}
	b := &pinStoreBackend{ps: nilRespPS}

	_, err := b.Get(ctx, "trust/tofu/pins/host:443")
	require.Error(t, err)
	assert.True(t, errors.Is(err, xkmsstorage.ErrNotFound), "nil response must map to ErrNotFound, got: %v", err)
}

func TestPinStoreBackend_Get_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeParamStore()
	fake.getErr = errors.New("transport failure")
	b := newTestBackend(fake)

	_, err := b.Get(ctx, "trust/tofu/pins/host:443")
	require.Error(t, err)
	var getErr *ErrPinStoreGet
	assert.ErrorAs(t, err, &getErr)
	assert.Equal(t, "trust/tofu/pins/host:443", getErr.Key)
}

// =============================================================================
// Put
// =============================================================================

func TestPinStoreBackend_Put_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "trust/tofu/pins/host:8443", []byte("data")))

	got, err := b.Get(ctx, "trust/tofu/pins/host:8443")
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

func TestPinStoreBackend_Put_OverwritesExistingValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "k", []byte("v1")))
	require.NoError(t, b.Put(ctx, "k", []byte("v2")))

	got, err := b.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
}

func TestPinStoreBackend_Put_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeParamStore()
	fake.putErr = errors.New("storage unavailable")
	b := newTestBackend(fake)

	err := b.Put(ctx, "k", []byte("v"))
	require.Error(t, err)
	var putErr *ErrPinStorePut
	assert.ErrorAs(t, err, &putErr)
}

// =============================================================================
// PutIfAbsent
// =============================================================================

func TestPinStoreBackend_PutIfAbsent_AbsentKeyStored(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	stored, err := b.PutIfAbsent(ctx, "trust/tofu/pins/host:443", []byte("pin1"))
	require.NoError(t, err)
	assert.True(t, stored, "first call must store the value")

	got, err := b.Get(ctx, "trust/tofu/pins/host:443")
	require.NoError(t, err)
	assert.Equal(t, []byte("pin1"), got)
}

func TestPinStoreBackend_PutIfAbsent_PresentKeyNotOverwritten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	_, err := b.PutIfAbsent(ctx, "k", []byte("original"))
	require.NoError(t, err)

	stored, err := b.PutIfAbsent(ctx, "k", []byte("second"))
	require.NoError(t, err)
	assert.False(t, stored, "second call must not overwrite existing value")

	// Confirm original value is unchanged.
	got, err := b.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), got)
}

func TestPinStoreBackend_PutIfAbsent_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeParamStore()
	fake.putErr = errors.New("network failure")
	b := newTestBackend(fake)

	_, err := b.PutIfAbsent(ctx, "k", []byte("v"))
	require.Error(t, err)
	var putErr *ErrPinStorePut
	assert.ErrorAs(t, err, &putErr)
}

// =============================================================================
// Delete
// =============================================================================

func TestPinStoreBackend_Delete_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "k", []byte("v")))
	require.NoError(t, b.Delete(ctx, "k"))

	_, err := b.Get(ctx, "k")
	assert.True(t, errors.Is(err, xkmsstorage.ErrNotFound))
}

func TestPinStoreBackend_Delete_AbsentKeyIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	// Deleting a non-existent key must not return an error (idempotent).
	require.NoError(t, b.Delete(ctx, "trust/tofu/pins/absent:443"))
}

func TestPinStoreBackend_Delete_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeParamStore()
	fake.delErr = errors.New("i/o error")
	b := newTestBackend(fake)

	err := b.Delete(ctx, "k")
	require.Error(t, err)
	var delErr *ErrPinStoreDelete
	assert.ErrorAs(t, err, &delErr)
}

// =============================================================================
// List
// =============================================================================

func TestPinStoreBackend_List_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "trust/tofu/pins/a:443", []byte("1")))
	require.NoError(t, b.Put(ctx, "trust/tofu/pins/b:443", []byte("2")))
	require.NoError(t, b.Put(ctx, "other/key", []byte("3")))

	keys, err := b.List(ctx, "trust/tofu/pins/")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestPinStoreBackend_List_EmptyPrefix(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "a", []byte("1")))
	require.NoError(t, b.Put(ctx, "b", []byte("2")))

	keys, err := b.List(ctx, "")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

// =============================================================================
// Scan
// =============================================================================

func TestPinStoreBackend_Scan_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "trust/tofu/pins/a:443", []byte("va")))
	require.NoError(t, b.Put(ctx, "trust/tofu/pins/b:443", []byte("vb")))

	collected := make(map[string][]byte)
	err := b.Scan(ctx, "trust/tofu/pins/", func(k string, v []byte) error {
		collected[k] = v
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, collected, 2)
}

func TestPinStoreBackend_Scan_EarlyStopOnCallbackError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "k/1", []byte("v1")))
	require.NoError(t, b.Put(ctx, "k/2", []byte("v2")))

	sentinel := errors.New("stop")
	count := 0
	err := b.Scan(ctx, "k/", func(_ string, _ []byte) error {
		count++
		return sentinel
	})
	require.Error(t, err)
	assert.Equal(t, 1, count, "scan must stop after first callback error")
}

// =============================================================================
// Exists
// =============================================================================

func TestPinStoreBackend_Exists_Present(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	require.NoError(t, b.Put(ctx, "k", []byte("v")))

	ok, err := b.Exists(ctx, "k")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestPinStoreBackend_Exists_Absent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	b := newTestBackend(newFakeParamStore())

	ok, err := b.Exists(ctx, "absent")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestPinStoreBackend_Exists_BackendError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fake := newFakeParamStore()
	fake.getErr = errors.New("timeout")
	b := newTestBackend(fake)

	_, err := b.Exists(ctx, "k")
	require.Error(t, err)
	var existsErr *ErrPinStoreExists
	assert.ErrorAs(t, err, &existsErr)
}

// =============================================================================
// Close
// =============================================================================

func TestPinStoreBackend_Close_IsNoOp(t *testing.T) {
	t.Parallel()
	b := newTestBackend(newFakeParamStore())
	require.NoError(t, b.Close(), "Close must not return an error")
	// Second close must also succeed (no double-close panic).
	require.NoError(t, b.Close())
}

// =============================================================================
// Error types
// =============================================================================

func TestPinStoreBackend_ErrorTypes_Wrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("underlying")

	t.Run("ErrPinStoreGet", func(t *testing.T) {
		t.Parallel()
		e := &ErrPinStoreGet{Key: "k", Err: cause}
		assert.ErrorIs(t, e, cause)
		assert.Contains(t, e.Error(), "k")
	})

	t.Run("ErrPinStorePut", func(t *testing.T) {
		t.Parallel()
		e := &ErrPinStorePut{Key: "k", Err: cause}
		assert.ErrorIs(t, e, cause)
		assert.Contains(t, e.Error(), "k")
	})

	t.Run("ErrPinStoreDelete", func(t *testing.T) {
		t.Parallel()
		e := &ErrPinStoreDelete{Key: "k", Err: cause}
		assert.ErrorIs(t, e, cause)
		assert.Contains(t, e.Error(), "k")
	})

	t.Run("ErrPinStoreScan", func(t *testing.T) {
		t.Parallel()
		e := &ErrPinStoreScan{Prefix: "p", Err: cause}
		assert.ErrorIs(t, e, cause)
		assert.Contains(t, e.Error(), "p")
	})

	t.Run("ErrPinStoreList", func(t *testing.T) {
		t.Parallel()
		e := &ErrPinStoreList{Prefix: "p", Err: cause}
		assert.ErrorIs(t, e, cause)
		assert.Contains(t, e.Error(), "p")
	})

	t.Run("ErrPinStoreExists", func(t *testing.T) {
		t.Parallel()
		e := &ErrPinStoreExists{Key: "k", Err: cause}
		assert.ErrorIs(t, e, cause)
		assert.Contains(t, e.Error(), "k")
	})

	t.Run("ErrNilPinStoreBackend", func(t *testing.T) {
		t.Parallel()
		e := ErrNilPinStoreBackend{}
		assert.NotEmpty(t, e.Error())
	})
}

// =============================================================================
// Helper types for edge case tests
// =============================================================================

// nilResponseParamStore returns a nil response with no error to simulate the
// embedded transport behaviour where absent keys produce an empty response
// rather than a CodeNotFound error.
type nilResponseParamStore struct {
	fakeParamStore
}

func (n *nilResponseParamStore) GetParameter(_ context.Context, _ *sdkparamstore.GetParameterRequest) (*sdkparamstore.GetParameterResponse, error) {
	return nil, nil
}
