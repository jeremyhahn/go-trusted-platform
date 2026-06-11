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
	"strings"
	"sync"

	quicbaasErrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	sdkparamstore "github.com/jeremyhahn/go-quicbaas/sdk/go/client/parameterstore"
	xkmsstorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage"
	xkmsbootstrap "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"
)

// pinStoreBackend implements xkms storage.Backend over the platform's
// ParameterStore client. It is used exclusively by NewTOFUPinStore to
// back the TOFU pin store with Raft-replicated storage.
//
// Key mapping: keys are passed through verbatim (the StoragePinStore already
// namespaces them under "trust/tofu/pins/"). No additional prefix is applied.
//
// PutIfAbsent atomicity: the ParameterStore service's SetParameter with
// Overwrite:false returns CodeAlreadyExists when a parameter already exists.
// That check is performed server-side with a single RPC; however the service
// implementation performs a Get-then-Put internally (see kv_parameter_manager.go),
// so true cross-node CAS is not available through this surface. We therefore
// serialize PutIfAbsent callers within this process with putIfAbsentMu, matching
// the documented pattern used by quicbaas's own KVStoreStorageAdapter and
// ObjStoreAdapter (see pkg/kms/storage_adapter.go). For the TOFU use case this
// is sufficient: pin contention only occurs at first connection, and any race
// results in the same pin value being written, not conflicting ones.
//
// Close is a deliberate no-op: the ParameterStore client is part of the shared
// SDK client whose lifecycle is managed by the platform Factory. Closing it here
// would tear down the entire client for all callers.
type pinStoreBackend struct {
	ps            sdkparamstore.Client
	putIfAbsentMu sync.Mutex
}

// compile-time interface check.
var _ xkmsstorage.Backend = (*pinStoreBackend)(nil)

// ErrNilPinStoreBackend is returned when the ParameterStore client is nil.
type ErrNilPinStoreBackend struct{}

// Error implements error.
func (e ErrNilPinStoreBackend) Error() string {
	return "quicbaas pinstore: ParameterStore client must not be nil"
}

// ErrPinStoreGet wraps a ParameterStore Get failure.
type ErrPinStoreGet struct {
	Key string
	Err error
}

// Error implements error.
func (e *ErrPinStoreGet) Error() string {
	return "quicbaas pinstore: get " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrPinStoreGet) Unwrap() error { return e.Err }

// ErrPinStorePut wraps a ParameterStore Put failure.
type ErrPinStorePut struct {
	Key string
	Err error
}

// Error implements error.
func (e *ErrPinStorePut) Error() string {
	return "quicbaas pinstore: put " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrPinStorePut) Unwrap() error { return e.Err }

// ErrPinStoreDelete wraps a ParameterStore Delete failure.
type ErrPinStoreDelete struct {
	Key string
	Err error
}

// Error implements error.
func (e *ErrPinStoreDelete) Error() string {
	return "quicbaas pinstore: delete " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrPinStoreDelete) Unwrap() error { return e.Err }

// ErrPinStoreScan wraps a ParameterStore List/Scan failure.
type ErrPinStoreScan struct {
	Prefix string
	Err    error
}

// Error implements error.
func (e *ErrPinStoreScan) Error() string {
	return "quicbaas pinstore: scan " + e.Prefix + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrPinStoreScan) Unwrap() error { return e.Err }

// ErrPinStoreList wraps a ParameterStore List failure.
type ErrPinStoreList struct {
	Prefix string
	Err    error
}

// Error implements error.
func (e *ErrPinStoreList) Error() string {
	return "quicbaas pinstore: list " + e.Prefix + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrPinStoreList) Unwrap() error { return e.Err }

// ErrPinStoreExists wraps a ParameterStore Exists check failure.
type ErrPinStoreExists struct {
	Key string
	Err error
}

// Error implements error.
func (e *ErrPinStoreExists) Error() string {
	return "quicbaas pinstore: exists " + e.Key + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ErrPinStoreExists) Unwrap() error { return e.Err }

// NewPinStoreBackend constructs a storage.Backend backed by the platform's
// ParameterStore. Keys are stored verbatim — the StoragePinStore layer
// above adds the "trust/tofu/pins/" namespace prefix.
//
// Returns ErrNilPinStoreBackend when sdkClient is nil or its ParameterStore
// client is unavailable.
func NewPinStoreBackend(sdkClient *SDKClient) (xkmsstorage.Backend, error) {
	if sdkClient == nil {
		return nil, ErrNilPinStoreBackend{}
	}
	ps := sdkClient.ParameterStore()
	if ps == nil {
		return nil, ErrNilPinStoreBackend{}
	}
	return &pinStoreBackend{ps: ps}, nil
}

// NewTOFUPinStore constructs a TOFU pin store backed by the platform's
// Raft-replicated ParameterStore. It composes NewPinStoreBackend and
// bootstrap.NewStoragePinStore. Returns an error when sdkClient is nil or
// the ParameterStore client is unavailable.
func NewTOFUPinStore(sdkClient *SDKClient) (xkmsbootstrap.PinStore, error) {
	backend, err := NewPinStoreBackend(sdkClient)
	if err != nil {
		return nil, err
	}
	return xkmsbootstrap.NewStoragePinStore(backend)
}

// Get retrieves the raw bytes stored at key. Returns xkmsstorage.ErrNotFound
// when the key does not exist.
//
// The ParameterStore client may signal a missing key in two ways:
//   - An error whose code is CodeNotFound (via quicbaasErrors.IsNotFound).
//   - A successful response with a nil Parameter field (embedded transport
//     short-circuits the error path and returns an empty response for absent keys).
//
// Both signals are translated to xkmsstorage.ErrNotFound so that the
// StoragePinStore semantics are preserved.
func (b *pinStoreBackend) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := b.ps.GetParameter(ctx, &sdkparamstore.GetParameterRequest{
		Path:           key,
		WithDecryption: true,
	})
	if err != nil {
		if quicbaasErrors.IsNotFound(err) || isPinNotFoundString(err) {
			return nil, xkmsstorage.ErrNotFound
		}
		return nil, &ErrPinStoreGet{Key: key, Err: err}
	}
	// Embedded transport may return a successful response with a nil Parameter
	// when the key is absent rather than a CodeNotFound error.
	if resp == nil || resp.Parameter == nil {
		return nil, xkmsstorage.ErrNotFound
	}
	return resp.Parameter.Value, nil
}

// Put stores value at key, overwriting any existing value.
func (b *pinStoreBackend) Put(ctx context.Context, key string, value []byte) error {
	_, err := b.ps.SetParameter(ctx, &sdkparamstore.SetParameterRequest{
		Path:      key,
		Value:     value,
		Type:      "binary",
		Overwrite: true,
	})
	if err != nil {
		return &ErrPinStorePut{Key: key, Err: err}
	}
	return nil
}

// PutIfAbsent stores value at key only when no value is currently stored
// there. Returns stored=true when the write occurred and stored=false when
// the key already existed (the store is left unchanged).
//
// Atomicity guarantee: concurrent callers within this process are serialized
// by putIfAbsentMu. The underlying ParameterStore performs a server-side
// Get-then-Put (see kv_parameter_manager.go), which is not a true cross-node
// CAS. For the TOFU pin-store use case this is sufficient: races only occur
// on the very first connection to a host, and any concurrent winner writes
// the same SPKI value from the same server response.
func (b *pinStoreBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	b.putIfAbsentMu.Lock()
	defer b.putIfAbsentMu.Unlock()

	_, err := b.ps.SetParameter(ctx, &sdkparamstore.SetParameterRequest{
		Path:      key,
		Value:     value,
		Type:      "binary",
		Overwrite: false,
	})
	if err != nil {
		if quicbaasErrors.IsAlreadyExists(err) || isPinAlreadyExistsString(err) {
			return false, nil
		}
		return false, &ErrPinStorePut{Key: key, Err: err}
	}
	return true, nil
}

// Delete removes the key. Returns nil when the key does not exist (idempotent).
func (b *pinStoreBackend) Delete(ctx context.Context, key string) error {
	resp, err := b.ps.DeleteParameter(ctx, &sdkparamstore.DeleteParameterRequest{
		Path: key,
	})
	if err != nil {
		if quicbaasErrors.IsNotFound(err) || isPinNotFoundString(err) {
			return nil
		}
		return &ErrPinStoreDelete{Key: key, Err: err}
	}
	// Deleted=false with no error means the key was absent — idempotent success.
	if resp != nil && !resp.Deleted {
		return nil
	}
	return nil
}

// List returns all keys that have the given prefix. An empty prefix returns
// all keys in the store.
func (b *pinStoreBackend) List(ctx context.Context, prefix string) ([]string, error) {
	resp, err := b.ps.ListParameters(ctx, &sdkparamstore.ListParametersRequest{
		Prefix:     prefix,
		Recursive:  true,
		WithValues: false,
		Limit:      0, // no artificial limit
	})
	if err != nil {
		return nil, &ErrPinStoreList{Prefix: prefix, Err: err}
	}
	if resp == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(resp.Parameters))
	for _, p := range resp.Parameters {
		keys = append(keys, p.Path)
	}
	return keys, nil
}

// Scan iterates over all key-value pairs whose keys share the given prefix,
// calling fn for each pair. Iteration stops early when fn returns a non-nil
// error.
func (b *pinStoreBackend) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	resp, err := b.ps.ListParameters(ctx, &sdkparamstore.ListParametersRequest{
		Prefix:         prefix,
		Recursive:      true,
		WithValues:     true,
		WithDecryption: true,
		Limit:          0,
	})
	if err != nil {
		return &ErrPinStoreScan{Prefix: prefix, Err: err}
	}
	if resp == nil {
		return nil
	}
	for _, p := range resp.Parameters {
		if err := fn(p.Path, p.Value); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether a key is present in the store.
func (b *pinStoreBackend) Exists(ctx context.Context, key string) (bool, error) {
	resp, err := b.ps.GetParameter(ctx, &sdkparamstore.GetParameterRequest{
		Path:           key,
		WithDecryption: false,
	})
	if err != nil {
		if quicbaasErrors.IsNotFound(err) || isPinNotFoundString(err) {
			return false, nil
		}
		return false, &ErrPinStoreExists{Key: key, Err: err}
	}
	if resp == nil || resp.Parameter == nil {
		return false, nil
	}
	return true, nil
}

// Close is a no-op. The ParameterStore client is owned by the platform
// SDKClient whose lifecycle is managed by the Factory; closing it here would
// tear down the shared client for all other callers.
func (b *pinStoreBackend) Close() error { return nil }

// isPinNotFoundString checks whether an error message string indicates a
// not-found condition. This is a fallback for errors wrapped through multiple
// transport layers where code-based matching via quicbaasErrors.IsNotFound
// may not work. The same pattern is used in sdk_storage.go.
func isPinNotFoundString(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "not_found")
}

// isPinAlreadyExistsString checks whether an error message string indicates
// an already-exists condition (fallback for transport-wrapped errors).
func isPinAlreadyExistsString(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "already_exists") ||
		strings.Contains(msg, "exists")
}
