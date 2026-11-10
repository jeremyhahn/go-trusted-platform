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

package certstore

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errCov964List is the failure the object store returns from List.
var errCov964List = errors.New("object store list failed")

// cov964ObjectAdapter returns an ObjectStorageAdapter backed by the mock
// object store whose List call returns keys and listErr.
func cov964ObjectAdapter(keys []string, listErr error) (*ObjectStorageAdapter, *MockObjectStorer) {
	objStore := new(MockObjectStorer)
	objStore.On("List", "").Return(keys, listErr)
	adapter := &ObjectStorageAdapter{
		objStore: objStore,
		logger:   logging.NewLogger(0, io.Discard),
	}
	return adapter, objStore
}

func TestCov964ListCerts_FiltersKeysToCertificateIDs(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		want []string
	}{
		{
			name: "plain certificate keys",
			keys: []string{"root-ca.pem", "intermediate.pem"},
			want: []string{"root-ca", "intermediate"},
		},
		{
			name: "chain files are skipped",
			keys: []string{"device.pem", "device.chain.pem"},
			want: []string{"device"},
		},
		{
			name: "non-pem keys are skipped",
			keys: []string{"device.pem", "device.key", "notes.txt", "crl.der"},
			want: []string{"device"},
		},
		{
			name: "nested keys are reduced to their base name",
			keys: []string{"tenants/acme/web.pem", "issued/ca/sub.chain.pem"},
			want: []string{"web"},
		},
		{
			name: "a bare suffix yields no id",
			keys: []string{".pem", "dir/.pem", "kept.pem"},
			want: []string{"kept"},
		},
		{
			name: "only chains and foreign files list nothing",
			keys: []string{"a.chain.pem", "b.json"},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, objStore := cov964ObjectAdapter(tt.keys, nil)

			ids, err := adapter.ListCerts(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, ids)
			objStore.AssertExpectations(t)
		})
	}
}

func TestCov964ListCerts_ListErrorYieldsEmptyList(t *testing.T) {
	adapter, objStore := cov964ObjectAdapter(nil, errCov964List)

	ids, err := adapter.ListCerts(context.Background())
	require.NoError(t, err)
	require.NotNil(t, ids, "a failed listing returns an empty, non-nil list")
	assert.Empty(t, ids)
	objStore.AssertExpectations(t)
}

func TestCov964SanitizeCertID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{name: "empty", id: "", want: ""},
		{name: "allowed characters pass through", id: "a-Z_0.9/x", want: "a-Z_0.9/x"},
		{name: "space becomes hyphen", id: "Device CN", want: "Device-CN"},
		{name: "run of disallowed collapses to one hyphen", id: "a @ # b", want: "a-b"},
		{name: "leading disallowed are dropped", id: "  *lead", want: "lead"},
		{name: "trailing hyphen is trimmed", id: "tail@@", want: "tail"},
		{name: "leading and trailing dots are trimmed", id: ".hidden.", want: "hidden"},
		{name: "non-ascii is replaced", id: "café.example", want: "caf-.example"},
		{name: "only disallowed yields empty", id: "@#$ ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeCertID(tt.id))
		})
	}
}

func TestCov964ImportCertificate_ParseErrorUnwrapsToCause(t *testing.T) {
	adapter := NewTPM2CertStoreAdapter(logging.NewLogger(0, io.Discard), new(MockCertStore))
	attrs := &xkmssdk.KeyAttributes{CN: "test.example.com"}
	malformed, err := EncodePEM([]byte("not a DER certificate"))
	require.NoError(t, err)

	cert, err := adapter.ImportCertificate(attrs, malformed)
	require.Error(t, err)
	assert.Nil(t, cert)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "certstore: failed to parse certificate", wrapped.Msg)
	require.NotNil(t, wrapped.Unwrap(), "the parse failure is kept as the cause")
	assert.Equal(t, wrapped.Err, errors.Unwrap(err))

	_, parseErr := x509.ParseCertificate([]byte("not a DER certificate"))
	require.Error(t, parseErr)
	assert.Equal(t, parseErr.Error(), wrapped.Unwrap().Error())
}

func TestCov964WrappedError_ErrorsIsReachesCause(t *testing.T) {
	cause := errors.New("root cause")
	err := error(&WrappedError{Msg: "certstore: context", Err: cause})

	assert.ErrorIs(t, err, cause)
	assert.Equal(t, "certstore: context: root cause", err.Error())
	assert.NotErrorIs(t, err, ErrInvalidPEM)
}
