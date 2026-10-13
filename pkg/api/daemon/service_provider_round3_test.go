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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVTPMProvider builds a PlatformServiceProvider wired only to the
// supplied vTPM service, which is all the vTPM runtime tests need.
func newVTPMProvider(v vtpm.VTPMService) *PlatformServiceProvider {
	return NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: v})
}

func TestPlatformServiceProvider_VTPMRuntime_Success(t *testing.T) {
	quoteResult := &vtpm.QuoteResult{Quote: []byte("q"), Signature: []byte("s")}
	mock := &mockVTPMService{
		startFunc: func(ctx context.Context, id string) error { return nil },
		stopFunc:  func(ctx context.Context, id string) error { return nil },
		quoteFunc: func(ctx context.Context, id string, n []byte, p []int) (*vtpm.QuoteResult, error) {
			return quoteResult, nil
		},
		sealFunc: func(ctx context.Context, id string, d []byte, o *vtpm.SealOptions) ([]byte, error) {
			return []byte("sealed"), nil
		},
		unsealFunc:    func(ctx context.Context, id string, d []byte, a string) ([]byte, error) { return []byte("plain"), nil },
		extendPCRFunc: func(ctx context.Context, id string, pcr int, d []byte) error { return nil },
		readPCRFunc:   func(ctx context.Context, id string, pcr int) ([]byte, error) { return []byte("pcr"), nil },
	}
	p := newVTPMProvider(mock)
	ctx := context.Background()

	require.NoError(t, p.VTPMStart(ctx, "vm1"))
	require.NoError(t, p.VTPMStop(ctx, "vm1"))

	q, err := p.VTPMQuote(ctx, "vm1", []byte("nonce"), []int{0, 7})
	require.NoError(t, err)
	assert.Equal(t, quoteResult, q)

	sealed, err := p.VTPMSeal(ctx, "vm1", []byte("data"), []int{7})
	require.NoError(t, err)
	assert.Equal(t, []byte("sealed"), sealed)

	plain, err := p.VTPMUnseal(ctx, "vm1", sealed)
	require.NoError(t, err)
	assert.Equal(t, []byte("plain"), plain)

	require.NoError(t, p.VTPMExtendPCR(ctx, "vm1", 7, []byte("x")))

	val, err := p.VTPMReadPCR(ctx, "vm1", 7)
	require.NoError(t, err)
	assert.Equal(t, []byte("pcr"), val)
}

func TestPlatformServiceProvider_VTPMSeal_PassesPCRs(t *testing.T) {
	var gotPCRs []int
	mock := &mockVTPMService{
		sealFunc: func(ctx context.Context, id string, d []byte, o *vtpm.SealOptions) ([]byte, error) {
			require.NotNil(t, o)
			gotPCRs = o.PCRs
			return []byte("ok"), nil
		},
	}
	p := newVTPMProvider(mock)
	_, err := p.VTPMSeal(context.Background(), "vm1", []byte("d"), []int{1, 2, 3})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, gotPCRs)
}

func TestPlatformServiceProvider_VTPMRuntime_Errors(t *testing.T) {
	sentinel := errors.New("boom")
	mock := &mockVTPMService{
		startFunc: func(ctx context.Context, id string) error { return sentinel },
		stopFunc:  func(ctx context.Context, id string) error { return sentinel },
		quoteFunc: func(ctx context.Context, id string, n []byte, p []int) (*vtpm.QuoteResult, error) {
			return nil, sentinel
		},
		sealFunc: func(ctx context.Context, id string, d []byte, o *vtpm.SealOptions) ([]byte, error) {
			return nil, sentinel
		},
		unsealFunc:    func(ctx context.Context, id string, d []byte, a string) ([]byte, error) { return nil, sentinel },
		extendPCRFunc: func(ctx context.Context, id string, pcr int, d []byte) error { return sentinel },
		readPCRFunc:   func(ctx context.Context, id string, pcr int) ([]byte, error) { return nil, sentinel },
	}
	p := newVTPMProvider(mock)
	ctx := context.Background()

	assert.ErrorIs(t, p.VTPMStart(ctx, "vm1"), sentinel)
	assert.ErrorIs(t, p.VTPMStop(ctx, "vm1"), sentinel)
	_, err := p.VTPMQuote(ctx, "vm1", nil, nil)
	assert.ErrorIs(t, err, sentinel)
	_, err = p.VTPMSeal(ctx, "vm1", nil, nil)
	assert.ErrorIs(t, err, sentinel)
	_, err = p.VTPMUnseal(ctx, "vm1", nil)
	assert.ErrorIs(t, err, sentinel)
	assert.ErrorIs(t, p.VTPMExtendPCR(ctx, "vm1", 7, nil), sentinel)
	_, err = p.VTPMReadPCR(ctx, "vm1", 7)
	assert.ErrorIs(t, err, sentinel)
}

func TestPlatformServiceProvider_VTPMRuntime_ServiceUnavailable(t *testing.T) {
	p := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})
	ctx := context.Background()

	assertUnavailable := func(err error) {
		t.Helper()
		var e ErrServiceNotAvailable
		assert.ErrorAs(t, err, &e)
	}

	assertUnavailable(p.VTPMStart(ctx, "vm1"))
	assertUnavailable(p.VTPMStop(ctx, "vm1"))
	_, err := p.VTPMQuote(ctx, "vm1", nil, nil)
	assertUnavailable(err)
	_, err = p.VTPMSeal(ctx, "vm1", nil, nil)
	assertUnavailable(err)
	_, err = p.VTPMUnseal(ctx, "vm1", nil)
	assertUnavailable(err)
	assertUnavailable(p.VTPMExtendPCR(ctx, "vm1", 7, nil))
	_, err = p.VTPMReadPCR(ctx, "vm1", 7)
	assertUnavailable(err)
}

func TestPlatformServiceProvider_SDNSetPortState_Unavailable(t *testing.T) {
	p := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})
	_, err := p.SDNSetPortState(context.Background(), "br0", "p0", "up", mcp.PortRates{})
	var e ErrServiceNotAvailable
	assert.ErrorAs(t, err, &e)
}
