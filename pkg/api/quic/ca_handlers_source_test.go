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

//go:build codec_msgpack

package quic

import (
	"context"
	"sync"
	"testing"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// swappableQUICCA is a mutex-guarded CA the test swaps under one handler.
type swappableQUICCA struct {
	mu sync.Mutex
	ca quicbaasca.CACertificateAuthority
}

func (s *swappableQUICCA) get() quicbaasca.CACertificateAuthority {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ca
}

func (s *swappableQUICCA) set(ca quicbaasca.CACertificateAuthority) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ca = ca
}

func quicCAInfo(t *testing.T, h *CAHandler) (byte, CAInfoResponse) {
	t.Helper()
	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpCAInfo})
	var info CAInfoResponse
	if resp.Status == quicwire.StatusOK {
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &info))
	}
	return resp.Status, info
}

func TestCAHandler_WithCASource_FollowsTheSwap(t *testing.T) {
	src := &swappableQUICCA{}
	h := NewCAHandler(logging.DefaultLogger(), nil, nil).WithCASource(src.get)

	t.Run("an empty source answers unavailable", func(t *testing.T) {
		for _, op := range []byte{
			quicwire.OpCAInfo,
			quicwire.OpCAList,
			quicwire.OpCABundle,
			quicwire.OpCACRL,
		} {
			resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: op})
			assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "opcode %#x", op)
		}
		resp := h.SignCSR(scopedCtx("ca:sign-csr"), nil)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("after the source holds a CA the handler serves it", func(t *testing.T) {
		src.set(newMockCA())
		code, info := quicCAInfo(t, h)
		require.Equal(t, quicwire.StatusOK, code)
		assert.True(t, info.IsInitialized)
		assert.Equal(t, "Test CA", info.CommonName)
	})

	t.Run("a second swap is served without a new handler", func(t *testing.T) {
		second := newMockCA()
		second.identity = "Second CA"
		src.set(second)
		code, info := quicCAInfo(t, h)
		require.Equal(t, quicwire.StatusOK, code)
		assert.Equal(t, "Second CA", info.CommonName)
	})

	t.Run("a handler built without a source serves its CA", func(t *testing.T) {
		code, info := quicCAInfo(t, NewCAHandler(logging.DefaultLogger(), newMockCA(), nil))
		require.Equal(t, quicwire.StatusOK, code)
		assert.Equal(t, "Test CA", info.CommonName)
	})

	t.Run("a nil source falls back to the constructor CA", func(t *testing.T) {
		plain := NewCAHandler(logging.DefaultLogger(), newMockCA(), nil).WithCASource(nil)
		code, info := quicCAInfo(t, plain)
		require.Equal(t, quicwire.StatusOK, code)
		assert.Equal(t, "Test CA", info.CommonName)
	})
}

func TestCAHandler_WithCASource_ConcurrentSwap(t *testing.T) {
	src := &swappableQUICCA{}
	h := NewCAHandler(logging.DefaultLogger(), nil, nil).WithCASource(src.get)
	ca := newMockCA()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpCAInfo})
				if resp.Status != quicwire.StatusOK && resp.Status != quicwire.StatusUnavailable {
					t.Errorf("unexpected status %d", resp.Status)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		src.set(ca)
	}()
	wg.Wait()
	code, _ := quicCAInfo(t, h)
	assert.Equal(t, quicwire.StatusOK, code)
}
