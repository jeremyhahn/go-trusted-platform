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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// SubOpTPM2GetSRK discarded its payload, so it answered every request
// with the SSRK and StatusOK. Issue #475.
//
// TestTPM2Handler_HandleGetSRK sends a bare sub-opcode and asserts
// StatusOK; that input cannot reach the defect, because discarding the
// handle and defaulting to the SSRK give the same answer. These cases
// use inputs that can, and assert on WHICH key came back.

func getSRKResponse(t *testing.T, req *TPM2GetSRKRequest) *quicwire.Response {
	t.Helper()
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())

	payload := []byte{quicwire.SubOpTPM2GetSRK}
	if req != nil {
		encoded, err := quicwire.EncodePayload(*req)
		require.NoError(t, err)
		payload = append(payload, encoded...)
	}
	return h.HandleMessage(context.Background(), &quicwire.Request{Payload: payload})
}

func decodeKeyResponse(t *testing.T, resp *quicwire.Response) TPM2KeyResponse {
	t.Helper()
	var key TPM2KeyResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &key))
	return key
}

// TestGetSRKResolvesThePlatformHandle is the regression: asking for the
// platform SRK must return the platform key, not the SSRK.
func TestGetSRKResolvesThePlatformHandle(t *testing.T) {
	resp := getSRKResponse(t, &TPM2GetSRKRequest{Handle: 0x81000002})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	key := decodeKeyResponse(t, resp)
	assert.Equal(t, uint32(0x81000002), key.Handle,
		"a request for the PlatformSRK must not be answered with the SSRK")
	assert.Equal(t, []byte("platform-srk-public-key"), key.PublicKey,
		"the public key must be the platform key's, not the SSRK's")
}

// TestGetSRKRejectsUnknownHandle is the other half: an unknown handle is
// an error, never a fall-through to a key the caller did not name.
func TestGetSRKRejectsUnknownHandle(t *testing.T) {
	resp := getSRKResponse(t, &TPM2GetSRKRequest{Handle: 0x81000099})
	assert.Equal(t, quicwire.StatusNotFound, resp.Status,
		"an unknown SRK handle must be StatusNotFound, not StatusOK with a key")
}

// TestGetSRKWithoutHandleStillReturnsSSRK pins the compatibility the
// change preserves: a bare sub-opcode, and an explicit 0, still mean the
// SSRK.
func TestGetSRKWithoutHandleStillReturnsSSRK(t *testing.T) {
	for name, req := range map[string]*TPM2GetSRKRequest{
		"no payload":  nil,
		"explicit 0":  {Handle: 0},
		"ssrk handle": {Handle: 0x81000001},
	} {
		t.Run(name, func(t *testing.T) {
			resp := getSRKResponse(t, req)
			require.Equal(t, quicwire.StatusOK, resp.Status)
			key := decodeKeyResponse(t, resp)
			assert.Equal(t, uint32(0x81000001), key.Handle)
			assert.Equal(t, []byte("ssrk-public-key"), key.PublicKey)
		})
	}
}
