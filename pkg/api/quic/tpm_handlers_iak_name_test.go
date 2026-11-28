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

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// GetAK answers the AK's TPM name on gRPC, Unix, embedded and REST
// (#2069); QUIC GetIAK must answer it too, so every transport carries it.
func TestTPM2Handler_HandleGetIAK_AnswersTheAKName(t *testing.T) {
	mock := newMockTPM()
	mock.iakAttrs.TPMAttributes.Name = tpm2.TPM2BName{Buffer: []byte("test-iak-name")}
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(mock)

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetIAK}})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	key := decodeKeyResponse(t, resp)
	assert.Equal(t, uint32(0x81020001), key.Handle)
	assert.Equal(t, []byte("test-iak-pub"), key.PublicKey)
	assert.Equal(t, []byte("test-iak-name"), key.Name, "QUIC GetIAK answers the AK name (#2069)")
}

// The key response struct is shared by EK, SRK and IAK answers; only
// GetIAK sets the name.
func TestTPM2Handler_HandleGetEK_OmitsName(t *testing.T) {
	h := NewTPM2Handler(logging.DefaultLogger())
	h.SetTPM2Service(newMockTPM())

	resp := h.HandleMessage(context.Background(), &quicwire.Request{Payload: []byte{quicwire.SubOpTPM2GetEK}})
	require.Equal(t, quicwire.StatusOK, resp.Status)

	key := decodeKeyResponse(t, resp)
	assert.Empty(t, key.Name)
}
