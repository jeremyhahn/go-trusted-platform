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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errDNSCategoryTestSave is the storage failure the Save path is driven with.
var errDNSCategoryTestSave = errors.New("zone store unavailable")

// dnsCategoryRequest frames a DNS category request: the sub-opcode in
// payload[0] and the MessagePack-encoded request in payload[1:].
func dnsCategoryRequest(t *testing.T, subOpcode byte, body interface{}) *quicwire.Request {
	t.Helper()
	encoded, err := quicwire.EncodePayload(body)
	require.NoError(t, err)
	return &quicwire.Request{
		Opcode:  quicwire.OpDNSCategory,
		Payload: append([]byte{subOpcode}, encoded...),
	}
}

func TestDNSCategory_UpdateZone(t *testing.T) {
	ctx := context.Background()

	t.Run("success changes TTL and description", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := dnsCategoryRequest(t, quicwire.OpDNSUpdateZone, &platformv1.UpdateZoneRequest{
			Name: "example.com.", Ttl: 7200, Description: "updated",
		})

		resp := handler.HandleRequest(ctx, req)

		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		var result platformv1.UpdateZoneResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &result))
		assert.True(t, result.GetStatus().GetSuccess())
		assert.Equal(t, "example.com.", result.GetZone().GetName())
		assert.Equal(t, int32(7200), int32(result.GetZone().GetTtl()))
		assert.Equal(t, "updated", result.GetZone().GetDescription())
		require.NotNil(t, mock.SavedZone)
		assert.Equal(t, 7200, int(mock.SavedZone.TTL))
		assert.Equal(t, "updated", mock.SavedZone.Description)
	})

	t.Run("missing name is invalid argument", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := dnsCategoryRequest(t, quicwire.OpDNSUpdateZone, &platformv1.UpdateZoneRequest{Ttl: 7200})

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Zero(t, mock.CallCount("Save"))
	})

	t.Run("unknown zone is not found", func(t *testing.T) {
		mock := NewMockDNSService()
		mock.ZoneFunc = func(ctx context.Context, zoneName string) (*entities.Zone, error) {
			return nil, dns.ErrZoneNotFound
		}
		handler := createDNSUnitTestHandler(mock)
		req := dnsCategoryRequest(t, quicwire.OpDNSUpdateZone, &platformv1.UpdateZoneRequest{Name: "missing.com."})

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
		assert.Zero(t, mock.CallCount("Save"))
	})

	t.Run("save failure is internal error", func(t *testing.T) {
		mock := NewMockDNSService()
		mock.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
			return errDNSCategoryTestSave
		}
		handler := createDNSUnitTestHandler(mock)
		req := dnsCategoryRequest(t, quicwire.OpDNSUpdateZone, &platformv1.UpdateZoneRequest{Name: "example.com.", Ttl: 60})

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("undecodable body is invalid request", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := &quicwire.Request{
			Opcode:  quicwire.OpDNSCategory,
			Payload: []byte{quicwire.OpDNSUpdateZone, 0xC1},
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

func TestDNSCategory_Dispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("no DNS service is unavailable", func(t *testing.T) {
		handler := newTestQUICServiceHandler(logging.DefaultLogger())
		req := dnsCategoryRequest(t, quicwire.OpDNSUpdateZone, &platformv1.UpdateZoneRequest{Name: "example.com."})

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("missing sub-opcode is invalid request", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())

		resp := handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpDNSCategory})

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	// A sub-opcode with no permission entry is refused before dispatch,
	// so an unassigned DNS sub-opcode fails closed.
	t.Run("unassigned sub-opcode is refused", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := dnsCategoryRequest(t, 0x3F, &platformv1.UpdateZoneRequest{Name: "example.com."})

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
		assert.Zero(t, mock.CallCount("Zone"))
	})
}
