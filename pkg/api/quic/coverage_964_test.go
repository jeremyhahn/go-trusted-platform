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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// admittedVTEPGatewayService serves a fixed admitted-VTEP set on top of the
// shared test gateway service, and records the identifiers it was asked for.
type admittedVTEPGatewayService struct {
	*testGatewayService
	vteps         []*quicwire.GatewayAdmittedVTEPInfo
	err           error
	gotGatewayID  string
	gotVTEPLookup string
}

func (s *admittedVTEPGatewayService) GetAdmittedVTEP(_ context.Context, gatewayID, vtep string) (*quicwire.GatewayAdmittedVTEPInfo, error) {
	s.gotGatewayID = gatewayID
	s.gotVTEPLookup = vtep
	if s.err != nil {
		return nil, s.err
	}
	for _, v := range s.vteps {
		if v.VTEP == vtep {
			return v, nil
		}
	}
	return nil, ErrGatewayAllocationNotFound
}

func (s *admittedVTEPGatewayService) ListAdmittedVTEPs(_ context.Context, gatewayID string) ([]*quicwire.GatewayAdmittedVTEPInfo, error) {
	s.gotGatewayID = gatewayID
	if s.err != nil {
		return nil, s.err
	}
	return s.vteps, nil
}

func newAdmittedVTEPService(err error) *admittedVTEPGatewayService {
	return &admittedVTEPGatewayService{
		testGatewayService: newTestGatewayService(),
		vteps: []*quicwire.GatewayAdmittedVTEPInfo{
			{VTEP: "fd00::1", DeviceID: 7, Hostname: "node-a", ProfileID: 3},
			{VTEP: "fd00::2", DeviceID: 8, Hostname: "node-b", ProfileID: 3},
		},
		err: err,
	}
}

func encodeTestPayload(t *testing.T, v any) []byte {
	t.Helper()
	payload, err := quicwire.EncodePayload(v)
	require.NoError(t, err)
	return payload
}

func TestGatewayHandler_AdmittedVTEP(t *testing.T) {
	t.Parallel()

	validPayload := func(t *testing.T) []byte {
		return encodeTestPayload(t, &quicwire.GatewayAdmittedVTEPRequest{GatewayID: "gw-1", VTEP: "fd00::2"})
	}

	tests := []struct {
		name       string
		service    GatewayServiceInterface
		payload    func(t *testing.T) []byte
		wantStatus byte
	}{
		{
			name:       "nil service is unavailable",
			service:    nil,
			payload:    validPayload,
			wantStatus: quicwire.StatusUnavailable,
		},
		{
			name:       "undecodable payload is an invalid request",
			service:    newAdmittedVTEPService(nil),
			payload:    func(*testing.T) []byte { return []byte("not a msgpack map") },
			wantStatus: quicwire.StatusInvalidRequest,
		},
		{
			name:    "missing VTEP address is an invalid request",
			service: newAdmittedVTEPService(nil),
			payload: func(t *testing.T) []byte {
				return encodeTestPayload(t, &quicwire.GatewayAdmittedVTEPRequest{GatewayID: "gw-1"})
			},
			wantStatus: quicwire.StatusInvalidRequest,
		},
		{
			name:       "unconfigured feature maps to unavailable",
			service:    newAdmittedVTEPService(ErrGatewayFeatureNotConfigured),
			payload:    validPayload,
			wantStatus: quicwire.StatusUnavailable,
		},
		{
			name:    "unknown VTEP maps to not found",
			service: newAdmittedVTEPService(nil),
			payload: func(t *testing.T) []byte {
				return encodeTestPayload(t, &quicwire.GatewayAdmittedVTEPRequest{GatewayID: "gw-1", VTEP: "fd00::9"})
			},
			wantStatus: quicwire.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := NewGatewayHandler(newGatewayTestLogger(), tt.service)
			resp := handler.HandleRequest(context.Background(), &quicwire.Request{
				Opcode:  quicwire.OpGatewayAdmittedVTEP,
				Payload: tt.payload(t),
			})
			assert.Equal(t, tt.wantStatus, resp.Status)
		})
	}

	t.Run("returns the admitted VTEP the service resolved", func(t *testing.T) {
		t.Parallel()
		service := newAdmittedVTEPService(nil)
		handler := NewGatewayHandler(newGatewayTestLogger(), service)

		resp := handler.HandleRequest(context.Background(), &quicwire.Request{
			Opcode:  quicwire.OpGatewayAdmittedVTEP,
			Payload: validPayload(t),
		})
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out quicwire.GatewayAdmittedVTEPResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		require.NotNil(t, out.VTEP)
		assert.Equal(t, "fd00::2", out.VTEP.VTEP)
		assert.Equal(t, uint64(8), out.VTEP.DeviceID)
		assert.Equal(t, "node-b", out.VTEP.Hostname)
		assert.NotZero(t, out.Timestamp)
		assert.Equal(t, "gw-1", service.gotGatewayID)
		assert.Equal(t, "fd00::2", service.gotVTEPLookup)
	})
}

func TestGatewayHandler_ListAdmittedVTEPs(t *testing.T) {
	t.Parallel()

	validPayload := func(t *testing.T) []byte {
		return encodeTestPayload(t, &quicwire.GatewayListAdmittedVTEPsRequest{GatewayID: "gw-1"})
	}

	tests := []struct {
		name       string
		service    GatewayServiceInterface
		payload    func(t *testing.T) []byte
		wantStatus byte
	}{
		{
			name:       "nil service is unavailable",
			service:    nil,
			payload:    validPayload,
			wantStatus: quicwire.StatusUnavailable,
		},
		{
			name:       "undecodable payload is an invalid request",
			service:    newAdmittedVTEPService(nil),
			payload:    func(*testing.T) []byte { return []byte("not a msgpack map") },
			wantStatus: quicwire.StatusInvalidRequest,
		},
		{
			name:       "unconfigured feature maps to unavailable",
			service:    newAdmittedVTEPService(ErrGatewayFeatureNotConfigured),
			payload:    validPayload,
			wantStatus: quicwire.StatusUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler := NewGatewayHandler(newGatewayTestLogger(), tt.service)
			resp := handler.HandleRequest(context.Background(), &quicwire.Request{
				Opcode:  quicwire.OpGatewayListAdmittedVTEPs,
				Payload: tt.payload(t),
			})
			assert.Equal(t, tt.wantStatus, resp.Status)
		})
	}

	t.Run("returns every admitted VTEP with its count", func(t *testing.T) {
		t.Parallel()
		service := newAdmittedVTEPService(nil)
		handler := NewGatewayHandler(newGatewayTestLogger(), service)

		resp := handler.HandleRequest(context.Background(), &quicwire.Request{
			Opcode:  quicwire.OpGatewayListAdmittedVTEPs,
			Payload: validPayload(t),
		})
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var out quicwire.GatewayListAdmittedVTEPsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
		assert.Equal(t, int32(2), out.Count)
		require.Len(t, out.VTEPs, 2)
		assert.Equal(t, "fd00::1", out.VTEPs[0].VTEP)
		assert.Equal(t, "fd00::2", out.VTEPs[1].VTEP)
		assert.Equal(t, "gw-1", service.gotGatewayID)
	})
}

func TestIsContainerSubOpcode_InPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		op   byte
		want bool
	}{
		{name: "create", op: quicwire.OpContainerCreate, want: true},
		{name: "attest", op: quicwire.OpContainerAttest, want: true},
		{name: "exec", op: quicwire.OpContainerExec, want: true},
		{name: "metrics", op: quicwire.OpContainerMetrics, want: true},
		{name: "vm restart is not a container op", op: quicwire.OpVMRestart, want: false},
		{name: "vm metrics is not a container op", op: quicwire.OpVMMetrics, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsContainerSubOpcode(tt.op))
		})
	}
}

func TestProxyCodecErrors_WrapCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("short buffer")

	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "decoding failure",
			err:     ErrProxyDecodingFailed{Cause: cause},
			wantMsg: "proxy request decoding failed: short buffer",
		},
		{
			name:    "encoding failure",
			err:     ErrProxyEncodingFailed{Cause: cause},
			wantMsg: "proxy response encoding failed: short buffer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.wantMsg, tt.err.Error())
			assert.ErrorIs(t, tt.err, cause)
			assert.Equal(t, cause, errors.Unwrap(tt.err))
		})
	}
}
