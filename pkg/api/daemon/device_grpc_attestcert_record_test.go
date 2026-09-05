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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// stubAttestCertRecorder stands in for device.AttestCertRecorder so the
// transports can be exercised against every outcome the recorder produces.
type stubAttestCertRecorder struct {
	gotID      uint64
	gotReissue bool
	calls      int
	rec        *device.AttestCertRecord
	err        error
}

func (s *stubAttestCertRecorder) Record(_ context.Context, id uint64, reissue bool) (*device.AttestCertRecord, error) {
	s.calls++
	s.gotID, s.gotReissue = id, reissue
	if s.err != nil {
		return nil, s.err
	}
	return s.rec, nil
}

var recordedAt = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func recordedFixture() *device.AttestCertRecord {
	return &device.AttestCertRecord{
		DeviceID:          42,
		Serial:            "SN0042",
		Model:             "SuperMicro X10",
		Source:            device.AttestCertSourceReissued,
		SourceDetail:      "iak-SuperMicro X10-SN0042",
		Changed:           true,
		Reissued:          true,
		Subject:           "CN=iak-SuperMicro X10-SN0042",
		CertificateSerial: "12345",
		NotAfter:          recordedAt.Add(24 * time.Hour),
		CertificatePEM:    "-----BEGIN CERTIFICATE-----\nreissued\n-----END CERTIFICATE-----\n",
	}
}

func newAttestCertGRPC(recorder AttestCertRecorder) *DeviceGRPCService {
	return NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil,
		WithDeviceAttestCertRecorder(recorder))
}

func TestDeviceGRPC_RecordAttestationCertificate_Success(t *testing.T) {
	stub := &stubAttestCertRecorder{rec: recordedFixture()}
	svc := newAttestCertGRPC(stub)

	resp, err := svc.RecordAttestationCertificate(context.Background(), &platformv1.RecordAttestationCertificateRequest{
		DeviceId: "42",
		Reissue:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(42), stub.gotID)
	assert.True(t, stub.gotReissue)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, uint64(42), resp.GetDeviceId())
	assert.Equal(t, "SN0042", resp.GetSerial())
	assert.Equal(t, "SuperMicro X10", resp.GetModel())
	assert.True(t, resp.GetChanged())
	assert.Equal(t, "reissued", resp.GetSource())
	assert.Equal(t, "iak-SuperMicro X10-SN0042", resp.GetSourceDetail())
	assert.True(t, resp.GetReissued())
	assert.Equal(t, "CN=iak-SuperMicro X10-SN0042", resp.GetSubject())
	assert.Equal(t, "12345", resp.GetCertificateSerial())
	assert.Equal(t, recordedAt.Add(24*time.Hour), resp.GetNotAfter().AsTime())
	assert.Equal(t, recordedFixture().CertificatePEM, resp.GetAttestCert())
}

func TestDeviceGRPC_RecordAttestationCertificate_ArgumentErrors(t *testing.T) {
	stub := &stubAttestCertRecorder{rec: recordedFixture()}
	svc := newAttestCertGRPC(stub)

	for name, id := range map[string]string{"empty": "", "zero": "0", "text": "lab-node-3", "negative": "-1"} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.RecordAttestationCertificate(context.Background(), &platformv1.RecordAttestationCertificateRequest{DeviceId: id})
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		})
	}
	assert.Zero(t, stub.calls, "malformed requests never reach the recorder")
}

func TestDeviceGRPC_RecordAttestationCertificate_UnavailableWithoutRecorder(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)
	_, err := svc.RecordAttestationCertificate(context.Background(), &platformv1.RecordAttestationCertificateRequest{DeviceId: "42"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
}

func TestDeviceGRPC_RecordAttestationCertificate_ErrorMapping(t *testing.T) {
	cases := map[string]struct {
		err  error
		code codes.Code
	}{
		"refused (unrestricted)": {
			err: device.ErrAttestCertRefused{DeviceID: 42, Attempts: []device.AttestCertAttempt{
				{Source: device.AttestCertSourceCA, Detail: "lab-node-3", Err: vm.ErrAKCertificateNotRestricted{Subject: "CN=x"}},
			}},
			code: codes.FailedPrecondition,
		},
		"no attest pub":      {err: device.ErrAttestCertNoAttestPub{DeviceID: 42}, code: codes.FailedPrecondition},
		"attest pub invalid": {err: device.ErrAttestCertAttestPubInvalid{DeviceID: 42, Cause: errors.New("hex")}, code: codes.FailedPrecondition},
		"public area unrestricted": {
			err:  device.ErrAttestCertPublicAreaNotRestricted{DeviceID: 42, Cause: vm.ErrAKPublicAreaNotRestricted{Reason: "restricted attribute is clear"}},
			code: codes.FailedPrecondition,
		},
		"trust anchor unavailable": {err: device.ErrAttestCertTrustAnchorUnavailable{}, code: codes.Unavailable},
		"reissue failed":           {err: device.ErrAttestCertReissueFailed{DeviceID: 42, Cause: errors.New("signer")}, code: codes.Internal},
		"write failed":             {err: device.ErrAttestCertWriteFailed{DeviceID: 42, Cause: errors.New("dao")}, code: codes.Internal},
		"invalid device id":        {err: device.ErrInvalidDeviceID, code: codes.InvalidArgument},
		"not found":                {err: &device.WrappedError{Msg: "failed to get device", Err: errors.New("not found")}, code: codes.NotFound},
		"unknown":                  {err: errors.New("boom"), code: codes.Internal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc := newAttestCertGRPC(&stubAttestCertRecorder{err: tc.err})
			_, err := svc.RecordAttestationCertificate(context.Background(), &platformv1.RecordAttestationCertificateRequest{DeviceId: "42"})
			require.Error(t, err)
			assert.Equal(t, tc.code, status.Code(err), "%v", err)
			assert.Contains(t, status.Convert(err).Message(), tc.err.Error(), "the wire message carries the recorder's reason")
		})
	}
}

func TestNewDeviceAttestCertRecorder_NilWithoutCAOrDevices(t *testing.T) {
	assert.Nil(t, newDeviceAttestCertRecorder(nil, nil))
	assert.Nil(t, newDeviceAttestCertRecorder(&Config{DeviceService: newMockDeviceService()}, slog.Default()))
	assert.Nil(t, newDeviceAttestCertRecorder(&Config{}, slog.Default()))
}

// -- QUIC ---------------------------------------------------------------

func newQUICAttestCertHandler(t *testing.T, recorder AttestCertRecorder) *QUICServiceHandler {
	t.Helper()
	handler := NewQUICServiceHandler(
		logging.DefaultLogger(),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(newMockProfileService()),
	)
	handler.SetDeviceAttestCertRecorder(recorder)
	return handler
}

func TestQUICDeviceRecordAttestCert_Success(t *testing.T) {
	stub := &stubAttestCertRecorder{rec: recordedFixture()}
	handler := newQUICAttestCertHandler(t, stub)

	req := encodeQUICCategoryRequest(t, quic.OpProvisioningCategory, quic.DeviceSubRecordAttestCert,
		&platformv1.RecordAttestationCertificateRequest{DeviceId: "42", Reissue: true})
	resp := handler.HandleRequest(context.Background(), req)

	var out platformv1.RecordAttestationCertificateResponse
	decodeQUICResponse(t, resp, &out)
	assert.Equal(t, uint64(42), out.GetDeviceId())
	assert.Equal(t, "reissued", out.GetSource())
	assert.True(t, out.GetChanged())
	assert.True(t, stub.gotReissue)
}

func TestQUICDeviceRecordAttestCert_RefusalIsInvalidRequest(t *testing.T) {
	handler := newQUICAttestCertHandler(t, &stubAttestCertRecorder{
		err: device.ErrAttestCertRefused{DeviceID: 42, Attempts: []device.AttestCertAttempt{
			{Source: device.AttestCertSourceCA, Detail: "lab-node-3", Err: vm.ErrAKCertificateNotRestricted{Subject: "CN=x"}},
		}},
	})
	req := encodeQUICCategoryRequest(t, quic.OpProvisioningCategory, quic.DeviceSubRecordAttestCert,
		&platformv1.RecordAttestationCertificateRequest{DeviceId: "42"})
	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status, "FailedPrecondition maps to the QUIC invalid-request status")
	assert.Contains(t, string(resp.Payload), "tcg-cap-verifiedTPMRestricted")
}

func TestQUICDeviceRecordAttestCert_UnavailableWithoutRecorder(t *testing.T) {
	handler := NewQUICServiceHandler(
		logging.DefaultLogger(),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(newMockProfileService()),
	)
	req := encodeQUICCategoryRequest(t, quic.OpProvisioningCategory, quic.DeviceSubRecordAttestCert,
		&platformv1.RecordAttestationCertificateRequest{DeviceId: "42"})
	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestQUICDeviceRecordAttestCert_MalformedPayload(t *testing.T) {
	handler := newQUICAttestCertHandler(t, &stubAttestCertRecorder{rec: recordedFixture()})
	resp := handler.HandleRequest(context.Background(), &quic.Request{
		Opcode:  quic.OpProvisioningCategory,
		Payload: []byte{quic.DeviceSubRecordAttestCert, 0xff, 0xfe, 0xfd},
	})
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// -- MCP ----------------------------------------------------------------

func TestMCPServiceProvider_DeviceRecordAttestCert(t *testing.T) {
	stub := &stubAttestCertRecorder{rec: recordedFixture()}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService:      newMockDeviceService(),
		AttestCertRecorder: stub,
		Logger:             slog.Default(),
	})

	out, err := p.DeviceRecordAttestCert(context.Background(), "42", true)
	require.NoError(t, err)
	resp, ok := out.(*platformv1.RecordAttestationCertificateResponse)
	require.True(t, ok, "the MCP result is the pb response so it marshals with proto field names")
	assert.Equal(t, uint64(42), resp.GetDeviceId())
	assert.True(t, stub.gotReissue)

	_, err = p.DeviceRecordAttestCert(context.Background(), "", false)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMCPServiceProvider_DeviceRecordAttestCert_UnavailableWithoutRecorder(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{DeviceService: newMockDeviceService(), Logger: slog.Default()})
	_, err := p.DeviceRecordAttestCert(context.Background(), "42", false)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestPlatformServiceProvider_DeviceRecordAttestCert(t *testing.T) {
	stub := &stubAttestCertRecorder{err: device.ErrAttestCertNoAttestPub{DeviceID: 42}}
	p := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		DeviceService:      newMockDeviceService(),
		ProfileService:     newMockProfileService(),
		AttestCertRecorder: stub,
	})
	_, err := p.DeviceRecordAttestCert(context.Background(), "42", false)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "%v", err)
	assert.Equal(t, uint64(42), stub.gotID)
}
