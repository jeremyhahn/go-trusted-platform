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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// newPhase35SDKClient mounts the ceremony, PIV and FIDO2 services on the real
// REST router and connects the SDK's REST adapter to it, so a call travels the
// client's routes, verbs and bodies into the daemon's handlers and back
// through the client's decoders.
func newPhase35SDKClient(t *testing.T) (*RESTServer, *sdkrest.Adapter) {
	t.Helper()
	s := newTestRESTServerForPhase35(t)
	ceremony, piv, fido := phase35Services()
	s.SetCeremonyService(ceremony)
	mustMountS6(t, s.SetPIVService(piv, s6RESTGuard()))
	mustMountS6(t, s.SetFIDO2Service(fido, s6RESTGuard()))
	a := connectPhase35REST(t, s.router)
	a.SetToken(s6OperatorToken)
	return s, a
}

// connectPhase35REST serves h over TLS, as the daemon's REST listener does
// (the SDK refuses a plaintext REST address), and connects the SDK REST
// adapter to it.
func connectPhase35REST(t *testing.T, h http.Handler) *sdkrest.Adapter {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)

	conn, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		platform.WithTLSConfig(phase35ClientTLS(server)),
	))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	a, ok := conn.(*sdkrest.Adapter)
	if !ok {
		t.Fatalf("Connect returned %T, want *rest.Adapter", conn)
	}
	return a
}

// phase35ClientTLS is a client TLS configuration that trusts only the test
// server's certificate.
func phase35ClientTLS(server *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// phase35Services builds the ceremony, PIV and FIDO2 services over the fakes
// whose replies phase35SDKCases expects.
func phase35Services() (*CeremonyService, *PIVService, *FIDO2Service) {
	log := logging.DefaultLogger()
	piv := NewPIVService(log, &fakePIVBackend{
		devices: []PIVDevice{{ID: "yk5", Name: "YubiKey", FirmwareVersion: "5.4.3"}},
		slots:   []PIVSlot{{ID: "9a", Algorithm: PIVAlgorithmECDSA, HasKey: true}},
	})
	return NewCeremonyService(log, &fakeCeremonyBackend{}), piv, NewFIDO2Service(log, &fakeFIDO2Backend{})
}

// phase35SDKCase is one SDK call and the reply the phase35Services fakes
// answer it with. Every transport's contract test runs the same table, so the
// transports are held to one expectation.
type phase35SDKCase struct {
	method string
	req    proto.Message
	reply  proto.Message
	check  func(t *testing.T, reply proto.Message)
}

// runPhase35SDKCases invokes every case through conn, after checking the
// table covers every method of the three generated service descriptors.
func runPhase35SDKCases(t *testing.T, conn grpc.ClientConnInterface) {
	t.Helper()
	cases := phase35SDKCases()
	covered := make(map[string]bool, len(cases))
	for _, tc := range cases {
		covered[tc.method] = true
	}
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CeremonyService_ServiceDesc, platformv1.PIVService_ServiceDesc, platformv1.FIDO2Service_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			if method := "/" + desc.ServiceName + "/" + m.MethodName; !covered[method] {
				t.Errorf("no contract case for %s", method)
			}
		}
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			if err := conn.Invoke(context.Background(), tc.method, tc.req, tc.reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			tc.check(t, tc.reply)
		})
	}
}

// TestPhase35RESTClientAgainstDaemonRouter drives every ceremony, PIV and
// FIDO2 method of the SDK REST client through the daemon's real router. A
// client route the server does not register is a 404, a body it cannot parse is
// a 400 or a wrong value, and a reply the client cannot decode is an error, so
// each of those fails here rather than in production.
func TestPhase35RESTClientAgainstDaemonRouter(t *testing.T) {
	_, a := newPhase35SDKClient(t)
	runPhase35SDKCases(t, a.Connection())
}

func phase35SDKCases() []phase35SDKCase {
	return []phase35SDKCase{
		{"/platform.v1.CeremonyService/Init",
			&platformv1.CeremonyInitRequest{SoPin: "1234", Threshold: "2-of-3"}, &platformv1.CeremonyInitResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.CeremonyInitResponse)
				if got.GetCeremonyId() != "cid" || got.GetState() != platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS {
					t.Errorf("reply = %+v", got)
				}
				if got.GetAdminCertPem() != "ADMIN-CERT" || got.GetAdminKeyPem() != "ADMIN-KEY" || got.GetSpkiPin() != "PIN" {
					t.Errorf("admin bundle not carried: %+v", got)
				}
			}},
		{"/platform.v1.CeremonyService/Status",
			&platformv1.CeremonyStatusRequest{}, &platformv1.CeremonyStatusResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.CeremonyStatusResponse).GetCeremonyId() != "cid" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.CeremonyService/ClaimCertBegin",
			&platformv1.CeremonyClaimCertBeginRequest{
				Username: "alice", Slot: "9a",
				AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV,
			}, &platformv1.CeremonyClaimCertBeginResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.CeremonyClaimCertBeginResponse)
				if got.GetNonce() != "deadbeef" || got.GetChallengeId() != "chal-1" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.CeremonyService/ClaimCertComplete",
			&platformv1.CeremonyClaimCertCompleteRequest{Username: "alice", Nonce: "deadbeef", Signature: "sig"},
			&platformv1.CeremonyClaimCertCompleteResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.CeremonyClaimCertCompleteResponse).GetCertificatePem() != "CERT" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.CeremonyService/ClaimShareBegin",
			&platformv1.CeremonyClaimShareBeginRequest{Username: "alice"}, &platformv1.CeremonyClaimShareBeginResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.CeremonyClaimShareBeginResponse).GetNonce() != "deadbeef" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.CeremonyService/ClaimShareComplete",
			&platformv1.CeremonyClaimShareCompleteRequest{Username: "alice", Nonce: "deadbeef", Signature: []byte{1, 2}},
			&platformv1.CeremonyClaimShareCompleteResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.CeremonyClaimShareCompleteResponse).GetShare() != "SHARE" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.CeremonyService/SignCSR",
			&platformv1.CeremonySignCSRRequest{
				Username: "alice", SoPin: "1234", CsrPem: "CSR",
				Role: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
			}, &platformv1.CeremonySignCSRResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.CeremonySignCSRResponse).GetCertificatePem() != "SIGNED" {
					t.Errorf("reply = %+v", r)
				}
			}},

		{"/platform.v1.PIVService/ListDevices",
			&platformv1.PIVListDevicesRequest{}, &platformv1.PIVListDevicesResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.PIVListDevicesResponse)
				if len(got.GetDevices()) != 1 || got.GetDevices()[0].GetId() != "yk5" || got.GetDevices()[0].GetFirmwareVersion() != "5.4.3" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.PIVService/ListSlots",
			&platformv1.PIVListSlotsRequest{Device: "yk5"}, &platformv1.PIVListSlotsResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.PIVListSlotsResponse)
				if len(got.GetSlots()) != 1 || got.GetSlots()[0].GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.PIVService/SlotInfo",
			&platformv1.PIVSlotInfoRequest{Slot: "9a", Device: "yk5"}, &platformv1.PIVSlotInfoResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.PIVSlotInfoResponse)
				if got.GetSlot().GetId() != "9a" || got.GetSlot().GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.PIVService/Generate",
			&platformv1.PIVGenerateRequest{Slot: "9a", Pin: "123456", Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA},
			&platformv1.PIVGenerateResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.PIVGenerateResponse).GetPublicKeyPem() == "" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.PIVService/Import",
			&platformv1.PIVImportRequest{Slot: "9a", PrivateKeyPem: "KEY", Pin: "123456"}, &platformv1.PIVImportResponse{},
			func(t *testing.T, r proto.Message) {
				if !r.(*platformv1.PIVImportResponse).GetImported() {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.PIVService/Sign",
			&platformv1.PIVSignRequest{Slot: "9a", Payload: []byte("hello"), Pin: "123456"}, &platformv1.PIVSignResponse{},
			func(t *testing.T, r proto.Message) {
				// The fake signs by echoing the payload, so the bytes
				// crossed the wire intact in both directions.
				if string(r.(*platformv1.PIVSignResponse).GetSignature()) != "hello" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.PIVService/Attest",
			&platformv1.PIVAttestRequest{Slot: "9a"}, &platformv1.PIVAttestResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.PIVAttestResponse)
				if got.GetAttestationCertPem() != "CERT" || got.GetAttestationChainPem() != "CHAIN" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.PIVService/Reset",
			&platformv1.PIVResetRequest{Device: "yk5"}, &platformv1.PIVResetResponse{},
			func(t *testing.T, r proto.Message) {
				if !r.(*platformv1.PIVResetResponse).GetReset_() {
					t.Errorf("reply = %+v", r)
				}
			}},

		{"/platform.v1.FIDO2Service/ListDevices",
			&platformv1.FIDO2ListDevicesRequest{}, &platformv1.FIDO2ListDevicesResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.FIDO2ListDevicesResponse)
				if len(got.GetDevices()) != 1 || got.GetDevices()[0].GetId() != "key1" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.FIDO2Service/WaitDevice",
			&platformv1.FIDO2WaitDeviceRequest{TimeoutSeconds: 1}, &platformv1.FIDO2WaitDeviceResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.FIDO2WaitDeviceResponse).GetDevice().GetId() != "key1" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.FIDO2Service/Info",
			&platformv1.FIDO2InfoRequest{Device: "key1"}, &platformv1.FIDO2InfoResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.FIDO2InfoResponse)
				if got.GetInfo().GetDevice().GetId() != "key1" || got.GetInfo().GetAaguid() != "aa-guid" {
					t.Errorf("reply = %+v", got)
				}
			}},
		{"/platform.v1.FIDO2Service/Register",
			&platformv1.FIDO2RegisterRequest{Username: "alice", Role: platformv1.FIDO2Role_FIDO2_ROLE_ADMIN},
			&platformv1.FIDO2RegisterResponse{},
			func(t *testing.T, r proto.Message) {
				if r.(*platformv1.FIDO2RegisterResponse).GetCredentialId() != "cred-1" {
					t.Errorf("reply = %+v", r)
				}
			}},
		{"/platform.v1.FIDO2Service/Authenticate",
			&platformv1.FIDO2AuthenticateRequest{CredentialId: "cred-1"}, &platformv1.FIDO2AuthenticateResponse{},
			func(t *testing.T, r proto.Message) {
				got := r.(*platformv1.FIDO2AuthenticateResponse)
				if !got.GetAuthenticated() || got.GetCounter() != 42 {
					t.Errorf("reply = %+v", got)
				}
			}},
	}
}

// TestPhase35RESTClientAgainstDaemonRouter_ServerErrorsSurface proves a
// server-side refusal reaches the client as an error, not an empty reply.
func TestPhase35RESTClientAgainstDaemonRouter_ServerErrorsSurface(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	mustMountS6(t, s.SetPIVService(NewPIVService(logging.DefaultLogger(), nil), s6RESTGuard()))
	a := connectPhase35REST(t, s.router)
	a.SetToken(s6OperatorToken)

	err := a.Connection().Invoke(context.Background(), "/platform.v1.PIVService/ListDevices",
		&platformv1.PIVListDevicesRequest{}, &platformv1.PIVListDevicesResponse{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("err = %v, want Unavailable for an unconfigured backend", err)
	}
}
