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

package embedded

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// attestProfileServer serves the device attestation and profile-assignment
// RPCs. With refusal set, every method returns it, so a test can tell the
// server's own error apart from the transport's "method not registered"
// Unimplemented.
type attestProfileServer struct {
	platformv1.UnimplementedDeviceServiceServer
	refusal error

	attested   *platformv1.AttestDeviceRequest
	recorded   *platformv1.RecordAttestationCertificateRequest
	fromTmpl   *platformv1.CreateProfileFromTemplateRequest
	configFor  *platformv1.FindConfigForDeviceRequest
	assigned   *platformv1.AssignProfileToDeviceRequest
	unassigned *platformv1.UnassignProfileFromDeviceRequest
}

func (s *attestProfileServer) AttestDevice(_ context.Context, req *platformv1.AttestDeviceRequest) (*platformv1.AttestDeviceResponse, error) {
	if s.refusal != nil {
		return nil, s.refusal
	}
	s.attested = req
	return &platformv1.AttestDeviceResponse{DeviceId: 42, Verified: true, AttestationStatus: "verified"}, nil
}

func (s *attestProfileServer) RecordAttestationCertificate(_ context.Context, req *platformv1.RecordAttestationCertificateRequest) (*platformv1.RecordAttestationCertificateResponse, error) {
	if s.refusal != nil {
		return nil, s.refusal
	}
	s.recorded = req
	return &platformv1.RecordAttestationCertificateResponse{DeviceId: 42, Changed: true, Source: "enrollment"}, nil
}

func (s *attestProfileServer) CreateProfileFromTemplate(_ context.Context, req *platformv1.CreateProfileFromTemplateRequest) (*platformv1.CreateProfileResponse, error) {
	if s.refusal != nil {
		return nil, s.refusal
	}
	s.fromTmpl = req
	return &platformv1.CreateProfileResponse{Profile: &platformv1.DeviceProfile{Id: 7, Name: "from-template"}}, nil
}

func (s *attestProfileServer) FindConfigForDevice(_ context.Context, req *platformv1.FindConfigForDeviceRequest) (*platformv1.FindConfigForDeviceResponse, error) {
	if s.refusal != nil {
		return nil, s.refusal
	}
	s.configFor = req
	return &platformv1.FindConfigForDeviceResponse{Profile: &platformv1.DeviceProfile{Id: 7, Name: "matched"}}, nil
}

func (s *attestProfileServer) AssignProfileToDevice(_ context.Context, req *platformv1.AssignProfileToDeviceRequest) (*platformv1.AssignProfileToDeviceResponse, error) {
	if s.refusal != nil {
		return nil, s.refusal
	}
	s.assigned = req
	return &platformv1.AssignProfileToDeviceResponse{Profile: &platformv1.DeviceProfile{Id: 7, Name: "assigned"}}, nil
}

func (s *attestProfileServer) UnassignProfileFromDevice(_ context.Context, req *platformv1.UnassignProfileFromDeviceRequest) (*platformv1.UnassignProfileFromDeviceResponse, error) {
	if s.refusal != nil {
		return nil, s.refusal
	}
	s.unassigned = req
	return &platformv1.UnassignProfileFromDeviceResponse{Profile: &platformv1.DeviceProfile{Id: 7, Name: "unassigned"}}, nil
}

// attestProfileCall invokes one RPC through the generated client and
// returns the reply, so every case crosses the embedded conn's proto copy.
type attestProfileCall struct {
	name string
	call func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error)
	// served reports whether the server saw the request and the client got
	// the server's reply back.
	served func(t *testing.T, server *attestProfileServer, reply any)
}

var attestProfileCalls = []attestProfileCall{
	{
		name: "AttestDevice",
		call: func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error) {
			return client.AttestDevice(ctx, &platformv1.AttestDeviceRequest{DeviceId: "42", Evidence: []byte("quote")})
		},
		served: func(t *testing.T, server *attestProfileServer, reply any) {
			if server.attested.GetDeviceId() != "42" || string(server.attested.GetEvidence()) != "quote" {
				t.Errorf("server received %v, want device 42 with its evidence", server.attested)
			}
			if got := reply.(*platformv1.AttestDeviceResponse); !got.GetVerified() || got.GetAttestationStatus() != "verified" {
				t.Errorf("reply = %v, want the server's verified result", got)
			}
		},
	},
	{
		name: "RecordAttestationCertificate",
		call: func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error) {
			return client.RecordAttestationCertificate(ctx, &platformv1.RecordAttestationCertificateRequest{DeviceId: "42", Reissue: true})
		},
		served: func(t *testing.T, server *attestProfileServer, reply any) {
			if server.recorded.GetDeviceId() != "42" || !server.recorded.GetReissue() {
				t.Errorf("server received %v, want device 42 with reissue", server.recorded)
			}
			if got := reply.(*platformv1.RecordAttestationCertificateResponse); !got.GetChanged() || got.GetSource() != "enrollment" {
				t.Errorf("reply = %v, want the server's recorded result", got)
			}
		},
	},
	{
		name: "CreateProfileFromTemplate",
		call: func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error) {
			return client.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 3})
		},
		served: func(t *testing.T, server *attestProfileServer, reply any) {
			if server.fromTmpl.GetTemplateId() != 3 {
				t.Errorf("server received %v, want template 3", server.fromTmpl)
			}
			if got := reply.(*platformv1.CreateProfileResponse); got.GetProfile().GetName() != "from-template" {
				t.Errorf("reply = %v, want the server's profile", got)
			}
		},
	},
	{
		name: "FindConfigForDevice",
		call: func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error) {
			return client.FindConfigForDevice(ctx, &platformv1.FindConfigForDeviceRequest{EkSerial: "ek-1", MacAddress: "52:54:00:00:00:01"})
		},
		served: func(t *testing.T, server *attestProfileServer, reply any) {
			if server.configFor.GetEkSerial() != "ek-1" || server.configFor.GetMacAddress() != "52:54:00:00:00:01" {
				t.Errorf("server received %v, want the EK serial and MAC", server.configFor)
			}
			if got := reply.(*platformv1.FindConfigForDeviceResponse); got.GetProfile().GetName() != "matched" {
				t.Errorf("reply = %v, want the server's profile", got)
			}
		},
	},
	{
		name: "AssignProfileToDevice",
		call: func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error) {
			return client.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{ProfileId: 7, DeviceId: 42})
		},
		served: func(t *testing.T, server *attestProfileServer, reply any) {
			if server.assigned.GetProfileId() != 7 || server.assigned.GetDeviceId() != 42 {
				t.Errorf("server received %v, want profile 7 to device 42", server.assigned)
			}
			if got := reply.(*platformv1.AssignProfileToDeviceResponse); got.GetProfile().GetName() != "assigned" {
				t.Errorf("reply = %v, want the server's profile", got)
			}
		},
	},
	{
		name: "UnassignProfileFromDevice",
		call: func(ctx context.Context, client platformv1.DeviceServiceClient) (any, error) {
			return client.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{ProfileId: 7})
		},
		served: func(t *testing.T, server *attestProfileServer, reply any) {
			if server.unassigned.GetProfileId() != 7 {
				t.Errorf("server received %v, want profile 7", server.unassigned)
			}
			if got := reply.(*platformv1.UnassignProfileFromDeviceResponse); got.GetProfile().GetName() != "unassigned" {
				t.Errorf("reply = %v, want the server's profile", got)
			}
		},
	},
}

func TestDispatch_DeviceAttestationAndProfileAssignment(t *testing.T) {
	for _, tc := range attestProfileCalls {
		t.Run(tc.name, func(t *testing.T) {
			server := &attestProfileServer{}
			client := platformv1.NewDeviceServiceClient(newEmbeddedClientConn(&ServiceRegistry{Device: server}))

			reply, err := tc.call(context.Background(), client)
			if err != nil {
				t.Fatalf("%s over the embedded transport: %v", tc.name, err)
			}
			tc.served(t, server, reply)
		})
	}
}

func TestDispatch_DeviceAttestationAndProfileAssignment_ServerError(t *testing.T) {
	for _, tc := range attestProfileCalls {
		t.Run(tc.name, func(t *testing.T) {
			server := &attestProfileServer{refusal: status.Error(codes.FailedPrecondition, "device is not enrolled")}
			client := platformv1.NewDeviceServiceClient(newEmbeddedClientConn(&ServiceRegistry{Device: server}))

			_, err := tc.call(context.Background(), client)
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("%s err = %v, want the server's FailedPrecondition", tc.name, err)
			}
		})
	}
}
