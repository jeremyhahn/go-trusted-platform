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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newFIDO2GRPC(backend FIDO2Backend) *FIDO2GRPCService {
	return NewFIDO2GRPCService(logging.DefaultLogger(), NewFIDO2Service(logging.DefaultLogger(), backend))
}

func TestFIDO2GRPC_Unavailable(t *testing.T) {
	svc := newFIDO2GRPC(nil)
	_, err := svc.ListDevices(context.Background(), &platformv1.FIDO2ListDevicesRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Errorf("code = %v", st.Code())
	}
}

func TestFIDO2GRPC_InvalidArgument(t *testing.T) {
	svc := newFIDO2GRPC(&fakeFIDO2Backend{})
	_, err := svc.Info(context.Background(), &platformv1.FIDO2InfoRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v", st.Code())
	}
}

func TestFIDO2GRPC_Success(t *testing.T) {
	svc := newFIDO2GRPC(&fakeFIDO2Backend{})
	ctx := context.Background()
	if d, err := svc.ListDevices(ctx, &platformv1.FIDO2ListDevicesRequest{}); err != nil || len(d.GetDevices()) != 1 {
		t.Errorf("ListDevices: %v %+v", err, d)
	}
	if d, err := svc.WaitDevice(ctx, &platformv1.FIDO2WaitDeviceRequest{TimeoutSeconds: 5}); err != nil || d.GetDevice().GetId() == "" {
		t.Errorf("WaitDevice: %v %+v", err, d)
	}
	if i, err := svc.Info(ctx, &platformv1.FIDO2InfoRequest{Device: "key1"}); err != nil || i.GetInfo().GetAaguid() == "" {
		t.Errorf("Info: %v %+v", err, i)
	}
	if r, err := svc.Register(ctx, &platformv1.FIDO2RegisterRequest{Username: "alice", Role: platformv1.FIDO2Role_FIDO2_ROLE_SO}); err != nil || r.GetCredentialId() == "" {
		t.Errorf("Register: %v %+v", err, r)
	}
	if r, err := svc.Authenticate(ctx, &platformv1.FIDO2AuthenticateRequest{CredentialId: "c"}); err != nil || !r.GetAuthenticated() {
		t.Errorf("Authenticate: %v %+v", err, r)
	}
}
