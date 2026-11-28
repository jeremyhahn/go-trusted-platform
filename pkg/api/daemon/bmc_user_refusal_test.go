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
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestBMCUserRefusal_GRPCCodes checks that the deliberate BMC user-slot
// refusals reach gRPC callers as AlreadyExists and FailedPrecondition, not
// Internal (#2145 Codex round 2).
func TestBMCUserRefusal_GRPCCodes(t *testing.T) {
	createReq := &platformv1.BMCCreateUserRequest{
		ProfileId: 1,
		User: &platformv1.BMCUser{
			Slot: 2, Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR,
		},
	}
	deleteReq := &platformv1.BMCDeleteUserRequest{ProfileId: 1, Slot: 5}

	cases := []struct {
		name string
		err  error
		call func(svc *BMCGRPCService) error
		fake func(err error) *fakeBMCService
		want codes.Code
	}{
		{
			name: "CreateUser_SlotOccupied",
			err:  bmc.ErrSlotOccupied{ProfileID: 1, Slot: 2},
			fake: func(err error) *fakeBMCService { return &fakeBMCService{createUserErr: err} },
			call: func(svc *BMCGRPCService) error {
				_, err := svc.CreateUser(context.Background(), createReq)
				return err
			},
			want: codes.AlreadyExists,
		},
		{
			name: "CreateUser_ConnectionAccount",
			err:  bmc.ErrConnectionAccount{ProfileID: 1, Slot: 2},
			fake: func(err error) *fakeBMCService { return &fakeBMCService{createUserErr: err} },
			call: func(svc *BMCGRPCService) error {
				_, err := svc.CreateUser(context.Background(), createReq)
				return err
			},
			want: codes.FailedPrecondition,
		},
		{
			name: "DeleteUser_ConnectionAccount",
			err:  bmc.ErrConnectionAccount{ProfileID: 1, Slot: 5},
			fake: func(err error) *fakeBMCService { return &fakeBMCService{deleteUserErr: err} },
			call: func(svc *BMCGRPCService) error {
				_, err := svc.DeleteUser(context.Background(), deleteReq)
				return err
			},
			want: codes.FailedPrecondition,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(tc.fake(tc.err), nil)
			err := tc.call(svc)
			if got := statusCode(err); got != tc.want {
				t.Fatalf("code = %v, want %v (err %v)", got, tc.want, err)
			}
			if msg := status.Convert(err).Message(); !strings.Contains(msg, tc.err.Error()) {
				t.Errorf("message = %q, want it to contain %q", msg, tc.err.Error())
			}
		})
	}
}
