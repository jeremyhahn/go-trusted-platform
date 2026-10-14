package rest

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestIAMResourceReplies_BareResourceLandsOnTheReply pins the IAM reply
// decoding (#401): the REST handlers answer the bare user, role or tenant, and the reply must carry it in its resource field, as gRPC's does.
// Before the decoders protojson discarded every field and the SDK returned a
// nil resource with no error.
func TestIAMResourceReplies_BareResourceLandsOnTheReply(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		payload    string
		got        func(reply proto.Message) string
		want       string
	}{
		{
			name:       "UpdateUser",
			grpcMethod: platformv1.PlatformIAMService_UpdateUser_FullMethodName,
			req:        &platformv1.UpdateIAMUserRequest{TenantId: "acme", UserId: "u-7", Email: "u7@example.test"},
			resp:       &platformv1.IAMUserResponse{},
			payload:    `{"id":"u-7","tenant_id":"acme","email":"u7@example.test","mfa_verified":false,"updated_at":"2026-10-13T02:00:00Z"}`,
			got:        func(reply proto.Message) string { return reply.(*platformv1.IAMUserResponse).GetUser().GetEmail() },
			want:       "u7@example.test",
		},
		{
			name:       "GetRole",
			grpcMethod: platformv1.PlatformIAMService_GetRole_FullMethodName,
			req:        &platformv1.GetIAMRoleRequest{TenantId: "acme", RoleId: "r-2"},
			resp:       &platformv1.IAMRoleResponse{},
			payload:    `{"id":"r-2","tenant_id":"acme","description":"ops","permissions":["iam:read"]}`,
			got: func(reply proto.Message) string {
				return reply.(*platformv1.IAMRoleResponse).GetRole().GetDescription()
			},
			want: "ops",
		},
		{
			name:       "UpdateTenant",
			grpcMethod: platformv1.PlatformIAMService_UpdateTenant_FullMethodName,
			req:        &platformv1.UpdateIAMTenantRequest{TenantId: "acme", Name: "Acme"},
			resp:       &platformv1.IAMTenantResponse{},
			payload:    `{"id":"acme","name":"Acme","settings":{"max_users":5,"mfa_required":true}}`,
			got:        func(reply proto.Message) string { return reply.(*platformv1.IAMTenantResponse).GetTenant().GetName() },
			want:       "Acme",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"payload":` + tc.payload + `}`))
			})

			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if got := tc.got(tc.resp); got != tc.want {
				t.Fatalf("reply carries %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIAMResourceReplies_MalformedResourceIsAnError: a payload that is not
// the resource must fail the call, never come back as an empty resource.
func TestIAMResourceReplies_MalformedResourceIsAnError(t *testing.T) {
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"payload":{"email":42}}`))
	})

	err := a.Connection().Invoke(context.Background(), platformv1.PlatformIAMService_GetUser_FullMethodName,
		&platformv1.GetIAMUserRequest{TenantId: "acme", UserId: "u-7"}, &platformv1.IAMUserResponse{})
	if st, _ := status.FromError(err); st == nil || st.Code() != codes.Internal {
		t.Fatalf("status = %v, want Internal", st)
	}
}

// TestIAMResourceReplies_WrongReplyTypeIsAnError: the decoder places the
// resource on the reply's field, so a reply without that field is refused.
func TestIAMResourceReplies_WrongReplyTypeIsAnError(t *testing.T) {
	decode := restResponseDecoders[platformv1.PlatformIAMService_GetUser_FullMethodName]
	err := decode([]byte(`{"id":"u-7"}`), &platformv1.IAMRoleResponse{})
	require.ErrorIs(t, err, ErrUnexpectedReplyType{Method: platformv1.PlatformIAMService_GetUser_FullMethodName})
}
