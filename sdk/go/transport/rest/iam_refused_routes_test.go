// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package rest

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestIAMTokenClaims_RefusedWithoutANetworkCall pins the REST transport's
// answer for the IAM token operations: they have no REST route (docs/iam/api.md
// §6), so the call fails with ErrNoRESTRoute carrying codes.Unimplemented and
// never reaches the server.
func TestIAMTokenClaims_RefusedWithoutANetworkCall(t *testing.T) {
	var hits atomic.Int32
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})
	client := platformv1.NewPlatformIAMServiceClient(a.Connection())
	ctx := context.Background()

	calls := map[string]func() error{
		platformv1.PlatformIAMService_CreateToken_FullMethodName: func() error {
			_, err := client.CreateToken(ctx, &platformv1.CreateIAMTokenRequest{})
			return err
		},
		platformv1.PlatformIAMService_RevokeToken_FullMethodName: func() error {
			_, err := client.RevokeToken(ctx, &platformv1.RevokeIAMTokenRequest{})
			return err
		},
		platformv1.PlatformIAMService_VerifyToken_FullMethodName: func() error {
			_, err := client.VerifyToken(ctx, &platformv1.VerifyIAMTokenRequest{})
			return err
		},
	}
	require.Len(t, calls, len(restRefusedMethods), "every refused method needs a case here")

	for method, call := range calls {
		t.Run(method[strings.LastIndex(method, "/")+1:], func(t *testing.T) {
			err := call()

			var refused ErrNoRESTRoute
			require.True(t, errors.As(err, &refused), "err = %v, want ErrNoRESTRoute", err)
			assert.Equal(t, method, refused.Method)
			assert.Contains(t, refused.Reason, "/api/v1/login")
			assert.Equal(t, codes.Unimplemented, status.Code(err))
		})
	}
	assert.Zero(t, hits.Load(), "a refused method reached the server")
}

// TestRestRefusedMethods_AreRealAndUnrouted guards the refusal table: every
// entry names a method on the generated IAM client, and none is also declared
// in a route map, where the refusal would shadow a real route.
func TestRestRefusedMethods_AreRealAndUnrouted(t *testing.T) {
	iface := reflect.TypeOf((*platformv1.PlatformIAMServiceClient)(nil)).Elem()
	require.NotEmpty(t, restRefusedMethods)

	for full, reason := range restRefusedMethods {
		method := full[strings.LastIndex(full, "/")+1:]
		_, ok := iface.MethodByName(method)
		assert.True(t, ok, "%s is not on the generated IAM client", full)
		assert.NotEmpty(t, reason, "%s is refused without a reason", full)

		_, flat := grpcMethodToRESTMap[full]
		_, templated := templatedRouteTable[full]
		assert.False(t, flat || templated, "%s is both refused and routed", full)
	}
}

func TestErrNoRESTRoute_ErrorAndStatus(t *testing.T) {
	err := ErrNoRESTRoute{Method: "/svc/Op", Reason: "use the other door"}

	assert.Equal(t, "REST transport has no route for /svc/Op: use the other door", err.Error())
	st := err.GRPCStatus()
	assert.Equal(t, codes.Unimplemented, st.Code())
	assert.Equal(t, err.Error(), st.Message())
}

// TestErrNoRESTRoute_OnlyForRefusedMethods is the error-path counterpart: a
// routed IAM method is not refused, it reaches the server.
func TestErrNoRESTRoute_OnlyForRefusedMethods(t *testing.T) {
	var hits atomic.Int32
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	})

	_, err := platformv1.NewPlatformIAMServiceClient(a.Connection()).CheckPermission(
		context.Background(), &platformv1.CheckIAMPermissionRequest{})

	require.Error(t, err)
	var refused ErrNoRESTRoute
	assert.False(t, errors.As(err, &refused), "a routed method was refused: %v", err)
	assert.Equal(t, int32(1), hits.Load())
}
