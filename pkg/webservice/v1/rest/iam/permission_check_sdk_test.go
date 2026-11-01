package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// sdkRESTConnection connects the SDK's REST transport to server and returns
// the gRPC-shaped connection the generated clients invoke through.
func sdkRESTConnection(t *testing.T, server *httptest.Server) grpc.ClientConnInterface {
	t.Helper()
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return conn.(*sdkrest.Adapter).Connection()
}

// TestCheckPermissionOverSDKREST_RoundTrip drives the SDK's CheckPermission
// claim (POST /api/v1/iam/permissions/check) through the SDK REST transport,
// the real IAM router and its guards, into the PEP, and decodes the verdict
// back into the generated response.
func TestCheckPermissionOverSDKREST_RoundTrip(t *testing.T) {
	t.Parallel()
	var got *iamsdk.CheckRequest
	pep := &mockPEPClient{
		checkFn: func(_ context.Context, req *iamsdk.CheckRequest) (*iamsdk.CheckResponse, error) {
			got = req
			return &iamsdk.CheckResponse{
				Allowed:          true,
				MatchedPolicy:    "docs-writers",
				MatchedRule:      "allow-write",
				EvaluationTimeNs: 4200,
			}, nil
		},
	}
	conn := sdkRESTConnection(t, adminSessionIAMServer(t, &mockIAMClient{}, pep))

	resp, err := platformv1.NewPlatformIAMServiceClient(conn).CheckPermission(context.Background(),
		&platformv1.CheckIAMPermissionRequest{
			TenantId:   "tenant-a",
			SubjectId:  "user-1",
			Roles:      []string{"writer"},
			Groups:     []string{"docs"},
			Action:     "write",
			Resource:   "documents/7",
			Context:    map[string]string{"ip": "10.0.0.7"},
			Attributes: map[string]string{"clearance": "high"},
		})
	require.NoError(t, err)

	assert.True(t, resp.GetAllowed())
	assert.Equal(t, "docs-writers", resp.GetMatchedPolicy())
	assert.Equal(t, "allow-write", resp.GetMatchedRule())
	assert.Equal(t, int64(4200), resp.GetEvaluationTimeNs())

	require.NotNil(t, got, "the PEP was not consulted")
	assert.Equal(t, iamsdk.CheckSubject{
		ID:         "user-1",
		TenantID:   "tenant-a",
		Roles:      []string{"writer"},
		Groups:     []string{"docs"},
		Attributes: map[string]interface{}{"clearance": "high"},
	}, got.Subject)
	assert.Equal(t, "write", got.Action)
	assert.Equal(t, "documents/7", got.Resource)
	assert.Equal(t, map[string]interface{}{"ip": "10.0.0.7"}, got.Context)
}

// TestCheckPermissionOverSDKREST_Refusals pins the error half of the round
// trip: a check naming a tenant other than the caller's is refused before the
// PEP is asked, an incomplete check is rejected, and a daemon without a PEP
// answers Unavailable rather than a verdict.
func TestCheckPermissionOverSDKREST_Refusals(t *testing.T) {
	t.Parallel()
	complete := func() *platformv1.CheckIAMPermissionRequest {
		return &platformv1.CheckIAMPermissionRequest{
			TenantId: "tenant-a", SubjectId: "user-1", Action: "read", Resource: "documents/7",
		}
	}
	unreachablePEP := &mockPEPClient{
		checkFn: func(context.Context, *iamsdk.CheckRequest) (*iamsdk.CheckResponse, error) {
			t.Error("the PEP was consulted for a request the route must refuse")
			return &iamsdk.CheckResponse{Allowed: true}, nil
		},
	}

	cases := []struct {
		name     string
		pep      PEPClient
		request  *platformv1.CheckIAMPermissionRequest
		wantCode codes.Code
	}{
		{
			name: "foreign tenant", pep: unreachablePEP,
			request: func() *platformv1.CheckIAMPermissionRequest {
				r := complete()
				r.TenantId = "tenant-b"
				return r
			}(),
			wantCode: codes.PermissionDenied,
		},
		{
			name: "missing resource", pep: unreachablePEP,
			request: func() *platformv1.CheckIAMPermissionRequest {
				r := complete()
				r.Resource = ""
				return r
			}(),
			wantCode: codes.InvalidArgument,
		},
		{name: "no PEP wired", pep: nil, request: complete(), wantCode: codes.Unavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := sdkRESTConnection(t, adminSessionIAMServer(t, &mockIAMClient{}, tc.pep))

			_, err := platformv1.NewPlatformIAMServiceClient(conn).CheckPermission(context.Background(), tc.request)
			assert.Equalf(t, tc.wantCode, status.Code(err), "err = %v", err)
		})
	}
}
