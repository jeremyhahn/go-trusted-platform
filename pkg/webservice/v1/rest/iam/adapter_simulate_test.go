package iam

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	qberrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The pinned embedded transport does not dispatch quicbaas.IAM.Policy/Simulate
// (an upstream go-quicbaas gap). A REST policy test must then answer 501 Not
// Implemented naming policy simulation, never a 500.
func TestAdapter_TestPolicy_UnimplementedSimulateIs501(t *testing.T) {
	upstream := map[string]error{
		"unimplemented code": qberrors.NewUnimplemented("iam.Policy.Simulate", "not implemented"),
		"unknown method":     errors.New("embedded: unknown method quicbaas.IAM.Policy/Simulate"),
		"grpc unimplemented": status.Error(codes.Unimplemented, "unknown method Simulate"),
	}
	for name, upErr := range upstream {
		t.Run(name, func(t *testing.T) {
			client := cov964NewClient()
			client.policies.err = upErr
			adapter := NewQuicBaaSIAMAdapter(client)

			_, err := adapter.TestPolicy(context.Background(), "tenant-1", &TestPolicyRequest{
				SubjectID: "user-123", Action: "read", Resource: "files/1",
			})
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "adapter must return a gRPC status, got %v", err)
			assert.Equal(t, codes.Unimplemented, st.Code())
			assert.Contains(t, st.Message(), "policy simulation")

			writer := &mockHttpWriter{}
			handlers := NewIAMHandlers(newTestLogger(), adapter, nil, writer)
			body := TestPolicyRequest{SubjectID: "user-123", Action: "read", Resource: "files/1"}
			req := createRequestWithVars(http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test", body, map[string]string{"tenant": "tenant-1"})
			handlers.TestPolicy(httptest.NewRecorder(), req)
			assert.Equal(t, http.StatusNotImplemented, writer.lastStatus)
		})
	}
}

// Other upstream failures keep their own mapping.
func TestAdapter_TestPolicy_OtherErrorsPassThrough(t *testing.T) {
	client := cov964NewClient()
	client.policies.err = qberrors.NewUnavailable("iam.Policy.Simulate", "backend down")
	_, err := NewQuicBaaSIAMAdapter(client).TestPolicy(context.Background(), "tenant-1", &TestPolicyRequest{
		SubjectID: "user-123", Action: "read", Resource: "files/1",
	})
	assert.Equal(t, client.policies.err, err)
}
