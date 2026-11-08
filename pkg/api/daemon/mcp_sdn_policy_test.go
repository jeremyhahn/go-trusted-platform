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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// webPolicyBody is a REST create-policy body. Its bridge target names a bridge
// the test service does not hold, so applying it installs no OpenFlow rules.
const webPolicyBody = `{"name": "web", "type": "firewall", "priority": 200, "enabled": true,
	"targets": [{"type": "bridge", "id": "br0"}]}`

func newPolicySDNService() *SDNService {
	return newTestSDNService(NewConfigurableMockOVSClient())
}

// applyWebPolicy stores webPolicyBody through the shared service and returns
// the generated policy ID.
func applyWebPolicy(t *testing.T, svc *SDNService) string {
	t.Helper()
	got, err := applySDNPolicy(context.Background(), svc, json.RawMessage(webPolicyBody))
	require.NoError(t, err)
	policy, ok := got.(rest.PolicyResponse)
	require.True(t, ok, "applySDNPolicy returned %T", got)
	return policy.ID
}

func TestApplySDNPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("stores the policy and returns the REST shape", func(t *testing.T) {
		svc := newPolicySDNService()

		got, err := applySDNPolicy(ctx, svc, json.RawMessage(webPolicyBody))

		require.NoError(t, err)
		policy, ok := got.(rest.PolicyResponse)
		require.True(t, ok, "applySDNPolicy returned %T", got)
		assert.NotEmpty(t, policy.ID)
		assert.Equal(t, "web", policy.Name)
		assert.Equal(t, "firewall", policy.Type)
		assert.Equal(t, int32(200), policy.Priority)

		stored, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: policy.ID})
		require.NoError(t, err)
		assert.Equal(t, "web", stored.GetPolicy().GetConfig().GetName())
	})

	invalid := map[string]string{
		"a body that is not JSON": `{"name": `,
		"an unknown policy type":  `{"name": "web", "type": "bogus"}`,
	}
	for name, body := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := applySDNPolicy(ctx, newPolicySDNService(), json.RawMessage(body))

			var invalidPolicy ErrSDNInvalidPolicy
			assert.True(t, errors.As(err, &invalidPolicy), "got %T: %v", err, err)
		})
	}

	t.Run("passes the service's duplicate-name error through", func(t *testing.T) {
		svc := newPolicySDNService()
		applyWebPolicy(t, svc)

		_, err := applySDNPolicy(ctx, svc, json.RawMessage(webPolicyBody))

		assert.Equal(t, codes.AlreadyExists, status.Code(err))
	})

	t.Run("needs the SDN service", func(t *testing.T) {
		_, err := applySDNPolicy(ctx, nil, json.RawMessage(webPolicyBody))

		assert.Equal(t, ErrServiceNotAvailable{Service: "sdn"}, err)
	})
}

func TestGetSDNPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("finds the policy by ID and by name", func(t *testing.T) {
		svc := newPolicySDNService()
		id := applyWebPolicy(t, svc)

		for _, key := range []string{id, "web"} {
			got, err := getSDNPolicy(ctx, svc, key)

			require.NoError(t, err)
			assert.Equal(t, id, got.(rest.PolicyResponse).ID)
		}
	})

	t.Run("names the policy that was not found", func(t *testing.T) {
		_, err := getSDNPolicy(ctx, newPolicySDNService(), "missing")

		assert.Equal(t, ErrSDNPolicyNotFound{PolicyID: "missing"}, err)
	})

	t.Run("needs the SDN service", func(t *testing.T) {
		_, err := getSDNPolicy(ctx, nil, "web")

		assert.Equal(t, ErrServiceNotAvailable{Service: "sdn"}, err)
	})
}

func TestListSDNPolicies(t *testing.T) {
	ctx := context.Background()

	t.Run("applies the type and target filters", func(t *testing.T) {
		svc := newPolicySDNService()
		id := applyWebPolicy(t, svc)

		all, err := listSDNPolicies(ctx, svc, "", "")
		require.NoError(t, err)
		require.Len(t, all, 1)
		assert.Equal(t, id, all[0].(rest.PolicyResponse).ID)

		matching, err := listSDNPolicies(ctx, svc, "firewall", "br0")
		require.NoError(t, err)
		assert.Len(t, matching, 1)

		otherType, err := listSDNPolicies(ctx, svc, "qos", "")
		require.NoError(t, err)
		assert.Empty(t, otherType)

		otherTarget, err := listSDNPolicies(ctx, svc, "", "br1")
		require.NoError(t, err)
		assert.Empty(t, otherTarget)
	})

	t.Run("needs the SDN service", func(t *testing.T) {
		_, err := listSDNPolicies(ctx, nil, "", "")

		assert.Equal(t, ErrServiceNotAvailable{Service: "sdn"}, err)
	})
}

func TestDeleteSDNPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("removes the policy from the shared service", func(t *testing.T) {
		svc := newPolicySDNService()
		applyWebPolicy(t, svc)

		require.NoError(t, deleteSDNPolicy(ctx, svc, "web"))

		_, err := svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "web"})
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("names the policy that was not found", func(t *testing.T) {
		err := deleteSDNPolicy(ctx, newPolicySDNService(), "missing")

		assert.Equal(t, ErrSDNPolicyNotFound{PolicyID: "missing"}, err)
	})

	t.Run("needs the SDN service", func(t *testing.T) {
		err := deleteSDNPolicy(ctx, nil, "web")

		assert.Equal(t, ErrServiceNotAvailable{Service: "sdn"}, err)
	})
}

func TestNamePolicyNotFound(t *testing.T) {
	t.Run("names the policy for NotFound", func(t *testing.T) {
		err := namePolicyNotFound("web", status.Error(codes.NotFound, "policy not found"))

		assert.Equal(t, ErrSDNPolicyNotFound{PolicyID: "web"}, err)
	})

	t.Run("keeps any other error unchanged", func(t *testing.T) {
		invalid := status.Error(codes.InvalidArgument, "policy_id is required")

		assert.Equal(t, invalid, namePolicyNotFound("", invalid))
	})

	t.Run("keeps success as nil", func(t *testing.T) {
		assert.NoError(t, namePolicyNotFound("web", nil))
	})
}

// policyTransports reaches one SDNService over the MCP tools of the service
// provider, the REST routes and the gRPC service methods, the way the daemon
// wires them.
type policyTransports struct {
	svc      *SDNService
	mcpTools map[string]*mcp.ToolRegistry
	rest     *mux.Router
	quic     *QUICServiceHandler
}

func newPolicyTransports(t *testing.T) policyTransports {
	t.Helper()
	svc := newPolicySDNService()

	handlers := rest.NewSDNHandlers(svc, slog.Default())
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)

	return policyTransports{
		svc: svc,
		mcpTools: map[string]*mcp.ToolRegistry{
			"MCPServiceProvider": mcp.NewToolRegistry(NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: svc,
				Logger:     slog.Default(),
			}), logging.DefaultLogger()),
		},
		rest: router,
		quic: newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICSDNService(svc)),
	}
}

func (p policyTransports) serveREST(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	p.rest.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
	return w
}

// webPolicyProtoBody is webPolicyBody as the REST route takes it: a protojson
// ApplyPolicyRequest.
func webPolicyProtoBody(t *testing.T) []byte {
	t.Helper()
	var req rest.CreatePolicyRequest
	require.NoError(t, json.Unmarshal([]byte(webPolicyBody), &req))
	apply, err := rest.PolicyRequestToProto(req)
	require.NoError(t, err)
	body, err := protojson.Marshal(apply)
	require.NoError(t, err)
	return body
}

// decodeRESTPolicy decodes the policy a REST policy route answered with (an
// ApplyPolicyResponse or GetPolicyResponse) into the form the MCP and QUIC
// transports answer with.
func decodeRESTPolicy(t *testing.T, w *httptest.ResponseRecorder) rest.PolicyResponse {
	t.Helper()
	// Only the policy field is read; an ApplyPolicyResponse also carries status.
	var resp platformv1.GetPolicyResponse
	decode := protojson.UnmarshalOptions{DiscardUnknown: true}
	require.NoError(t, decode.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	return rest.PolicyToResponse(resp.GetPolicy())
}

// decodeToolResult re-encodes an MCP tool result as JSON, the form an MCP
// client receives, and decodes it into v.
func decodeToolResult(t *testing.T, result interface{}, v interface{}) {
	t.Helper()
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, v))
}

func TestSDNPolicyTransportParity(t *testing.T) {
	ctx := context.Background()

	for providerName := range newPolicyTransports(t).mcpTools {
		t.Run("REST and gRPC policies are seen over MCP via "+providerName, func(t *testing.T) {
			p := newPolicyTransports(t)
			tools := p.mcpTools[providerName]

			created := p.serveREST(t, http.MethodPost, "/api/v1/sdn/policies", webPolicyProtoBody(t))
			require.Equal(t, http.StatusOK, created.Code, created.Body.String())
			restPolicy := decodeRESTPolicy(t, created)

			_, err := p.svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{
				Name: "grpc-qos",
				Type: platformv1.PolicyType_POLICY_TYPE_QOS,
			}})
			require.NoError(t, err)

			got, err := tools.ExecuteTool(ctx, "sdn_get_policy", map[string]interface{}{"policy_id": restPolicy.ID})
			require.NoError(t, err)
			var mcpPolicy rest.PolicyResponse
			decodeToolResult(t, got, &mcpPolicy)
			assert.Equal(t, restPolicy, mcpPolicy)

			listed, err := tools.ExecuteTool(ctx, "sdn_list_policies", map[string]interface{}{})
			require.NoError(t, err)
			var list struct {
				Policies []rest.PolicyResponse `json:"policies"`
			}
			decodeToolResult(t, listed, &list)
			names := make([]string, 0, len(list.Policies))
			for _, policy := range list.Policies {
				names = append(names, policy.Name)
			}
			assert.ElementsMatch(t, []string{"web", "grpc-qos"}, names)
		})

		t.Run("MCP policies are seen over REST and gRPC via "+providerName, func(t *testing.T) {
			p := newPolicyTransports(t)
			tools := p.mcpTools[providerName]

			var args map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(webPolicyBody), &args))
			applied, err := tools.ExecuteTool(ctx, "sdn_apply_policy", args)
			require.NoError(t, err)
			var mcpPolicy rest.PolicyResponse
			decodeToolResult(t, applied, &mcpPolicy)

			fetched := p.serveREST(t, http.MethodGet, "/api/v1/sdn/policies/"+mcpPolicy.ID, nil)
			require.Equal(t, http.StatusOK, fetched.Code, fetched.Body.String())
			restPolicy := decodeRESTPolicy(t, fetched)
			assert.Equal(t, mcpPolicy, restPolicy)

			grpcPolicy, err := p.svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "web"})
			require.NoError(t, err)
			assert.Equal(t, mcpPolicy.ID, grpcPolicy.GetPolicy().GetId())

			_, err = tools.ExecuteTool(ctx, "sdn_delete_policy", map[string]interface{}{"policy_id": "web"})
			require.NoError(t, err)
			gone := p.serveREST(t, http.MethodGet, "/api/v1/sdn/policies/"+mcpPolicy.ID, nil)
			assert.Equal(t, http.StatusNotFound, gone.Code)
		})
	}

	t.Run("REST, gRPC and MCP policies are seen over QUIC", func(t *testing.T) {
		p := newPolicyTransports(t)

		created := p.serveREST(t, http.MethodPost, "/api/v1/sdn/policies", webPolicyProtoBody(t))
		require.Equal(t, http.StatusOK, created.Code, created.Body.String())
		restPolicy := decodeRESTPolicy(t, created)

		_, err := p.svc.ApplyPolicy(ctx, &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{
			Name: "grpc-qos",
			Type: platformv1.PolicyType_POLICY_TYPE_QOS,
		}})
		require.NoError(t, err)

		applied, err := p.mcpTools["MCPServiceProvider"].ExecuteTool(ctx, "sdn_apply_policy",
			map[string]interface{}{"name": "mcp-acl", "type": "acl", "enabled": true})
		require.NoError(t, err)
		var mcpPolicy rest.PolicyResponse
		decodeToolResult(t, applied, &mcpPolicy)

		for _, want := range []rest.PolicyResponse{restPolicy, mcpPolicy} {
			var quicPolicy rest.PolicyResponse
			decodeQUICPolicy(t, callQUICPolicy(t, p.quic, quicwire.OpSDNGetPolicy, SDNGetPolicyRequest{PolicyID: want.ID}), &quicPolicy)
			assert.Equal(t, want, inUTC(quicPolicy))
		}

		var list rest.SDNPolicyListResponse
		decodeQUICPolicy(t, callQUICPolicy(t, p.quic, quicwire.OpSDNListPolicies, SDNListPoliciesRequest{}), &list)
		names := make([]string, 0, len(list.Policies))
		for _, policy := range list.Policies {
			names = append(names, policy.Name)
		}
		assert.ElementsMatch(t, []string{"web", "grpc-qos", "mcp-acl"}, names)
		assert.Equal(t, 3, list.Count)
	})

	t.Run("QUIC policies are seen over REST, gRPC and MCP", func(t *testing.T) {
		p := newPolicyTransports(t)

		var quicPolicy rest.PolicyResponse
		decodeQUICPolicy(t, callQUICPolicy(t, p.quic, quicwire.OpSDNApplyPolicy, webPolicyRequest(t)), &quicPolicy)
		quicPolicy = inUTC(quicPolicy)

		fetched := p.serveREST(t, http.MethodGet, "/api/v1/sdn/policies/"+quicPolicy.ID, nil)
		require.Equal(t, http.StatusOK, fetched.Code, fetched.Body.String())
		restPolicy := decodeRESTPolicy(t, fetched)
		assert.Equal(t, quicPolicy, restPolicy)

		got, err := p.mcpTools["MCPServiceProvider"].ExecuteTool(ctx, "sdn_get_policy", map[string]interface{}{"policy_id": quicPolicy.ID})
		require.NoError(t, err)
		var mcpPolicy rest.PolicyResponse
		decodeToolResult(t, got, &mcpPolicy)
		assert.Equal(t, quicPolicy, mcpPolicy)

		grpcPolicy, err := p.svc.GetPolicy(ctx, &platformv1.GetPolicyRequest{PolicyId: "web"})
		require.NoError(t, err)
		assert.Equal(t, quicPolicy, rest.PolicyToResponse(grpcPolicy.GetPolicy()))

		var deleted rest.SDNActionResponse
		decodeQUICPolicy(t, callQUICPolicy(t, p.quic, quicwire.OpSDNDeletePolicy, SDNDeletePolicyRequest{PolicyID: "web"}), &deleted)
		assert.True(t, deleted.Success)
		gone := p.serveREST(t, http.MethodGet, "/api/v1/sdn/policies/"+quicPolicy.ID, nil)
		assert.Equal(t, http.StatusNotFound, gone.Code)
	})
}
