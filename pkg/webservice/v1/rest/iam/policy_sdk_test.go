package iam

import (
	"context"
	"testing"
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestPolicyMethodsOverSDKREST_RoundTrip drives the seven IAM policy RPCs
// through the SDK's REST transport against the built router (#1958): each
// reaches its tenant-scoped route, spec_yaml travels as YAML text both ways,
// and every reply decodes into its proto response.
func TestPolicyMethodsOverSDKREST_RoundTrip(t *testing.T) {
	t.Parallel()
	const spec = "rules:\n  - effect: allow\n    actions: [read]\n"
	created := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	policy := func(name string) *PolicyResponse {
		return &PolicyResponse{
			Name: name, TenantID: "tenant-a", Description: "readers", Priority: 5,
			SpecYAML: spec, Labels: map[string]string{"team": "docs"},
			CreatedAt: &created, UpdatedAt: &created,
		}
	}

	var (
		createdReq   *CreatePolicyRequest
		updatedReq   *UpdatePolicyRequest
		validatedYML string
		testedReq    *TestPolicyRequest
		listLimit    int32
		listOffset   int32
		seen         = map[string]string{}
	)
	iamClient := &mockIAMClient{
		createPolicyFn: func(_ context.Context, tenantID string, req *CreatePolicyRequest) (*PolicyResponse, error) {
			seen["create"], createdReq = tenantID, req
			return policy(req.Name), nil
		},
		listPoliciesFn: func(_ context.Context, tenantID string, limit, offset int32) (*ListPoliciesResponse, error) {
			seen["list"] = tenantID
			listLimit, listOffset = limit, offset
			resp := &ListPoliciesResponse{Policies: []PolicyResponse{*policy("p1"), *policy("p2")}}
			resp.Total = 2
			return resp, nil
		},
		getPolicyFn: func(_ context.Context, tenantID, name string) (*PolicyResponse, error) {
			seen["get"] = tenantID + "/" + name
			return policy(name), nil
		},
		updatePolicyFn: func(_ context.Context, tenantID, name string, req *UpdatePolicyRequest) (*PolicyResponse, error) {
			seen["update"], updatedReq = tenantID+"/"+name, req
			return policy(name), nil
		},
		deletePolicyFn: func(_ context.Context, tenantID, name string) error {
			seen["delete"] = tenantID + "/" + name
			return nil
		},
		validatePolicyFn: func(_ context.Context, tenantID, specYAML string) (*ValidatePolicyResponse, error) {
			seen["validate"], validatedYML = tenantID, specYAML
			return &ValidatePolicyResponse{Valid: false, Errors: []string{"rule 1: unknown action"}}, nil
		},
		testPolicyFn: func(_ context.Context, tenantID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
			seen["test"], testedReq = tenantID, req
			return &TestPolicyResponse{Allowed: true, MatchedPolicy: "p1", MatchedRule: "r1", EvaluationTimeNs: 4200}, nil
		},
	}
	client := platformv1.NewPlatformIAMServiceClient(
		sdkRESTConnection(t, adminSessionIAMServer(t, iamClient, &mockPEPClient{})))
	ctx := context.Background()

	assertPolicy := func(t *testing.T, got *platformv1.IAMPolicy, name string) {
		t.Helper()
		require.NotNil(t, got)
		assert.Equal(t, name, got.GetName())
		assert.Equal(t, "tenant-a", got.GetTenantId())
		assert.Equal(t, "readers", got.GetDescription())
		assert.Equal(t, int32(5), got.GetPriority())
		assert.Equal(t, spec, string(got.GetSpecYaml()))
		assert.Equal(t, "docs", got.GetLabels()["team"])
		assert.True(t, got.GetCreatedAt().AsTime().Equal(created))
	}

	createResp, err := client.CreatePolicy(ctx, &platformv1.CreateIAMPolicyRequest{
		TenantId: "tenant-a", Name: "p1", Description: "readers", Priority: 5,
		SpecYaml: []byte(spec), Labels: map[string]string{"team": "docs"},
	})
	require.NoError(t, err)
	assertPolicy(t, createResp.GetPolicy(), "p1")
	assert.Equal(t, "tenant-a", seen["create"])
	require.NotNil(t, createdReq)
	assert.Equal(t, "p1", createdReq.Name)
	assert.Equal(t, spec, createdReq.SpecYAML)
	assert.Equal(t, int32(5), createdReq.Priority)

	listResp, err := client.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{
		TenantId: "tenant-a", Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 7},
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", seen["list"])
	assert.Equal(t, int32(7), listLimit, "page_size reaches the backend as the limit")
	assert.Equal(t, int32(7), listOffset, "page 2 of 7 reaches the backend as offset 7")
	require.Len(t, listResp.GetPolicies(), 2)
	assertPolicy(t, listResp.GetPolicies()[1], "p2")
	assert.Equal(t, int64(2), listResp.GetTotal())

	getResp, err := client.GetPolicy(ctx, &platformv1.GetIAMPolicyRequest{TenantId: "tenant-a", PolicyName: "p1"})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a/p1", seen["get"])
	assertPolicy(t, getResp.GetPolicy(), "p1")

	updateResp, err := client.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
		TenantId: "tenant-a", PolicyName: "p1", Description: "readers",
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a/p1", seen["update"])
	assertPolicy(t, updateResp.GetPolicy(), "p1")
	require.NotNil(t, updatedReq)
	assert.Equal(t, "readers", updatedReq.Description)

	deleteResp, err := client.DeletePolicy(ctx, &platformv1.DeleteIAMPolicyRequest{TenantId: "tenant-a", PolicyName: "p1"})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a/p1", seen["delete"])
	assert.True(t, deleteResp.GetStatus().GetSuccess())
	assert.Equal(t, "policy deleted successfully", deleteResp.GetStatus().GetMessage())

	validateResp, err := client.ValidatePolicy(ctx, &platformv1.ValidateIAMPolicyRequest{
		TenantId: "tenant-a", SpecYaml: []byte(spec),
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", seen["validate"])
	assert.Equal(t, spec, validatedYML)
	assert.False(t, validateResp.GetValid())
	assert.Equal(t, []string{"rule 1: unknown action"}, validateResp.GetErrors())

	testResp, err := client.TestPolicy(ctx, &platformv1.TestIAMPolicyRequest{
		TenantId: "tenant-a", SubjectId: "user-1", Roles: []string{"reader"},
		Action: "read", Resource: "documents/7",
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", seen["test"])
	require.NotNil(t, testedReq)
	assert.Equal(t, "user-1", testedReq.SubjectID)
	assert.Equal(t, []string{"reader"}, testedReq.Roles)
	assert.Equal(t, "read", testedReq.Action)
	assert.Equal(t, "documents/7", testedReq.Resource)
	assert.True(t, testResp.GetAllowed())
	assert.Equal(t, "p1", testResp.GetMatchedPolicy())
	assert.Equal(t, "r1", testResp.GetMatchedRule())
	assert.Equal(t, int64(4200), testResp.GetEvaluationTimeNs())
}

// pagedPolicies is an upstream policy client with the pinned embedded
// transport's list contract: it applies Limit to the head of the collection
// and returns neither HasMore, NextCursor nor TotalCount.
type pagedPolicies struct {
	iamsdk.PolicyClient
	t        *testing.T
	policies []iamsdk.Policy
}

func (p *pagedPolicies) List(_ context.Context, _ string, req *iamsdk.ListPoliciesRequest) (*iamsdk.ListPoliciesResponse, error) {
	end := len(p.policies)
	if req.Limit > 0 && req.Limit < end {
		end = req.Limit
	}
	return &iamsdk.ListPoliciesResponse{Policies: append([]iamsdk.Policy(nil), p.policies[:end]...)}, nil
}

func (p *pagedPolicies) Update(context.Context, string, string, *iamsdk.UpdatePolicyRequest) (*iamsdk.Policy, error) {
	p.t.Fatal("a spec_yaml update must be refused before the upstream is called")
	return nil, nil
}

// pagedPolicyClient is the cov964 SDK client with the cursor-paged policies.
type pagedPolicyClient struct {
	*cov964Client
	policies *pagedPolicies
}

func (c *pagedPolicyClient) Policy() iamsdk.PolicyClient { return c.policies }

// TestPolicyMethodsOverSDKREST_ProductionAdapter serves the production
// QuicBaaSIAMAdapter over SDK REST: a page past the first returns that page
// of the cursor-paged upstream with its total, and a spec_yaml update is
// refused as InvalidArgument without reaching the upstream.
func TestPolicyMethodsOverSDKREST_ProductionAdapter(t *testing.T) {
	t.Parallel()
	upstream := &pagedPolicies{t: t}
	for _, name := range []string{"p1", "p2", "p3", "p4", "p5"} {
		upstream.policies = append(upstream.policies, iamsdk.Policy{Name: name, SpecYAML: []byte("rules: []")})
	}
	adapter := NewQuicBaaSIAMAdapter(&pagedPolicyClient{cov964Client: cov964NewClient(), policies: upstream})
	client := platformv1.NewPlatformIAMServiceClient(
		sdkRESTConnection(t, adminSessionIAMServer(t, adapter, &mockPEPClient{})))
	ctx := context.Background()

	names := func(resp *platformv1.ListIAMPoliciesResponse) []string {
		var out []string
		for _, p := range resp.GetPolicies() {
			out = append(out, p.GetName())
		}
		return out
	}

	page2, err := client.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{
		TenantId: "tenant-a", Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 2},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"p3", "p4"}, names(page2))
	assert.Equal(t, int64(5), page2.GetTotal())

	page3, err := client.ListPolicies(ctx, &platformv1.ListIAMPoliciesRequest{
		TenantId: "tenant-a", Pagination: &platformv1.PaginationRequest{Page: 3, PageSize: 2},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"p5"}, names(page3))
	assert.Equal(t, int64(5), page3.GetTotal())

	_, err = client.UpdatePolicy(ctx, &platformv1.UpdateIAMPolicyRequest{
		TenantId: "tenant-a", PolicyName: "p1", SpecYaml: []byte("rules: []"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "err %v", err)
}
