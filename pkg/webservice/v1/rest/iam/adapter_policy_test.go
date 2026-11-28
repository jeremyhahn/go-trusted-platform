package iam

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recordingPolicies is an upstream policy client with the pinned embedded
// transport's contracts: List applies Limit to the head of the collection
// and returns no cursor and no TotalCount. It records what reaches it.
type recordingPolicies struct {
	iamsdk.PolicyClient
	policies  []iamsdk.Policy
	creates   int
	listLimit []int
	tested    []*iamsdk.TestPolicyRequest
}

func (p *recordingPolicies) Create(_ context.Context, _ string, req *iamsdk.CreatePolicyRequest) (*iamsdk.Policy, error) {
	p.creates++
	return &iamsdk.Policy{Name: req.Name}, nil
}

func (p *recordingPolicies) List(_ context.Context, _ string, req *iamsdk.ListPoliciesRequest) (*iamsdk.ListPoliciesResponse, error) {
	p.listLimit = append(p.listLimit, req.Limit)
	end := len(p.policies)
	if req.Limit > 0 && req.Limit < end {
		end = req.Limit
	}
	return &iamsdk.ListPoliciesResponse{Policies: append([]iamsdk.Policy(nil), p.policies[:end]...)}, nil
}

func (p *recordingPolicies) Test(_ context.Context, _ string, req *iamsdk.TestPolicyRequest) (*iamsdk.TestPolicyResponse, error) {
	p.tested = append(p.tested, req)
	return &iamsdk.TestPolicyResponse{}, nil
}

type recordingPolicyClient struct {
	*cov964Client
	policies *recordingPolicies
}

func (c *recordingPolicyClient) Policy() iamsdk.PolicyClient { return c.policies }

func newRecordingAdapter() (*QuicBaaSIAMAdapter, *recordingPolicies) {
	up := &recordingPolicies{}
	return NewQuicBaaSIAMAdapter(&recordingPolicyClient{cov964Client: cov964NewClient(), policies: up}), up
}

// A rule carrying when/unless is refused before the upstream is called: the
// pinned upstream persists only the flat Rules, which carry no conditions,
// so a conditional allow would be stored as an unconditional one.
func TestQuicBaaSIAMAdapter_CreatePolicyRefusesConditions(t *testing.T) {
	t.Parallel()
	for name, spec := range map[string]string{
		"when":   "spec:\n  rules:\n    - name: r\n      effect: allow\n      actions: [\"read\"]\n      resources: [\"*\"]\n      when:\n        - attr: mfa\n",
		"unless": "rules:\n  - name: r\n    effect: allow\n    actions: [\"read\"]\n    resources: [\"*\"]\n    unless:\n      - attr: guest\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adapter, up := newRecordingAdapter()
			_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "p", SpecYAML: spec})
			require.Error(t, err)
			assert.ErrorAs(t, err, new(ErrInvalidRequestBody))
			assert.Contains(t, err.Error(), name)
			assert.Zero(t, up.creates, "no create may reach the upstream")
		})
	}

	adapter, up := newRecordingAdapter()
	_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{
		Name: "p", SpecYAML: "rules:\n  - name: r\n    effect: allow\n    actions: [\"read\"]\n    resources: [\"*\"]\n",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, up.creates)
}

// TestQuicBaaSIAMAdapter_CreatePolicyRefusesUnknownEffect pins that a rule
// effect other than allow or deny is refused before anything is created: the
// pinned upstream persists the translated Rules only, so a `DENY` rule would
// otherwise be stored as an allow rule.
func TestQuicBaaSIAMAdapter_CreatePolicyRefusesUnknownEffect(t *testing.T) {
	t.Parallel()
	spec := func(effect string) string {
		return "rules:\n  - name: r1\n    effect: \"" + effect + "\"\n    actions: [\"read\"]\n    resources: [\"*\"]\n"
	}
	for _, effect := range []string{"DENY", "Deny", "block", ""} {
		t.Run("bad/"+effect, func(t *testing.T) {
			t.Parallel()
			adapter, up := newRecordingAdapter()
			_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "p", SpecYAML: spec(effect)})
			require.Error(t, err)
			assert.ErrorAs(t, err, new(ErrInvalidRequestBody))
			assert.Contains(t, err.Error(), `"r1"`)
			assert.Contains(t, err.Error(), `"`+effect+`"`)
			assert.Zero(t, up.creates, "no create may reach the upstream")
		})
	}
	for _, effect := range []string{"deny", "allow"} {
		t.Run("ok/"+effect, func(t *testing.T) {
			t.Parallel()
			adapter, up := newRecordingAdapter()
			_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "p", SpecYAML: spec(effect)})
			require.NoError(t, err)
			assert.Equal(t, 1, up.creates)
		})
	}
}

// TestQuicBaaSIAMAdapter_CreatePolicyRefusesSubjects: the pinned backend
// stores only the flat rules and drops the subject selector, and an empty
// selector matches every subject, so a subject-scoped policy would grant its
// rules to everyone. CreatePolicy refuses it before anything is created.
func TestQuicBaaSIAMAdapter_CreatePolicyRefusesSubjects(t *testing.T) {
	t.Parallel()
	const rule = "  rules:\n    - name: r\n      effect: allow\n      actions: [read]\n      resources: [\"*\"]\n"
	for name, spec := range map[string]string{
		"spec roles":     "spec:\n  subjects:\n    roles: [reader]\n" + rule,
		"top-level":      "subjects:\n  users: [u1]\nrules:\n  - name: r\n    effect: allow\n    actions: [read]\n    resources: [\"*\"]\n",
		"spec any":       "spec:\n  subjects:\n    any: true\n" + rule,
		"spec attribute": "spec:\n  subjects:\n    match: {dept: eng}\n" + rule,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adapter, up := newRecordingAdapter()
			_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "p", SpecYAML: spec})
			require.Error(t, err)
			assert.ErrorAs(t, err, new(ErrInvalidRequestBody))
			assert.Contains(t, err.Error(), "subjects")
			assert.Zero(t, up.creates, "no create may reach the upstream")
		})
	}

	adapter, up := newRecordingAdapter()
	_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{
		Name: "p", SpecYAML: "spec:\n  subjects: {}\n" + rule,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, up.creates)
}

// A subject selector that is not a mapping must be refused, not read as no
// selector: the rules parser ignores subjects, so the allow rule would reach
// the upstream and apply to every subject.
func TestQuicBaaSIAMAdapter_CreatePolicyRefusesMalformedSubjects(t *testing.T) {
	t.Parallel()
	const rule = "  rules:\n    - name: r\n      effect: allow\n      actions: [read]\n      resources: [\"*\"]\n"
	for name, spec := range map[string]string{
		"spec list":   "spec:\n  subjects: [reader]\n" + rule,
		"spec scalar": "spec:\n  subjects: reader\n" + rule,
		// The rules decode on their own while the selector does not: the
		// guard must refuse, never fall through to a selector-less create.
		"spec undecodable": "spec:\n  subjects: !!int not-an-int\n" + rule,
		"top-level list":   "subjects: [u1]\nrules:\n  - name: r\n    effect: allow\n    actions: [read]\n    resources: [\"*\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adapter, up := newRecordingAdapter()
			_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "p", SpecYAML: spec})
			require.Error(t, err)
			assert.ErrorAs(t, err, new(ErrInvalidRequestBody))
			assert.Contains(t, err.Error(), "subjects")
			assert.Zero(t, up.creates, "no create may reach the upstream")
		})
	}

	for name, spec := range map[string]string{
		"absent":    "spec:\n" + rule,
		"empty map": "spec:\n  subjects: {}\n" + rule,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			adapter, up := newRecordingAdapter()
			_, err := adapter.CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{Name: "p", SpecYAML: spec})
			require.NoError(t, err)
			assert.Equal(t, 1, up.creates)
		})
	}
}

// Paging is done over the whole collection: the upstream supplies no cursor
// and no total, so the adapter asks for everything and slices it.
func TestQuicBaaSIAMAdapter_ListPoliciesWithoutCursor(t *testing.T) {
	t.Parallel()
	adapter, up := newRecordingAdapter()
	for _, n := range []string{"p1", "p2", "p3", "p4", "p5"} {
		up.policies = append(up.policies, iamsdk.Policy{Name: n})
	}
	resp, err := adapter.ListPolicies(context.Background(), "tenant-a", 2, 2)
	require.NoError(t, err)
	var names []string
	for _, p := range resp.Policies {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"p3", "p4"}, names)
	assert.Equal(t, int64(5), resp.Total)
	assert.Equal(t, []int{0}, up.listLimit, "one unlimited upstream list")

	resp, err = adapter.ListPolicies(context.Background(), "tenant-a", 2, 9)
	require.NoError(t, err)
	assert.Empty(t, resp.Policies)
	assert.Equal(t, int64(5), resp.Total)
}

// TestPolicy evaluates against the named policy; the pinned SDK refuses a
// request without one, so a request naming none is refused explicitly.
func TestQuicBaaSIAMAdapter_TestPolicyUnimplemented(t *testing.T) {
	t.Parallel()
	var req TestPolicyRequest
	require.NoError(t, json.Unmarshal([]byte(`{"policy_name":"p1","subject_id":"u","action":"read","resource":"r"}`), &req))

	adapter, up := newRecordingAdapter()
	_, err := adapter.TestPolicy(context.Background(), "tenant-a", &req)
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err), "err %v", err)
	assert.Empty(t, up.tested, "no test may reach the upstream")

	typ := reflect.TypeOf(TestPolicyRequest{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		assert.False(t, strings.HasPrefix(f.Tag.Get("json"), "policy_name"),
			"TestPolicyRequest.%s carries a REST-only policy_name the SDK request lacks", f.Name)
	}
}
