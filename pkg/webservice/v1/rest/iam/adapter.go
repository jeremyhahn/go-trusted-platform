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

package iam

import (
	"context"
	"errors"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"gopkg.in/yaml.v3"
)

// parsePolicyRulesFromYAML extracts the rules slice from the canonical
// IAM Policy YAML document. Returns nil when the YAML cannot be parsed;
// callers should treat that as "no rules" and substitute a default.
func parsePolicyRulesFromYAML(specYAML string) []iamsdk.Rule {
	if specYAML == "" {
		return nil
	}
	var doc struct {
		Spec struct {
			Rules []struct {
				Name      string                   `yaml:"name"`
				Effect    string                   `yaml:"effect"`
				Priority  int                      `yaml:"priority"`
				Actions   []string                 `yaml:"actions"`
				Resources []string                 `yaml:"resources"`
				When      []map[string]interface{} `yaml:"when"`
				Unless    []map[string]interface{} `yaml:"unless"`
			} `yaml:"rules"`
		} `yaml:"spec"`
		Rules []struct {
			Name      string                   `yaml:"name"`
			Effect    string                   `yaml:"effect"`
			Priority  int                      `yaml:"priority"`
			Actions   []string                 `yaml:"actions"`
			Resources []string                 `yaml:"resources"`
			When      []map[string]interface{} `yaml:"when"`
			Unless    []map[string]interface{} `yaml:"unless"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(specYAML), &doc); err != nil {
		return nil
	}
	src := doc.Spec.Rules
	if len(src) == 0 {
		src = doc.Rules
	}
	if len(src) == 0 {
		return nil
	}
	out := make([]iamsdk.Rule, 0, len(src))
	for _, r := range src {
		effect := iamsdk.EffectAllow
		if r.Effect == "deny" {
			effect = iamsdk.EffectDeny
		}
		actions := make([]iamsdk.ActionMatcher, 0, len(r.Actions))
		for _, a := range r.Actions {
			actions = append(actions, iamsdk.ActionMatcher{Pattern: a})
		}
		resources := make([]iamsdk.ResourceMatcher, 0, len(r.Resources))
		for _, res := range r.Resources {
			resources = append(resources, iamsdk.ResourceMatcher{Pattern: res})
		}
		out = append(out, iamsdk.Rule{
			Name:      r.Name,
			Effect:    effect,
			Priority:  r.Priority,
			Actions:   actions,
			Resources: resources,
		})
	}
	return out
}

// QuicBaaSIAMAdapter wraps a quicbaassdk.IAMClient to satisfy the
// IAMClient interface consumed by the REST handlers. The QuicBaaS SDK
// exposes IAM operations through nested per-resource clients
// (.User(), .Role(), …); this adapter flattens those into the wide
// interface the REST handlers expect.
//
// Tenant, Policy and Application requests are translated between the
// REST layer's local DTOs and the QuicBaaS SDK message types. User,
// Group and Role types are re-exported by the iamsdk package the REST
// router already imports, so those calls pass through as plain
// delegation.
type QuicBaaSIAMAdapter struct {
	client iamsdk.Client
}

// NewQuicBaaSIAMAdapter wraps the supplied SDK client. Callers should
// pass quicbaassdk.IAMClient (which is a type alias for iamsdk.Client).
func NewQuicBaaSIAMAdapter(client quicbaassdk.IAMClient) *QuicBaaSIAMAdapter {
	return &QuicBaaSIAMAdapter{client: client}
}

// -----------------------------------------------------------------------------
// User operations — direct delegation, types are shared between REST and SDK.
// -----------------------------------------------------------------------------

// CreateUser delegates to iamsdk.UserClient.Create, first resolving the
// request's role references, which may name roles, to the role IDs the SDK
// takes (ResolveRoleIDs). The caller's request is not modified.
func (a *QuicBaaSIAMAdapter) CreateUser(ctx context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
	if req == nil {
		return nil, ErrInvalidRequestBody{Reason: "create user request is required"}
	}
	roleIDs, err := ResolveRoleIDs(ctx, a.client.Role(), tenantID, req.Roles)
	if err != nil {
		return nil, err
	}
	resolved := *req
	resolved.Roles = roleIDs
	return a.client.User().Create(ctx, tenantID, &resolved)
}

// GetUser delegates to iamsdk.UserClient.Get.
func (a *QuicBaaSIAMAdapter) GetUser(ctx context.Context, tenantID, userID string) (*iamsdk.User, error) {
	return a.client.User().Get(ctx, tenantID, userID)
}

// emailLookupPageSize is the page size GetUserByEmail lists users with when
// it falls back to reading the tenant's users.
const emailLookupPageSize = 100

// GetUserByEmail delegates to iamsdk.UserClient.GetByEmail. The embedded
// transport of go-quicbaas v0.12.0-alpha routes no IAM.User/GetByEmail, so
// login's workspace-role lookup (WorkspaceRoleResolver) would fail there;
// only on that unknown-method error does GetUserByEmail read the tenant's
// users instead, page by page, and return the first user whose canonical email
// (canonicalEmail: trimmed and lower-cased) equals the canonical form of email,
// as the upstream lookup matches. It answers an SDK not-found error only when the listing is
// provably complete: the last page holds fewer than emailLookupPageSize users.
// A full page with no next-page token may hide later users (the v0.12.0-alpha
// embedded user list ignores PageToken), so that miss fails closed with an SDK
// unavailable error naming the truncated listing. Every other GetByEmail
// error, and any List error, is returned.
func (a *QuicBaaSIAMAdapter) GetUserByEmail(ctx context.Context, tenantID, email string) (*iamsdk.User, error) {
	users := a.client.User()
	user, err := users.GetByEmail(ctx, tenantID, email)
	if err == nil || !isUnknownMethod(err) {
		return user, err
	}
	want := canonicalEmail(email)
	tok := ""
	for {
		resp, err := users.List(ctx, tenantID, &iamsdk.ListUsersRequest{PageSize: emailLookupPageSize, PageToken: tok})
		if err != nil {
			return nil, err
		}
		if resp == nil {
			break
		}
		for i := range resp.Users {
			if canonicalEmail(resp.Users[i].Email) == want {
				found := resp.Users[i]
				return &found, nil
			}
		}
		tok = resp.Pagination.NextPageToken
		if tok == "" {
			if len(resp.Users) >= emailLookupPageSize {
				return nil, sdkerrors.NewUnavailable("iam.GetUserByEmail",
					"the user listing of tenant "+tenantID+" was truncated at a full page with no next-page token; cannot tell whether a user has the email "+email)
			}
			break
		}
	}
	return nil, sdkerrors.NewNotFound("iam.GetUserByEmail", "no user in tenant "+tenantID+" has the email "+email)
}

// canonicalEmail returns the form in which go-quicbaas compares emails: the
// pinned IdentityStore.GetUserByEmail trims and lower-cases the lookup key, and
// QRDBUserStorage stores and looks up NormalizeEmail's output, the same
// transformation. The GetUserByEmail list fallback compares both sides in this
// form so it finds the same account the upstream lookup would.
func canonicalEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// isUnknownMethod reports whether err says the transport does not route the
// method called.
func isUnknownMethod(err error) bool {
	var unknown *embedded.UnknownMethodError
	return errors.As(err, &unknown) || sdkerrors.IsUnimplemented(err)
}

// ListUsers delegates to iamsdk.UserClient.List.
func (a *QuicBaaSIAMAdapter) ListUsers(ctx context.Context, tenantID string, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
	return a.client.User().List(ctx, tenantID, req)
}

// UpdateUser delegates to iamsdk.UserClient.Update.
func (a *QuicBaaSIAMAdapter) UpdateUser(ctx context.Context, tenantID, userID string, req *iamsdk.UpdateUserRequest) (*iamsdk.User, error) {
	return a.client.User().Update(ctx, tenantID, userID, req)
}

// DeleteUser delegates to iamsdk.UserClient.Delete.
func (a *QuicBaaSIAMAdapter) DeleteUser(ctx context.Context, tenantID, userID string) error {
	return a.client.User().Delete(ctx, tenantID, userID)
}

// SetUserRoles replaces the user's roles with the referenced ones
// (SetUserRoles); no references leaves them alone.
func (a *QuicBaaSIAMAdapter) SetUserRoles(ctx context.Context, tenantID, userID string, roles []string) error {
	return SetUserRoles(ctx, a.client, tenantID, userID, roles)
}

// AssignRole delegates to iamsdk.UserClient.AssignRole, first resolving the
// role reference, which may name the role, to its ID (ResolveRoleID).
func (a *QuicBaaSIAMAdapter) AssignRole(ctx context.Context, tenantID, userID, roleRef string) error {
	roleID, err := ResolveRoleID(ctx, a.client.Role(), tenantID, roleRef)
	if err != nil {
		return err
	}
	return a.client.User().AssignRole(ctx, tenantID, userID, roleID)
}

// RevokeRole delegates to iamsdk.UserClient.RevokeRole, first resolving the
// role reference, which may name the role, to its ID (ResolveRoleID).
func (a *QuicBaaSIAMAdapter) RevokeRole(ctx context.Context, tenantID, userID, roleRef string) error {
	roleID, err := ResolveRoleID(ctx, a.client.Role(), tenantID, roleRef)
	if err != nil {
		return err
	}
	return a.client.User().RevokeRole(ctx, tenantID, userID, roleID)
}

// -----------------------------------------------------------------------------
// Group operations.
// -----------------------------------------------------------------------------

// CreateGroup returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) CreateGroup(context.Context, string, *SDKCreateGroupRequest) (*SDKGroup, error) {
	return nil, ErrGroupsNotSupported{Op: "CreateGroup"}
}

// GetGroup returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) GetGroup(context.Context, string, string) (*SDKGroup, error) {
	return nil, ErrGroupsNotSupported{Op: "GetGroup"}
}

// ListGroups returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) ListGroups(context.Context, string, *SDKListGroupsRequest) (*SDKListGroupsResponse, error) {
	return nil, ErrGroupsNotSupported{Op: "ListGroups"}
}

// UpdateGroup returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) UpdateGroup(context.Context, string, string, *SDKUpdateGroupRequest) (*SDKGroup, error) {
	return nil, ErrGroupsNotSupported{Op: "UpdateGroup"}
}

// DeleteGroup returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) DeleteGroup(context.Context, string, string) error {
	return ErrGroupsNotSupported{Op: "DeleteGroup"}
}

// AddGroupMember returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) AddGroupMember(context.Context, string, string, string) error {
	return ErrGroupsNotSupported{Op: "AddGroupMember"}
}

// RemoveGroupMember returns ErrGroupsNotSupported: the QuicBaaS IAM client has no group API.
func (a *QuicBaaSIAMAdapter) RemoveGroupMember(context.Context, string, string, string) error {
	return ErrGroupsNotSupported{Op: "RemoveGroupMember"}
}

// -----------------------------------------------------------------------------
// Role operations.
// -----------------------------------------------------------------------------

func (a *QuicBaaSIAMAdapter) CreateRole(ctx context.Context, tenantID string, req *iamsdk.CreateRoleRequest) (*iamsdk.Role, error) {
	return a.client.Role().Create(ctx, tenantID, req)
}

func (a *QuicBaaSIAMAdapter) GetRole(ctx context.Context, tenantID, roleID string) (*iamsdk.Role, error) {
	return a.client.Role().Get(ctx, tenantID, roleID)
}

func (a *QuicBaaSIAMAdapter) ListRoles(ctx context.Context, tenantID string, req *iamsdk.ListRolesRequest) (*iamsdk.ListRolesResponse, error) {
	return a.client.Role().List(ctx, tenantID, req)
}

func (a *QuicBaaSIAMAdapter) UpdateRole(ctx context.Context, tenantID, roleID string, req *iamsdk.UpdateRoleRequest) (*iamsdk.Role, error) {
	return a.client.Role().Update(ctx, tenantID, roleID, req)
}

func (a *QuicBaaSIAMAdapter) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	return a.client.Role().Delete(ctx, tenantID, roleID)
}

// -----------------------------------------------------------------------------
// Tenant operations — translate between local REST DTOs and SDK types.
// -----------------------------------------------------------------------------

func (a *QuicBaaSIAMAdapter) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*TenantResponse, error) {
	if req == nil {
		return nil, errors.New("create tenant request is required")
	}
	sdkReq := &iamsdk.CreateTenantRequest{
		ID:   req.ID,
		Name: req.Name,
	}
	if req.Settings != nil {
		sdkReq.Settings = encodeTenantSettings(req.Settings)
	}
	t, err := a.client.Tenant().Create(ctx, sdkReq)
	if err != nil {
		return nil, err
	}
	return decodeTenant(t), nil
}

func (a *QuicBaaSIAMAdapter) GetTenant(ctx context.Context, tenantID string) (*TenantResponse, error) {
	t, err := a.client.Tenant().Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return decodeTenant(t), nil
}

func (a *QuicBaaSIAMAdapter) ListTenants(ctx context.Context, limit, offset int32) (*ListTenantsResponse, error) {
	sdkReq := &iamsdk.ListTenantsRequest{}
	if limit > 0 {
		sdkReq.PageSize = int(limit)
	}
	resp, err := a.client.Tenant().List(ctx, sdkReq)
	if err != nil {
		return nil, err
	}
	out := &ListTenantsResponse{
		Tenants: make([]TenantResponse, 0, len(resp.Tenants)),
	}
	for i := range resp.Tenants {
		out.Tenants = append(out.Tenants, *decodeTenant(&resp.Tenants[i]))
	}
	return out, nil
}

func (a *QuicBaaSIAMAdapter) UpdateTenant(ctx context.Context, tenantID string, req *UpdateTenantRequest) (*TenantResponse, error) {
	if req == nil {
		return nil, errors.New("update tenant request is required")
	}
	sdkReq := &iamsdk.UpdateTenantRequest{}
	if req.Settings != nil {
		sdkReq.Settings = encodeTenantSettings(req.Settings)
	}
	t, err := a.client.Tenant().Update(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, err
	}
	return decodeTenant(t), nil
}

func (a *QuicBaaSIAMAdapter) DeleteTenant(ctx context.Context, tenantID string) error {
	return a.client.Tenant().Delete(ctx, tenantID)
}

// -----------------------------------------------------------------------------
// Policy operations — translate between local REST DTOs and SDK types.
// -----------------------------------------------------------------------------

func (a *QuicBaaSIAMAdapter) CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest) (*PolicyResponse, error) {
	if req == nil {
		return nil, errors.New("create policy request is required")
	}
	sdkReq := &iamsdk.CreatePolicyRequest{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     true,
		Priority:    int(req.Priority),
		SpecYAML:    []byte(req.SpecYAML),
		Labels:      req.Labels,
	}
	// The IAM SDK validates `req.Rules` length at create time even when
	// SpecYAML carries the canonical document. The REST contract only
	// surfaces SpecYAML; parse the YAML's `spec.rules` into the SDK's
	// flat Rules slice so validation passes. Falls back to a minimal
	// placeholder rule when the YAML cannot be parsed so callers
	// supplying just a name + description still succeed.
	if rules := parsePolicyRulesFromYAML(req.SpecYAML); len(rules) > 0 {
		sdkReq.Rules = rules
	} else {
		sdkReq.Rules = []iamsdk.Rule{{
			Name:    "default",
			Effect:  iamsdk.EffectDeny,
			Actions: []iamsdk.ActionMatcher{{Pattern: "*"}},
		}}
	}
	p, err := a.client.Policy().Create(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, err
	}
	return decodePolicy(tenantID, p), nil
}

func (a *QuicBaaSIAMAdapter) GetPolicy(ctx context.Context, tenantID, policyName string) (*PolicyResponse, error) {
	p, err := a.client.Policy().Get(ctx, tenantID, policyName)
	if err != nil {
		return nil, err
	}
	return decodePolicy(tenantID, p), nil
}

func (a *QuicBaaSIAMAdapter) ListPolicies(ctx context.Context, tenantID string, limit, offset int32) (*ListPoliciesResponse, error) {
	sdkReq := &iamsdk.ListPoliciesRequest{}
	if limit > 0 {
		sdkReq.Limit = int(limit)
	}
	resp, err := a.client.Policy().List(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, err
	}
	out := &ListPoliciesResponse{
		Policies: make([]PolicyResponse, 0, len(resp.Policies)),
	}
	for i := range resp.Policies {
		out.Policies = append(out.Policies, *decodePolicy(tenantID, &resp.Policies[i]))
	}
	return out, nil
}

func (a *QuicBaaSIAMAdapter) UpdatePolicy(ctx context.Context, tenantID, policyName string, req *UpdatePolicyRequest) (*PolicyResponse, error) {
	if req == nil {
		return nil, errors.New("update policy request is required")
	}
	// SDK does not accept raw SpecYAML on update — to reapply YAML we must
	// delete and re-create the policy. Surface the limitation as an error so
	// callers fall through to the create+delete path or use the partial
	// pointer-field updates the SDK does support.
	if req.SpecYAML != "" {
		return nil, errors.New("update via spec_yaml not supported by IAM SDK; delete and re-create instead")
	}
	desc := req.Description
	prio := int(req.Priority)
	sdkReq := &iamsdk.UpdatePolicyRequest{
		Description: &desc,
		Priority:    &prio,
		Labels:      req.Labels,
	}
	p, err := a.client.Policy().Update(ctx, tenantID, policyName, sdkReq)
	if err != nil {
		return nil, err
	}
	return decodePolicy(tenantID, p), nil
}

func (a *QuicBaaSIAMAdapter) DeletePolicy(ctx context.Context, tenantID, policyName string) error {
	return a.client.Policy().Delete(ctx, tenantID, policyName)
}

func (a *QuicBaaSIAMAdapter) ValidatePolicy(ctx context.Context, tenantID, specYAML string) (*ValidatePolicyResponse, error) {
	policy := &iamsdk.Policy{
		TenantID: tenantID,
		SpecYAML: []byte(specYAML),
	}
	resp, err := a.client.Policy().Validate(ctx, tenantID, policy)
	if err != nil {
		return nil, err
	}
	out := &ValidatePolicyResponse{Valid: resp.Valid}
	for _, e := range resp.Errors {
		out.Errors = append(out.Errors, e.Message)
	}
	return out, nil
}

func (a *QuicBaaSIAMAdapter) TestPolicy(ctx context.Context, tenantID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
	if req == nil {
		return nil, errors.New("test policy request is required")
	}
	// The QuicBaaS SDK runs test cases against a named policy. The REST
	// shape only describes a single inline check; wrap it as a one-element
	// test case so the underlying engine evaluates the same scenario.
	contextMap := make(map[string]interface{}, len(req.Context))
	for k, v := range req.Context {
		contextMap[k] = v
	}
	subject := iamsdk.Subject{
		ID:       req.SubjectID,
		TenantID: tenantID,
		Roles:    req.Roles,
		Groups:   req.Groups,
	}
	sdkReq := &iamsdk.TestPolicyRequest{
		TestCases: []iamsdk.TestCase{{
			Name:     "rest-inline",
			Subject:  subject,
			Action:   req.Action,
			Resource: req.Resource,
			Context:  contextMap,
		}},
	}
	resp, err := a.client.Policy().Test(ctx, tenantID, sdkReq)
	if err != nil {
		return nil, err
	}
	return testPolicyResponseFromSDK(resp), nil
}

// testPolicyResponseFromSDK maps the inline case's result to the REST shape.
// Allowed is the actual authorization decision: the SDK's Passed only says
// whether the case met its expected result, so a passing deny case is denied.
func testPolicyResponseFromSDK(resp *iamsdk.TestPolicyResponse) *TestPolicyResponse {
	out := &TestPolicyResponse{}
	if len(resp.Results) > 0 {
		first := resp.Results[0]
		out.MatchedRule = first.MatchedRule
		out.Allowed = first.ActualResult == iamsdk.EffectAllow
	}
	return out
}

// -----------------------------------------------------------------------------
// Application operations.
// -----------------------------------------------------------------------------

func (a *QuicBaaSIAMAdapter) RegisterApp(ctx context.Context, tenantID string, req *iamsdk.RegisterAppRequest) (*iamsdk.Application, error) {
	return a.client.App().Register(ctx, tenantID, req)
}

func (a *QuicBaaSIAMAdapter) GetApp(ctx context.Context, tenantID, clientID string) (*iamsdk.Application, error) {
	return a.client.App().Get(ctx, tenantID, clientID)
}

func (a *QuicBaaSIAMAdapter) ListApps(ctx context.Context, tenantID string, limit, offset int32) (*ListAppsResponse, error) {
	resp, err := a.client.App().List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := &ListAppsResponse{
		Apps: make([]AppResponse, 0, len(resp.Applications)),
	}
	for i := range resp.Applications {
		out.Apps = append(out.Apps, *decodeApp(tenantID, &resp.Applications[i]))
	}
	return out, nil
}

func (a *QuicBaaSIAMAdapter) UpdateApp(ctx context.Context, tenantID, clientID string, req *iamsdk.UpdateAppRequest) (*iamsdk.Application, error) {
	return a.client.App().Update(ctx, tenantID, clientID, req)
}

func (a *QuicBaaSIAMAdapter) DeleteApp(ctx context.Context, tenantID, clientID string) error {
	return a.client.App().Delete(ctx, tenantID, clientID)
}

func (a *QuicBaaSIAMAdapter) RotateAppSecret(ctx context.Context, tenantID, clientID string) (*RotateSecretResponse, error) {
	resp, err := a.client.App().RotateSecret(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	return &RotateSecretResponse{
		ClientID:     resp.ClientID,
		ClientSecret: resp.ClientSecret,
	}, nil
}

// -----------------------------------------------------------------------------
// Translation helpers.
// -----------------------------------------------------------------------------

func encodeTenantSettings(s *TenantSettings) map[string]string {
	if s == nil {
		return nil
	}
	out := map[string]string{}
	if s.MaxUsers > 0 {
		out["max_users"] = intToString(int64(s.MaxUsers))
	}
	if s.MFARequired {
		out["mfa_required"] = "true"
	}
	return out
}

func decodeTenantSettings(m map[string]string) *TenantSettings {
	if len(m) == 0 {
		return nil
	}
	out := &TenantSettings{}
	if v, ok := m["max_users"]; ok {
		out.MaxUsers = int32(parseInt(v))
	}
	if v, ok := m["mfa_required"]; ok && v == "true" {
		out.MFARequired = true
	}
	return out
}

func decodeTenant(t *iamsdk.Tenant) *TenantResponse {
	if t == nil {
		return nil
	}
	resp := &TenantResponse{
		ID:       t.ID,
		Name:     t.Name,
		Settings: decodeTenantSettings(t.Settings),
	}
	if !t.CreatedAt.IsZero() {
		ts := t.CreatedAt
		resp.CreatedAt = &ts
	}
	if !t.UpdatedAt.IsZero() {
		ts := t.UpdatedAt
		resp.UpdatedAt = &ts
	}
	return resp
}

func decodePolicy(tenantID string, p *iamsdk.Policy) *PolicyResponse {
	if p == nil {
		return nil
	}
	resp := &PolicyResponse{
		Name:        p.Name,
		TenantID:    tenantID,
		Description: p.Description,
		Priority:    int32(p.Priority),
		SpecYAML:    string(p.SpecYAML),
	}
	if !p.CreatedAt.IsZero() {
		ts := p.CreatedAt
		resp.CreatedAt = &ts
	}
	if !p.UpdatedAt.IsZero() {
		ts := p.UpdatedAt
		resp.UpdatedAt = &ts
	}
	return resp
}

func decodeApp(tenantID string, app *iamsdk.Application) *AppResponse {
	if app == nil {
		return nil
	}
	grants := make([]string, 0, len(app.GrantTypes))
	for _, g := range app.GrantTypes {
		grants = append(grants, g.String())
	}
	resp := &AppResponse{
		ClientID:      app.ClientID,
		TenantID:      tenantID,
		Name:          app.Name,
		RedirectURIs:  app.RedirectURIs,
		GrantTypes:    grants,
		ResponseTypes: app.ResponseTypes,
	}
	if !app.CreatedAt.IsZero() {
		ts := app.CreatedAt
		resp.CreatedAt = &ts
	}
	if !app.UpdatedAt.IsZero() {
		ts := app.UpdatedAt
		resp.UpdatedAt = &ts
	}
	return resp
}

// -----------------------------------------------------------------------------
// PEP adapter.
// -----------------------------------------------------------------------------

// QuicBaaSPEPAdapter wraps quicbaassdk.IAMPEPClient as restiam.PEPClient.
type QuicBaaSPEPAdapter struct {
	pep iamsdk.PEPClient
}

// NewQuicBaaSPEPAdapter wraps the supplied PEP client.
func NewQuicBaaSPEPAdapter(pep quicbaassdk.IAMPEPClient) *QuicBaaSPEPAdapter {
	return &QuicBaaSPEPAdapter{pep: pep}
}

// Check delegates to iamsdk.PEPClient.Check.
func (a *QuicBaaSPEPAdapter) Check(ctx context.Context, req *iamsdk.CheckRequest) (*iamsdk.CheckResponse, error) {
	return a.pep.Check(ctx, req)
}

// -----------------------------------------------------------------------------
// Compile-time interface assertions.
// -----------------------------------------------------------------------------

var (
	_ IAMClient = (*QuicBaaSIAMAdapter)(nil)
	_ PEPClient = (*QuicBaaSPEPAdapter)(nil)
)
