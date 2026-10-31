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

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"gopkg.in/yaml.v3"
)

// parsePolicyRulesFromYAML extracts the rules slice from the canonical
// IAM Policy YAML document. Returns nil when the YAML cannot be parsed;
// callers should treat that as "no rules" and substitute a default.
//
// The SDK's embedded policy create keeps only each rule's name, effect,
// priority, actions and resources, so a `when` or `unless` condition would
// be dropped and a conditional rule stored as unconditional. A rule that
// carries either is refused with ErrPolicyConditionUnsupported instead.
// The create keeps no subject selector either, and an empty selector
// matches every subject, so a policy whose `subjects` names any role, group
// or user is refused with ErrInvalidPolicySpec rather than widened.
func parsePolicyRulesFromYAML(specYAML string) ([]iamsdk.Rule, error) {
	if specYAML == "" {
		return nil, nil
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
			Subjects interface{} `yaml:"subjects"`
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
		Subjects interface{} `yaml:"subjects"`
	}
	if err := yaml.Unmarshal([]byte(specYAML), &doc); err != nil {
		return nil, nil
	}
	if hasSubjectSelector(doc.Spec.Subjects) || hasSubjectSelector(doc.Subjects) {
		return nil, ErrInvalidPolicySpec{Reason: "spec.subjects restricts which subjects the policy applies to, " +
			"and the pinned IAM SDK's policy create does not carry subject selectors; " +
			"stored without them the policy would apply to every subject in the tenant"}
	}
	src := doc.Spec.Rules
	if len(src) == 0 {
		src = doc.Rules
	}
	if len(src) == 0 {
		return nil, nil
	}
	out := make([]iamsdk.Rule, 0, len(src))
	for _, r := range src {
		if len(r.When) > 0 {
			return nil, ErrPolicyConditionUnsupported{Rule: r.Name, Condition: "when"}
		}
		if len(r.Unless) > 0 {
			return nil, ErrPolicyConditionUnsupported{Rule: r.Name, Condition: "unless"}
		}
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
	return out, nil
}

// hasSubjectSelector reports whether a policy's `subjects` value names any
// subject (a role, group, user or any other selector). An absent or empty
// selector restricts nothing.
func hasSubjectSelector(subjects interface{}) bool {
	switch v := subjects.(type) {
	case nil:
		return false
	case map[string]interface{}:
		for _, selector := range v {
			if hasSubjectSelector(selector) {
				return true
			}
		}
		return false
	case []interface{}:
		return len(v) > 0
	case string:
		return v != ""
	default:
		return true
	}
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

// GetUserByEmail delegates to iamsdk.UserClient.GetByEmail.
func (a *QuicBaaSIAMAdapter) GetUserByEmail(ctx context.Context, tenantID, email string) (*iamsdk.User, error) {
	return a.client.User().GetByEmail(ctx, tenantID, email)
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

func (a *QuicBaaSIAMAdapter) CreateGroup(ctx context.Context, tenantID string, req *iamsdk.CreateGroupRequest) (*iamsdk.Group, error) {
	return a.client.Group().Create(ctx, tenantID, req)
}

func (a *QuicBaaSIAMAdapter) GetGroup(ctx context.Context, tenantID, groupID string) (*iamsdk.Group, error) {
	return a.client.Group().Get(ctx, tenantID, groupID)
}

func (a *QuicBaaSIAMAdapter) ListGroups(ctx context.Context, tenantID string, req *iamsdk.ListGroupsRequest) (*iamsdk.ListGroupsResponse, error) {
	return a.client.Group().List(ctx, tenantID, req)
}

func (a *QuicBaaSIAMAdapter) UpdateGroup(ctx context.Context, tenantID, groupID string, req *iamsdk.UpdateGroupRequest) (*iamsdk.Group, error) {
	return a.client.Group().Update(ctx, tenantID, groupID, req)
}

func (a *QuicBaaSIAMAdapter) DeleteGroup(ctx context.Context, tenantID, groupID string) error {
	return a.client.Group().Delete(ctx, tenantID, groupID)
}

func (a *QuicBaaSIAMAdapter) AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	return a.client.Group().AddMember(ctx, tenantID, groupID, userID)
}

func (a *QuicBaaSIAMAdapter) RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	return a.client.Group().RemoveMember(ctx, tenantID, groupID, userID)
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
	rules, err := parsePolicyRulesFromYAML(req.SpecYAML)
	if err != nil {
		return nil, err
	}
	if len(rules) > 0 {
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
	out := &TestPolicyResponse{}
	if resp.Passed > 0 {
		out.Allowed = true
	}
	if len(resp.Results) > 0 {
		first := resp.Results[0]
		out.MatchedRule = first.MatchedRule
		out.Allowed = first.Passed
	}
	return out, nil
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
