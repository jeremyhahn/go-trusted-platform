//go:build integration

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

package sdn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTRequestFailed indicates a REST request failure.
type ErrRESTRequestFailed struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("REST request failed: %s %s returned status %d: %s",
		e.Method, e.URL, e.StatusCode, e.Body)
}

// ErrRESTConnectionFailed indicates a connection failure.
type ErrRESTConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("REST connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrRESTEncodeFailed indicates a request message that did not encode as JSON.
type ErrRESTEncodeFailed struct {
	Err error
}

func (e ErrRESTEncodeFailed) Error() string {
	return fmt.Sprintf("REST encode failed: %v", e.Err)
}

func (e ErrRESTEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrRESTDecodeFailed indicates a JSON decoding failure.
type ErrRESTDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrRESTDecodeFailed) Error() string {
	return fmt.Sprintf("REST decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrRESTDecodeFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// REST Adapter
// =============================================================================

// RESTAdapter implements SDNCommands using REST API calls. It speaks the
// proto/SDK wire shape the SDN routes serve (docs/sdn/api-reference-rest.md):
// platformv1 request and reply messages in their protojson form.
type RESTAdapter struct {
	baseURL   string
	client    *http.Client
	authToken string
}

// NewRESTAdapter creates a new REST adapter with default settings.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv("PLATFORM_API_ENDPOINT")
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformAPI
	}

	return &RESTAdapter{
		baseURL: endpoint,
		client:  helpers.NewAdminHTTPClient(60 * time.Second),
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup verifies connectivity to the REST API.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	_, err := r.doRequest(ctx, http.MethodGet, "/health", nil)
	return err
}

// Teardown performs any cleanup (none needed for REST).
func (r *RESTAdapter) Teardown() error {
	return nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// restProtoJSON writes request bodies as the SDK's REST transport sends them
// (sdk/go/transport/rest/sdn.go): the proto JSON mapping, with lowerCamelCase
// field names and enums as their names.
var restProtoJSON = protojson.MarshalOptions{}

// call sends req to the route method and path as its protojson body and reads
// the reply message into resp. The path carries the request fields the route
// table puts in the path or query, so req holds only the rest; a request with
// nothing left goes without a body. Every SDN route answers 200, creates
// included (pkg/api/rest/protorest.go); any other status is an error.
func (r *RESTAdapter) call(ctx context.Context, method, path string, req, resp proto.Message) error {
	var reqBody io.Reader
	if req != nil && proto.Size(req) > 0 {
		data, err := restProtoJSON.Marshal(req)
		if err != nil {
			return ErrRESTEncodeFailed{Err: err}
		}
		reqBody = bytes.NewReader(data)
	}

	respBody, err := r.doRequest(ctx, method, path, reqBody)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(respBody, resp); err != nil {
		return ErrRESTDecodeFailed{Operation: method + " " + path, Err: err}
	}
	return nil
}

// doRequest performs an HTTP request and returns the body of its 200 reply.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, reqBody io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}

	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if r.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.authToken)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ErrRESTRequestFailed{
			Method:     method,
			URL:        r.baseURL + path,
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// bridgePath is the route of one bridge, followed by suffix.
func bridgePath(bridgeID, suffix string) string {
	return "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + suffix
}

// portPath is the route of one port on a bridge, followed by suffix.
func portPath(bridgeID, portID, suffix string) string {
	return bridgePath(bridgeID, "/ports/"+url.PathEscape(portID)+suffix)
}

// listPage reads a list reply's pagination; a reply without one carries all
// count items.
func listPage(p *platformv1.PaginationResponse, count int) (totalCount int32, hasMore bool, nextCursor string) {
	if p == nil {
		return int32(count), false, ""
	}
	return int32(p.GetTotalItems()), p.GetPage() < p.GetTotalPages(), strconv.FormatUint(uint64(p.GetPage())+1, 10)
}

// pageRequest asks for limit items, or the server's default when limit is 0.
func pageRequest(limit int32) *platformv1.PaginationRequest {
	if limit <= 0 {
		return nil
	}
	return &platformv1.PaginationRequest{PageSize: uint32(limit)}
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge with POST /api/v1/sdn/bridges.
func (r *RESTAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
	bridgeType, ok := bridgeTypeFromString[strings.ToLower(opts.Type)]
	if !ok {
		bridgeType = platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED
	}

	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name:       opts.Name,
			Type:       bridgeType,
			DatapathId: opts.DatapathID,
			StpEnabled: opts.STP,
			Mtu:        uint32(opts.MTU),
			Labels:     opts.Tags,
		},
	}

	var resp platformv1.CreateBridgeResponse
	if err := r.call(ctx, http.MethodPost, "/api/v1/sdn/bridges", req, &resp); err != nil {
		return nil, err
	}

	bridge := resp.GetBridge()
	if bridge == nil {
		return &BridgeCreateResult{
			BridgeID: opts.BridgeID,
			Name:     opts.Name,
			Type:     opts.Type,
		}, nil
	}
	return bridgeToCreateResult(bridge), nil
}

// BridgeGet retrieves a bridge with GET /api/v1/sdn/bridges/{id}.
func (r *RESTAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	var resp platformv1.GetBridgeResponse
	if err := r.call(ctx, http.MethodGet, bridgePath(bridgeID, ""), nil, &resp); err != nil {
		return nil, err
	}

	bridge := resp.GetBridge()
	if bridge == nil {
		return &BridgeGetResult{BridgeID: bridgeID}, nil
	}
	return bridgeToGetResult(bridge), nil
}

// BridgeDelete deletes a bridge with DELETE /api/v1/sdn/bridges/{id}?force=.
func (r *RESTAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	path := bridgePath(bridgeID, "")
	if opts.Force {
		path += "?force=true"
	}

	var resp platformv1.DeleteBridgeResponse
	if err := r.call(ctx, http.MethodDelete, path, nil, &resp); err != nil {
		return nil, err
	}

	return &BridgeDeleteResult{
		BridgeID: bridgeID,
		Deleted:  resp.GetStatus().GetSuccess(),
	}, nil
}

// BridgeList lists bridges with GET /api/v1/sdn/bridges.
func (r *RESTAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	req := &platformv1.ListBridgesRequest{Pagination: pageRequest(opts.Limit)}

	var resp platformv1.ListBridgesResponse
	if err := r.call(ctx, http.MethodGet, "/api/v1/sdn/bridges", req, &resp); err != nil {
		return nil, err
	}

	bridges := make([]BridgeSummary, 0, len(resp.GetBridges()))
	for _, b := range resp.GetBridges() {
		bridges = append(bridges, bridgeToSummary(b))
	}

	totalCount, hasMore, nextCursor := listPage(resp.GetPagination(), len(bridges))
	return &BridgeListResult{
		Bridges:    bridges,
		TotalCount: totalCount,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

// =============================================================================
// Port Commands
// =============================================================================

// PortAdd adds a port with POST /api/v1/sdn/bridges/{bridge_id}/ports.
func (r *RESTAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
	portType, ok := portTypeFromString[strings.ToLower(opts.Type)]
	if !ok {
		portType = platformv1.PortType_PORT_TYPE_UNSPECIFIED
	}

	trunks := make([]uint32, len(opts.Trunks))
	for i, t := range opts.Trunks {
		trunks[i] = uint32(t)
	}

	req := &platformv1.AddPortRequest{
		Config: &platformv1.PortConfig{
			Name:       opts.Name,
			Type:       portType,
			Vlan:       uint32(opts.Tag),
			TrunkVlans: trunks,
			MacAddress: opts.MAC,
			Mtu:        uint32(opts.MTU),
			Options:    opts.Options,
		},
	}

	var resp platformv1.AddPortResponse
	if err := r.call(ctx, http.MethodPost, bridgePath(opts.BridgeID, "/ports"), req, &resp); err != nil {
		return nil, err
	}

	port := resp.GetPort()
	if port == nil {
		return &PortAddResult{
			BridgeID: opts.BridgeID,
			PortID:   opts.PortID,
			Name:     opts.Name,
			Type:     opts.Type,
		}, nil
	}
	return portToAddResult(port), nil
}

// PortDelete deletes a port with DELETE /api/v1/sdn/bridges/{bridge_id}/ports/{port_id}.
func (r *RESTAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	var resp platformv1.DeletePortResponse
	if err := r.call(ctx, http.MethodDelete, portPath(bridgeID, portID, ""), nil, &resp); err != nil {
		return nil, err
	}

	return &PortDeleteResult{
		BridgeID: bridgeID,
		PortID:   portID,
		Deleted:  resp.GetStatus().GetSuccess(),
	}, nil
}

// PortGetState gets a port's state with GET .../ports/{port_id}/state.
func (r *RESTAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	var resp platformv1.GetPortResponse
	if err := r.call(ctx, http.MethodGet, portPath(bridgeID, portID, "/state"), nil, &resp); err != nil {
		return nil, err
	}

	port := resp.GetPort()
	if port == nil {
		return &PortStateResult{BridgeID: bridgeID, PortID: portID}, nil
	}
	return portToStateResult(port), nil
}

// PortSetState sets a port's state with PUT .../ports/{port_id}/state.
func (r *RESTAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	req := &platformv1.SetPortStateRequest{
		AdminState:   opts.AdminState,
		IngressRate:  opts.IngressRate,
		EgressRate:   opts.EgressRate,
		IngressBurst: opts.IngressBurst,
		EgressBurst:  opts.EgressBurst,
	}

	var resp platformv1.SetPortStateResponse
	if err := r.call(ctx, http.MethodPut, portPath(bridgeID, portID, "/state"), req, &resp); err != nil {
		return nil, err
	}

	port := resp.GetPort()
	if port == nil {
		return &PortStateResult{BridgeID: bridgeID, PortID: portID}, nil
	}
	return portToStateResult(port), nil
}

// PortGetStats gets a port's counters with GET .../ports/{port_id}/stats.
func (r *RESTAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	var resp platformv1.GetPortStatsResponse
	if err := r.call(ctx, http.MethodGet, portPath(bridgeID, portID, "/stats"), nil, &resp); err != nil {
		return nil, err
	}

	stats := resp.GetStats()
	return &PortStatsResult{
		BridgeID:    bridgeID,
		PortID:      portID,
		RxPackets:   stats.GetPacketsReceived(),
		TxPackets:   stats.GetPacketsSent(),
		RxBytes:     stats.GetBytesReceived(),
		TxBytes:     stats.GetBytesSent(),
		RxErrors:    stats.GetErrors(),
		RxDropped:   stats.GetDropped(),
		RetrievedAt: time.Now(),
	}, nil
}

// =============================================================================
// Flow Commands
// =============================================================================

// FlowAdd adds a flow with POST /api/v1/sdn/flows; the config names the bridge.
func (r *RESTAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	actions := make([]*platformv1.FlowAction, 0, len(opts.Actions))
	for _, a := range opts.Actions {
		actions = append(actions, flowActionToProto(a))
	}

	req := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId:    opts.BridgeID,
			Table:       platformv1.FlowTable(opts.Table),
			Priority:    uint32(opts.Priority),
			Match:       flowMatchToProto(opts.Match),
			Actions:     actions,
			IdleTimeout: uint32(opts.IdleTimeout),
			HardTimeout: uint32(opts.HardTimeout),
		},
	}

	var resp platformv1.AddFlowResponse
	if err := r.call(ctx, http.MethodPost, "/api/v1/sdn/flows", req, &resp); err != nil {
		return nil, err
	}

	flow := resp.GetFlow()
	if flow == nil {
		return &FlowAddResult{
			BridgeID: opts.BridgeID,
			FlowID:   opts.FlowID,
			Table:    opts.Table,
			Priority: opts.Priority,
		}, nil
	}
	return flowToAddResult(flow, opts.BridgeID), nil
}

// FlowDelete deletes a flow with DELETE /api/v1/sdn/flows, whose body names
// the bridge and the flow.
func (r *RESTAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	req := &platformv1.DeleteFlowRequest{BridgeId: bridgeID, FlowId: flowID}

	var resp platformv1.DeleteFlowResponse
	if err := r.call(ctx, http.MethodDelete, "/api/v1/sdn/flows", req, &resp); err != nil {
		return nil, err
	}

	return &FlowDeleteResult{
		BridgeID: bridgeID,
		FlowID:   flowID,
		Deleted:  resp.GetStatus().GetSuccess(),
	}, nil
}

// FlowList lists a bridge's flows with GET /api/v1/sdn/flows, whose body
// names the bridge.
func (r *RESTAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	req := &platformv1.ListFlowsRequest{
		BridgeId:   bridgeID,
		Table:      platformv1.FlowTable(opts.Table),
		Pagination: pageRequest(opts.Limit),
	}

	var resp platformv1.ListFlowsResponse
	if err := r.call(ctx, http.MethodGet, "/api/v1/sdn/flows", req, &resp); err != nil {
		return nil, err
	}

	flows := make([]FlowSummary, 0, len(resp.GetFlows()))
	for _, f := range resp.GetFlows() {
		flows = append(flows, flowToSummary(f))
	}

	totalCount, hasMore, nextCursor := listPage(resp.GetPagination(), len(flows))
	return &FlowListResult{
		BridgeID:   bridgeID,
		Flows:      flows,
		TotalCount: totalCount,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

// =============================================================================
// VLAN Commands
// =============================================================================

// VLANCreate creates a VLAN with POST /api/v1/sdn/vlans. The route, like
// gRPC, places a VLAN on one bridge.
func (r *RESTAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	var bridgeID string
	if len(opts.BridgeIDs) > 0 {
		bridgeID = opts.BridgeIDs[0]
	}

	ports := make([]string, 0, len(opts.Tagged)+len(opts.Untagged))
	ports = append(ports, opts.Tagged...)
	ports = append(ports, opts.Untagged...)

	req := &platformv1.CreateVLANRequest{
		Config: &platformv1.VLANConfig{
			VlanId:   uint32(opts.VLANID),
			Name:     opts.Name,
			BridgeId: bridgeID,
			Ports:    ports,
		},
	}

	var resp platformv1.CreateVLANResponse
	if err := r.call(ctx, http.MethodPost, "/api/v1/sdn/vlans", req, &resp); err != nil {
		return nil, err
	}

	vlan := resp.GetVlan()
	if vlan == nil {
		return &VLANCreateResult{
			VLANID:      opts.VLANID,
			Name:        opts.Name,
			Description: opts.Description,
		}, nil
	}
	return vlanToCreateResult(vlan, opts.Description), nil
}

// VLANDelete deletes a VLAN with DELETE /api/v1/sdn/vlans/{vlan_id}?bridge_id=.
func (r *RESTAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	params := url.Values{}
	params.Set("bridge_id", bridgeID)
	path := "/api/v1/sdn/vlans/" + strconv.Itoa(int(vlanID)) + "?" + params.Encode()

	var resp platformv1.DeleteVLANResponse
	if err := r.call(ctx, http.MethodDelete, path, nil, &resp); err != nil {
		return nil, err
	}

	return &VLANDeleteResult{
		VLANID:  vlanID,
		Deleted: resp.GetStatus().GetSuccess(),
	}, nil
}

// VLANList lists a bridge's VLANs with GET /api/v1/sdn/vlans?bridge_id=.
func (r *RESTAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	path := "/api/v1/sdn/vlans"
	if opts.BridgeID != "" {
		params := url.Values{}
		params.Set("bridge_id", opts.BridgeID)
		path += "?" + params.Encode()
	}

	var resp platformv1.ListVLANsResponse
	if err := r.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}

	vlans := make([]VLANSummary, 0, len(resp.GetVlans()))
	for _, v := range resp.GetVlans() {
		vlans = append(vlans, vlanToSummary(v))
	}

	return &VLANListResult{
		VLANs:      vlans,
		TotalCount: int32(len(vlans)),
	}, nil
}

// =============================================================================
// Policy Commands
// =============================================================================

// PolicyApply applies a network policy with POST /api/v1/sdn/policies.
func (r *RESTAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
	policyType, ok := policyTypeFromString[strings.ToLower(opts.Type)]
	if !ok {
		policyType = platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED
	}

	rules := make([]*platformv1.PolicyRule, 0, len(opts.Rules))
	for _, rule := range opts.Rules {
		rules = append(rules, policyRuleToProto(rule))
	}

	targets := make([]*platformv1.PolicyTarget, 0, len(opts.Targets))
	for _, t := range opts.Targets {
		targets = append(targets, policyTargetToProto(t))
	}

	var schedule *platformv1.PolicySchedule
	if opts.Schedule != nil {
		schedule = policyScheduleToProto(opts.Schedule)
	}

	req := &platformv1.ApplyPolicyRequest{
		PolicyId: opts.PolicyID,
		Config: &platformv1.PolicyConfig{
			Name:        opts.Name,
			Description: opts.Description,
			Type:        policyType,
			Priority:    opts.Priority,
			Enabled:     opts.Enabled,
			Rules:       rules,
			Targets:     targets,
			Schedule:    schedule,
		},
	}

	var resp platformv1.ApplyPolicyResponse
	if err := r.call(ctx, http.MethodPost, "/api/v1/sdn/policies", req, &resp); err != nil {
		return nil, err
	}

	policy := resp.GetPolicy()
	if policy == nil {
		return &PolicyApplyResult{
			PolicyID: opts.PolicyID,
			Name:     opts.Name,
			Type:     opts.Type,
		}, nil
	}
	return policyToApplyResult(policy), nil
}

// newPolicyBody builds the create-policy request from opts. QUIC sends it as
// is; MCP sends it as newRESTPolicyBody.
func newPolicyBody(opts PolicyApplyOptions) sdnPolicyBody {
	rules := make([]restPolicyRule, 0, len(opts.Rules))
	for _, rule := range opts.Rules {
		rules = append(rules, newRESTPolicyRule(rule))
	}
	targets := make([]restPolicyTarget, 0, len(opts.Targets))
	for _, target := range opts.Targets {
		targets = append(targets, restPolicyTarget(target))
	}

	var schedule *restPolicySchedule
	if opts.Schedule != nil {
		converted := restPolicySchedule(*opts.Schedule)
		schedule = &converted
	}

	return sdnPolicyBody{
		ID:          opts.PolicyID,
		Name:        opts.Name,
		Description: opts.Description,
		Type:        opts.Type,
		Priority:    opts.Priority,
		Enabled:     opts.Enabled,
		Rules:       rules,
		Targets:     targets,
		Schedule:    schedule,
	}
}

// newRESTPolicyBody builds the REST create-policy body, which the MCP
// sdn_apply_policy tool takes as its arguments too.
func newRESTPolicyBody(opts PolicyApplyOptions) map[string]interface{} {
	policy := newPolicyBody(opts)
	body := map[string]interface{}{
		"id":          policy.ID,
		"name":        policy.Name,
		"description": policy.Description,
		"type":        policy.Type,
		"priority":    policy.Priority,
		"enabled":     policy.Enabled,
		"rules":       policy.Rules,
		"targets":     policy.Targets,
	}
	if policy.Schedule != nil {
		body["schedule"] = policy.Schedule
	}
	return body
}

// PolicyGet retrieves a policy with GET /api/v1/sdn/policies/{policy_id}.
func (r *RESTAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	path := "/api/v1/sdn/policies/" + url.PathEscape(policyID)

	var resp platformv1.GetPolicyResponse
	if err := r.call(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}

	policy := resp.GetPolicy()
	if policy == nil {
		return &PolicyGetResult{PolicyID: policyID}, nil
	}
	return policyToGetResult(policy), nil
}

// PolicyList lists policies with GET /api/v1/sdn/policies, whose body carries
// the filters.
func (r *RESTAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	req := &platformv1.ListPoliciesRequest{
		Type:       opts.Type,
		TargetId:   opts.TargetID,
		Pagination: pageRequest(opts.Limit),
	}

	var resp platformv1.ListPoliciesResponse
	if err := r.call(ctx, http.MethodGet, "/api/v1/sdn/policies", req, &resp); err != nil {
		return nil, err
	}

	policies := make([]PolicySummary, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		policies = append(policies, policyToSummary(p))
	}

	totalCount, hasMore, nextCursor := listPage(resp.GetPagination(), len(policies))
	return &PolicyListResult{
		Policies:   policies,
		TotalCount: totalCount,
		HasMore:    hasMore,
		NextCursor: nextCursor,
	}, nil
}

// restPolicy is a policy as the REST policy routes answer it.
type restPolicy struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"`
	Priority    int32               `json:"priority"`
	Enabled     bool                `json:"enabled"`
	Status      string              `json:"status"`
	Rules       []restPolicyRule    `json:"rules"`
	Targets     []restPolicyTarget  `json:"targets"`
	Schedule    *restPolicySchedule `json:"schedule"`
	HitCount    uint64              `json:"hit_count"`
	ByteCount   uint64              `json:"byte_count"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// applyResult converts the policy returned by a create into PolicyApplyResult.
func (p restPolicy) applyResult() *PolicyApplyResult {
	return &PolicyApplyResult{
		PolicyID:    p.ID,
		Name:        p.Name,
		Type:        p.Type,
		Status:      p.Status,
		RuleCount:   int32(len(p.Rules)),
		TargetCount: int32(len(p.Targets)),
		AppliedAt:   p.CreatedAt,
	}
}

// getResult converts the policy into PolicyGetResult.
func (p restPolicy) getResult() *PolicyGetResult {
	rules := make([]PolicyRule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		rules = append(rules, rule.policyRule())
	}
	targets := make([]PolicyTarget, 0, len(p.Targets))
	for _, target := range p.Targets {
		targets = append(targets, PolicyTarget(target))
	}
	var schedule *PolicySchedule
	if p.Schedule != nil {
		converted := PolicySchedule(*p.Schedule)
		schedule = &converted
	}

	return &PolicyGetResult{
		PolicyID:    p.ID,
		Name:        p.Name,
		Description: p.Description,
		Type:        p.Type,
		Priority:    p.Priority,
		Enabled:     p.Enabled,
		Status:      p.Status,
		Rules:       rules,
		Targets:     targets,
		Schedule:    schedule,
		HitCount:    p.HitCount,
		ByteCount:   p.ByteCount,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// summary converts the policy into a PolicySummary list entry.
func (p restPolicy) summary() PolicySummary {
	return PolicySummary{
		PolicyID:    p.ID,
		Name:        p.Name,
		Type:        p.Type,
		Priority:    p.Priority,
		Enabled:     p.Enabled,
		Status:      p.Status,
		RuleCount:   int32(len(p.Rules)),
		TargetCount: int32(len(p.Targets)),
		HitCount:    p.HitCount,
		CreatedAt:   p.CreatedAt,
	}
}

// restPolicyRule is a policy rule with its match fields inlined, as REST carries it.
type restPolicyRule struct {
	RuleID          string `json:"rule_id,omitempty"`
	Priority        int32  `json:"priority,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      int32  `json:"source_port,omitempty"`
	DestinationPort int32  `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"`
	Interface       string `json:"interface,omitempty"`
	VLANID          int32  `json:"vlan_id,omitempty"`
	DSCP            int32  `json:"dscp,omitempty"`
	Application     string `json:"application,omitempty"`
	Action          string `json:"action,omitempty"`
	ActionValue     string `json:"action_value,omitempty"`
	Log             bool   `json:"log,omitempty"`
	Counter         bool   `json:"counter,omitempty"`
}

type restPolicyTarget struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Direction string `json:"direction,omitempty"`
}

type restPolicySchedule struct {
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Days      []string `json:"days,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Enabled   bool     `json:"enabled"`
}

func newRESTPolicyRule(rule PolicyRule) restPolicyRule {
	return restPolicyRule{
		RuleID:          rule.RuleID,
		Priority:        rule.Priority,
		SourceIP:        rule.Match.SourceIP,
		DestinationIP:   rule.Match.DestinationIP,
		SourcePort:      rule.Match.SourcePort,
		DestinationPort: rule.Match.DestinationPort,
		Protocol:        rule.Match.Protocol,
		Direction:       rule.Match.Direction,
		Interface:       rule.Match.Interface,
		VLANID:          rule.Match.VLANID,
		DSCP:            rule.Match.DSCP,
		Application:     rule.Match.Application,
		Action:          rule.Action,
		ActionValue:     rule.ActionValue,
		Log:             rule.Log,
		Counter:         rule.Counter,
	}
}

func (r restPolicyRule) policyRule() PolicyRule {
	return PolicyRule{
		RuleID:   r.RuleID,
		Priority: r.Priority,
		Match: PolicyMatch{
			SourceIP:        r.SourceIP,
			DestinationIP:   r.DestinationIP,
			SourcePort:      r.SourcePort,
			DestinationPort: r.DestinationPort,
			Protocol:        r.Protocol,
			Direction:       r.Direction,
			Interface:       r.Interface,
			VLANID:          r.VLANID,
			DSCP:            r.DSCP,
			Application:     r.Application,
		},
		Action:      r.Action,
		ActionValue: r.ActionValue,
		Log:         r.Log,
		Counter:     r.Counter,
	}
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure RESTAdapter implements SDNCommands interface.
var _ SDNCommands = (*RESTAdapter)(nil)
