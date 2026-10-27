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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/proto"
)

// =============================================================================
// SDN REST Handler Errors
// =============================================================================

// ErrSDNServiceNotAvailable is returned when the SDN service is not configured
// or unavailable.
type ErrSDNServiceNotAvailable struct{}

func (e ErrSDNServiceNotAvailable) Error() string {
	return "SDN service not available"
}

// ErrInvalidPolicyField is returned when a policy request names a type,
// rule action or target type the SDN service does not define.
type ErrInvalidPolicyField struct {
	Field string
	Value string
}

func (e ErrInvalidPolicyField) Error() string {
	return fmt.Sprintf("invalid policy %s %q", e.Field, e.Value)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreatePolicyRequest is the REST form of the gRPC ApplyPolicyRequest. With an
// ID it re-applies (replaces) that policy; without one the service assigns it.
type CreatePolicyRequest struct {
	ID          string          `json:"id,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type,omitempty"` // acl, qos, nat, firewall, routing
	Priority    int32           `json:"priority,omitempty"`
	Enabled     bool            `json:"enabled"`
	Rules       []PolicyRule    `json:"rules,omitempty"`
	Targets     []PolicyTarget  `json:"targets,omitempty"`
	Schedule    *PolicySchedule `json:"schedule,omitempty"`
}

// PolicyRule is the gRPC PolicyRule with its match fields inlined.
type PolicyRule struct {
	RuleID          string `json:"rule_id,omitempty"`
	Priority        int32  `json:"priority,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      uint32 `json:"source_port,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"` // ingress, egress, both
	Interface       string `json:"interface,omitempty"`
	VLANID          uint32 `json:"vlan_id,omitempty"`
	DSCP            uint32 `json:"dscp,omitempty"`
	Application     string `json:"application,omitempty"`
	Action          string `json:"action,omitempty"` // allow, deny, rate-limit, redirect, mirror, log
	ActionValue     string `json:"action_value,omitempty"`
	Log             bool   `json:"log,omitempty"`
	Counter         bool   `json:"counter,omitempty"`
}

// PolicyTarget names what a policy applies to.
type PolicyTarget struct {
	Type      string `json:"type"` // bridge, port, vlan, interface
	ID        string `json:"id"`
	Direction string `json:"direction,omitempty"`
	Zone      string `json:"zone,omitempty"`
}

// PolicySchedule limits when a policy is in force.
type PolicySchedule struct {
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Days      []string `json:"days,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Enabled   bool     `json:"enabled"`
}

// PolicyResponse is a network policy as the SDN service holds it.
type PolicyResponse struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type,omitempty"`
	Priority    int32           `json:"priority"`
	Enabled     bool            `json:"enabled"`
	Status      string          `json:"status"`
	Rules       []PolicyRule    `json:"rules"`
	Targets     []PolicyTarget  `json:"targets"`
	Schedule    *PolicySchedule `json:"schedule,omitempty"`
	HitCount    uint64          `json:"hit_count"`
	ByteCount   uint64          `json:"byte_count"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// SDNPolicyListResponse represents a list of policies.
type SDNPolicyListResponse struct {
	Policies  []PolicyResponse `json:"policies"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// SDNActionResponse represents an SDN action result.
type SDNActionResponse struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
}

// SDNErrorResponse represents an SDN error response.
type SDNErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkZoneCreateRequest is the body of POST /api/v1/sdn/zones: an
// owner-defined zone.
type NetworkZoneCreateRequest = gateway.ZoneSpec

// NetworkZoneUpdateRequest is the body of PUT /api/v1/sdn/zones/{name}: the
// zone's new policy (the name comes from the path).
type NetworkZoneUpdateRequest = gateway.ZoneSpec

// NetworkZoneResponse represents a network zone in API responses.
type NetworkZoneResponse = gateway.ZoneView

// NetworkZoneListResponse represents a list of network zones.
type NetworkZoneListResponse struct {
	Zones     []NetworkZoneResponse `json:"zones"`
	Count     int                   `json:"count"`
	Timestamp time.Time             `json:"timestamp"`
}

// =============================================================================
// SDN Handlers
// =============================================================================

// SDNHandlers serves the daemon's /api/v1/sdn REST routes. Bridge, port,
// flow, VLAN and policy routes serve the platform.v1 SDNService in the proto
// JSON mapping (#445), the shape the SDK's REST transport speaks; the zone
// routes keep the REST zone document.
type SDNHandlers struct {
	// proto answers the SDNService routes; writeJSON and writeError answer
	// the zone routes.
	proto       protoResponder
	sdn         platformv1.SDNServiceServer
	zoneService gateway.ZoneService
	logger      *slog.Logger
}

// NewSDNHandlers creates the SDN handlers over the daemon's SDN service. A nil
// service makes every SDNService route answer 503.
func NewSDNHandlers(sdn platformv1.SDNServiceServer, logger *slog.Logger) *SDNHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &SDNHandlers{
		proto:  protoResponder{logger: logger},
		sdn:    sdn,
		logger: logger,
	}
}

// SetZoneService wires the network zone service into the zone routes.
func (h *SDNHandlers) SetZoneService(svc gateway.ZoneService) {
	h.zoneService = svc
}

// sdnRPC adapts one SDNService RPC to a protoRPC route.
func sdnRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](h *SDNHandlers, rpc func(platformv1.SDNServiceServer, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return protoRPC(h.proto, h.sdnService, rpc)
}

// sdnService returns the SDN service, or ErrSDNServiceNotAvailable when none
// is wired.
func (h *SDNHandlers) sdnService() (platformv1.SDNServiceServer, error) {
	if h.sdn == nil {
		return nil, ErrSDNServiceNotAvailable{}
	}
	return h.sdn, nil
}

// RegisterRoutes registers all SDN routes on the provided router.
func (h *SDNHandlers) RegisterRoutes(router *mux.Router) {
	// The routes are the SDK REST transport's SDNService table
	// (sdk/go/transport/rest/sdn.go). A path variable is named after the
	// request field it fills.
	router.HandleFunc("/api/v1/sdn/bridges", sdnRPC(h, platformv1.SDNServiceServer.CreateBridge)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/bridges", sdnRPC(h, platformv1.SDNServiceServer.ListBridges)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}", sdnRPC(h, platformv1.SDNServiceServer.GetBridge)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{id}", sdnRPC(h, platformv1.SDNServiceServer.DeleteBridge)).Methods(http.MethodDelete)

	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports", sdnRPC(h, platformv1.SDNServiceServer.AddPort)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports", sdnRPC(h, platformv1.SDNServiceServer.ListPorts)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}", sdnRPC(h, platformv1.SDNServiceServer.DeletePort)).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/state", sdnRPC(h, platformv1.SDNServiceServer.GetPort)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/state", sdnRPC(h, platformv1.SDNServiceServer.SetPortState)).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/stats", sdnRPC(h, platformv1.SDNServiceServer.GetPortStats)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/auth", sdnRPC(h, platformv1.SDNServiceServer.AuthenticatePort)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/auth", sdnRPC(h, platformv1.SDNServiceServer.RevokePortAuth)).Methods(http.MethodDelete)

	router.HandleFunc("/api/v1/sdn/flows", sdnRPC(h, platformv1.SDNServiceServer.AddFlow)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/flows", sdnRPC(h, platformv1.SDNServiceServer.ListFlows)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/flows", sdnRPC(h, platformv1.SDNServiceServer.DeleteFlow)).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/sdn/bridges/{bridge_id}/flows", sdnRPC(h, platformv1.SDNServiceServer.ListFlows)).Methods(http.MethodGet)

	router.HandleFunc("/api/v1/sdn/vlans", sdnRPC(h, platformv1.SDNServiceServer.CreateVLAN)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/vlans", sdnRPC(h, platformv1.SDNServiceServer.ListVLANs)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/vlans/{vlan_id}", sdnRPC(h, platformv1.SDNServiceServer.DeleteVLAN)).Methods(http.MethodDelete)

	router.HandleFunc("/api/v1/sdn/policies", sdnRPC(h, platformv1.SDNServiceServer.ApplyPolicy)).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/policies", sdnRPC(h, platformv1.SDNServiceServer.ListPolicies)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/policies/{policy_id}", sdnRPC(h, platformv1.SDNServiceServer.GetPolicy)).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/policies/{policy_id}", sdnRPC(h, platformv1.SDNServiceServer.DeletePolicy)).Methods(http.MethodDelete)

	// Network Zone operations
	router.HandleFunc("/api/v1/sdn/zones", h.handleCreateNetworkZone).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/sdn/zones", h.handleListNetworkZones).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/sdn/zones/{name}", h.handleUpdateNetworkZone).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/sdn/zones/{name}", h.handleDeleteNetworkZone).Methods(http.MethodDelete)

	h.logger.Info("SDN REST routes registered")
}

// =============================================================================
// Helper Methods
// =============================================================================

// writeJSON writes a JSON response.
func (h *SDNHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *SDNHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, SDNErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// Proto enum value-name prefixes; REST spells the rest of the name in lower
// case with dashes, e.g. POLICY_RULE_ACTION_RATE_LIMIT is "rate-limit".
const (
	policyTypePrefix       = "POLICY_TYPE_"
	policyStatusPrefix     = "POLICY_STATUS_"
	policyRuleActionPrefix = "POLICY_RULE_ACTION_"
	policyTargetTypePrefix = "POLICY_TARGET_TYPE_"
)

// protoEnumValue resolves a REST enum name to its proto value. An empty name
// is the unspecified value, as an omitted gRPC field is.
func protoEnumValue(values map[string]int32, prefix, field, name string) (int32, error) {
	if name == "" {
		return 0, nil
	}
	value, ok := values[prefix+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))]
	if !ok {
		return 0, ErrInvalidPolicyField{Field: field, Value: name}
	}
	return value, nil
}

// protoEnumName is the inverse of protoEnumValue; the unspecified value is "".
func protoEnumName(name, prefix string) string {
	name = strings.TrimPrefix(name, prefix)
	if name == "UNSPECIFIED" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// PolicyRequestToProto converts a REST policy body into the gRPC
// ApplyPolicyRequest, rejecting enum names the proto does not define.
func PolicyRequestToProto(req CreatePolicyRequest) (*platformv1.ApplyPolicyRequest, error) {
	policyType, err := protoEnumValue(platformv1.PolicyType_value, policyTypePrefix, "type", req.Type)
	if err != nil {
		return nil, err
	}

	rules := make([]*platformv1.PolicyRule, 0, len(req.Rules))
	for _, rule := range req.Rules {
		protoRule, err := policyRuleToProto(rule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, protoRule)
	}

	targets := make([]*platformv1.PolicyTarget, 0, len(req.Targets))
	for _, target := range req.Targets {
		targetType, err := protoEnumValue(platformv1.PolicyTargetType_value, policyTargetTypePrefix, "target type", target.Type)
		if err != nil {
			return nil, err
		}
		targets = append(targets, &platformv1.PolicyTarget{
			Type:      platformv1.PolicyTargetType(targetType),
			Id:        target.ID,
			Direction: target.Direction,
			Zone:      target.Zone,
		})
	}

	return &platformv1.ApplyPolicyRequest{
		PolicyId: req.ID,
		Config: &platformv1.PolicyConfig{
			Name:        req.Name,
			Description: req.Description,
			Type:        platformv1.PolicyType(policyType),
			Priority:    req.Priority,
			Enabled:     req.Enabled,
			Rules:       rules,
			Targets:     targets,
			Schedule:    policyScheduleToProto(req.Schedule),
		},
	}, nil
}

func policyRuleToProto(rule PolicyRule) (*platformv1.PolicyRule, error) {
	action, err := protoEnumValue(platformv1.PolicyRuleAction_value, policyRuleActionPrefix, "rule action", rule.Action)
	if err != nil {
		return nil, err
	}
	return &platformv1.PolicyRule{
		RuleId:   rule.RuleID,
		Priority: rule.Priority,
		Match: &platformv1.PolicyRuleMatch{
			SourceIp:        rule.SourceIP,
			DestinationIp:   rule.DestinationIP,
			SourcePort:      rule.SourcePort,
			DestinationPort: rule.DestinationPort,
			Protocol:        rule.Protocol,
			Direction:       rule.Direction,
			Interface:       rule.Interface,
			VlanId:          rule.VLANID,
			Dscp:            rule.DSCP,
			Application:     rule.Application,
		},
		Action:      platformv1.PolicyRuleAction(action),
		ActionValue: rule.ActionValue,
		Log:         rule.Log,
		Counter:     rule.Counter,
	}, nil
}

func policyScheduleToProto(schedule *PolicySchedule) *platformv1.PolicySchedule {
	if schedule == nil {
		return nil
	}
	return &platformv1.PolicySchedule{
		StartTime: schedule.StartTime,
		EndTime:   schedule.EndTime,
		Days:      schedule.Days,
		Timezone:  schedule.Timezone,
		Enabled:   schedule.Enabled,
	}
}

// PolicyToResponse converts a policy held by the SDN service into its REST form.
func PolicyToResponse(policy *platformv1.Policy) PolicyResponse {
	config := policy.GetConfig()

	rules := make([]PolicyRule, 0, len(config.GetRules()))
	for _, rule := range config.GetRules() {
		match := rule.GetMatch()
		rules = append(rules, PolicyRule{
			RuleID:          rule.GetRuleId(),
			Priority:        rule.GetPriority(),
			SourceIP:        match.GetSourceIp(),
			DestinationIP:   match.GetDestinationIp(),
			SourcePort:      match.GetSourcePort(),
			DestinationPort: match.GetDestinationPort(),
			Protocol:        match.GetProtocol(),
			Direction:       match.GetDirection(),
			Interface:       match.GetInterface(),
			VLANID:          match.GetVlanId(),
			DSCP:            match.GetDscp(),
			Application:     match.GetApplication(),
			Action:          protoEnumName(rule.GetAction().String(), policyRuleActionPrefix),
			ActionValue:     rule.GetActionValue(),
			Log:             rule.GetLog(),
			Counter:         rule.GetCounter(),
		})
	}

	targets := make([]PolicyTarget, 0, len(config.GetTargets()))
	for _, target := range config.GetTargets() {
		targets = append(targets, PolicyTarget{
			Type:      protoEnumName(target.GetType().String(), policyTargetTypePrefix),
			ID:        target.GetId(),
			Direction: target.GetDirection(),
			Zone:      target.GetZone(),
		})
	}

	resp := PolicyResponse{
		ID:          policy.GetId(),
		Name:        config.GetName(),
		Description: config.GetDescription(),
		Type:        protoEnumName(config.GetType().String(), policyTypePrefix),
		Priority:    config.GetPriority(),
		Enabled:     config.GetEnabled(),
		Status:      protoEnumName(policy.GetStatus().String(), policyStatusPrefix),
		Rules:       rules,
		Targets:     targets,
		HitCount:    policy.GetHitCount(),
		ByteCount:   policy.GetByteCount(),
	}
	if schedule := config.GetSchedule(); schedule != nil {
		resp.Schedule = &PolicySchedule{
			StartTime: schedule.GetStartTime(),
			EndTime:   schedule.GetEndTime(),
			Days:      schedule.GetDays(),
			Timezone:  schedule.GetTimezone(),
			Enabled:   schedule.GetEnabled(),
		}
	}
	if policy.GetCreatedAt() != nil {
		resp.CreatedAt = policy.GetCreatedAt().AsTime().UTC()
	}
	if policy.GetUpdatedAt() != nil {
		resp.UpdatedAt = policy.GetUpdatedAt().AsTime().UTC()
	}
	return resp
}

// =============================================================================
// Network Zone Handlers
// =============================================================================

// handleCreateNetworkZone handles POST /api/v1/sdn/zones
func (h *SDNHandlers) handleCreateNetworkZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	var req NetworkZoneCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, &WrappedError{Msg: "invalid request body", Err: err})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, &MessageError{Msg: "zone name is required"})
		return
	}

	rec, restartRequired, err := h.zoneService.Create(ctx, req.Config(""))
	if err != nil {
		switch err.(type) {
		case gateway.ErrZoneAlreadyExists:
			h.writeError(w, http.StatusConflict, err)
		case gateway.ErrZoneValidation:
			h.writeError(w, http.StatusBadRequest, err)
		default:
			h.writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	h.writeJSON(w, http.StatusCreated, rec.View(restartRequired))
}

// handleListNetworkZones handles GET /api/v1/sdn/zones
func (h *SDNHandlers) handleListNetworkZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	lifecycleRole := r.URL.Query().Get("lifecycle_role")

	recs, err := h.zoneService.List(ctx, zone.LifecycleRole(lifecycleRole))
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}

	zones := make([]NetworkZoneResponse, 0, len(recs))
	for _, rec := range recs {
		zones = append(zones, rec.View(false))
	}

	h.writeJSON(w, http.StatusOK, NetworkZoneListResponse{
		Zones:     zones,
		Count:     len(zones),
		Timestamp: time.Now(),
	})
}

// handleUpdateNetworkZone handles PUT /api/v1/sdn/zones/{name}
func (h *SDNHandlers) handleUpdateNetworkZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		h.writeError(w, http.StatusBadRequest, &MessageError{Msg: "zone name is required"})
		return
	}

	var req NetworkZoneUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, &WrappedError{Msg: "invalid request body", Err: err})
		return
	}

	rec, restartRequired, err := h.zoneService.Update(ctx, zone.Zone(name), req.Config(name))
	if err != nil {
		switch err.(type) {
		case gateway.ErrZoneNotFound:
			h.writeError(w, http.StatusNotFound, err)
		case gateway.ErrZoneValidation:
			h.writeError(w, http.StatusBadRequest, err)
		default:
			h.writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	h.writeJSON(w, http.StatusOK, rec.View(restartRequired))
}

// handleDeleteNetworkZone handles DELETE /api/v1/sdn/zones/{name}
func (h *SDNHandlers) handleDeleteNetworkZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.zoneService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrSDNServiceNotAvailable{})
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		h.writeError(w, http.StatusBadRequest, &MessageError{Msg: "zone name is required"})
		return
	}

	restartRequired, err := h.zoneService.Delete(ctx, zone.Zone(name))
	if err != nil {
		switch err.(type) {
		case gateway.ErrZoneNotFound:
			h.writeError(w, http.StatusNotFound, err)
		case gateway.ErrZoneValidation:
			h.writeError(w, http.StatusBadRequest, err)
		default:
			h.writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":          true,
		"restart_required": restartRequired,
	})
}
