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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// =============================================================================
// Config delivery (provisioning) tool wiring
// =============================================================================
//
// These tools mirror the platform.v1 ConfigDeliveryService gRPC surface so
// AI/LLM clients can drive the same pre-enrollment config delivery workflows
// over MCP. Tool names follow the `provision_<verb>` convention and are
// routed through a map-based dispatcher (O(1) lookup per project
// conventions).
//
// The MCP server stays decoupled from the daemon: the underlying config
// delivery service is exposed via the optional ProvisionProvider interface,
// satisfied by the daemon's MCPServiceProvider when the provisioning
// dependencies are configured. Authentication (single-use nonce + EAB HMAC
// and EK-certificate binding) is enforced INSIDE the backing service, so
// this surface only binds arguments and surfaces the service's typed errors.

// ErrProvisionNotConfigured indicates the config delivery backend is not
// wired into the MCP tool registry. Clients see this when the daemon was
// started without the provisioning dependencies configured.
var ErrProvisionNotConfigured = errors.New("provision: config delivery service not configured")

// ErrProvisionSessionIDRequired indicates the session_id argument is
// missing or empty.
var ErrProvisionSessionIDRequired = errors.New("provision: session_id is required")

// ErrProvisionProfileIDRequired indicates the profile_id argument is
// missing or zero.
var ErrProvisionProfileIDRequired = errors.New("provision: profile_id is required and must be non-zero")

// ErrProvisionDigestRequired indicates the digest argument is missing or
// empty.
var ErrProvisionDigestRequired = errors.New("provision: digest is required")

// ErrProvisionInvalidProfileID indicates the profile_id argument could not
// be parsed as an unsigned 64-bit integer.
type ErrProvisionInvalidProfileID struct {
	Value string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrProvisionInvalidProfileID) Error() string {
	return fmt.Sprintf("provision: profile_id %q is not a valid uint64: %v", e.Value, e.Cause)
}

// Unwrap exposes the underlying parse error for errors.Is/As.
func (e ErrProvisionInvalidProfileID) Unwrap() error {
	return e.Cause
}

// ErrProvisionInvalidDigest indicates the digest argument is not valid
// standard base64.
type ErrProvisionInvalidDigest struct {
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrProvisionInvalidDigest) Error() string {
	return fmt.Sprintf("provision: digest must be base64 encoded: %v", e.Cause)
}

// Unwrap exposes the underlying decode error for errors.Is/As.
func (e ErrProvisionInvalidDigest) Unwrap() error {
	return e.Cause
}

// ProvisionFetchConfigRequest carries the device identity and authentication
// arguments for the provision_fetch_config tool. Field semantics match
// configdelivery.ConfigRequest; EKCert is the standard-base64 encoding of the
// DER-encoded TPM Endorsement Key certificate.
type ProvisionFetchConfigRequest struct {
	EKSerial   string
	MACAddress string
	EKCert     string
	EABKeyID   string
	EABHMAC    string
	Nonce      string
}

// ProvisionSignDigestRequest carries the arguments for the
// provision_sign_digest tool. Digest is the decoded message digest bytes;
// KeyRef selects the Secure Boot key (empty defaults to "db").
type ProvisionSignDigestRequest struct {
	EKSerial   string
	MACAddress string
	EKCert     string
	EABKeyID   string
	EABHMAC    string
	Nonce      string
	Digest     []byte
	KeyRef     string
}

// ProvisionProvider is the optional interface a ServiceProvider can satisfy
// to unlock the provision_* MCP tools. Implementations delegate to the
// platform configdelivery.Service (the same backing implementation that
// powers the gRPC ConfigDeliveryService) so the MCP and gRPC surfaces remain
// in lockstep. Results are domain values that the tool executors normalize
// to their canonical JSON shapes via marshalResult.
type ProvisionProvider interface {
	// ProvisionGetNonce issues a new single-use nonce for replay
	// prevention.
	ProvisionGetNonce(ctx context.Context) (interface{}, error)

	// ProvisionFetchConfig authenticates a device and resolves its
	// platform configuration. The tri-state result is either a delivered
	// config (config, status) or a pending session (session_id,
	// provision_url, poll_interval_seconds).
	ProvisionFetchConfig(ctx context.Context, req *ProvisionFetchConfigRequest) (interface{}, error)

	// ProvisionSignDigest signs a UKI (or kernel-module) digest with the
	// control-plane Secure Boot DB key.
	ProvisionSignDigest(ctx context.Context, req *ProvisionSignDigestRequest) (interface{}, error)

	// ProvisionPollSession checks whether a pending provisioning session
	// has been fulfilled, returning either the delivered config or a
	// pending status.
	ProvisionPollSession(ctx context.Context, sessionID string) (interface{}, error)

	// ProvisionFulfillSession links a device profile to a pending
	// provisioning session.
	ProvisionFulfillSession(ctx context.Context, sessionID string, profileID uint64) (interface{}, error)

	// ProvisionListSessions returns all active provisioning sessions.
	ProvisionListSessions(ctx context.Context) (interface{}, error)

	// ProvisionGetSession returns a provisioning session by ID.
	ProvisionGetSession(ctx context.Context, sessionID string) (interface{}, error)
}

// provisionProvider returns the ProvisionProvider interface if the
// ServiceProvider implements it, else nil.
func (r *ToolRegistry) provisionProvider() ProvisionProvider {
	if p, ok := r.service.(ProvisionProvider); ok {
		return p
	}
	return nil
}

// registerProvisionTools registers the provision_* MCP tools. Each tool
// definition mirrors the equivalent ConfigDeliveryService gRPC RPC so AI/LLM
// clients can issue the same calls they would over gRPC or REST.
func (r *ToolRegistry) registerProvisionTools() {
	sessionIDSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"session_id": map[string]interface{}{
				"type":        "string",
				"description": "Provisioning session identifier",
			},
		},
		"required": []string{"session_id"},
	}

	identityProperties := func() map[string]interface{} {
		return map[string]interface{}{
			"ek_serial": map[string]interface{}{
				"type":        "string",
				"description": "TPM Endorsement Key certificate serial number",
			},
			"mac_address": map[string]interface{}{
				"type":        "string",
				"description": "Primary NIC MAC address",
			},
			"ek_cert": map[string]interface{}{
				"type":        "string",
				"description": "Standard-base64 encoding of the DER-encoded TPM EK certificate",
			},
			"eab_key_id": map[string]interface{}{
				"type":        "string",
				"description": "External Account Binding key identifier",
			},
			"eab_hmac": map[string]interface{}{
				"type":        "string",
				"description": "Base64url-encoded EAB HMAC over the request",
			},
			"nonce": map[string]interface{}{
				"type":        "string",
				"description": "Single-use nonce issued by provision_get_nonce",
			},
		}
	}

	r.addTool(ToolDefinition{
		Name:        "provision_get_nonce",
		Description: "Issue a single-use nonce for authenticating a config delivery or digest signing request",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "provision_fetch_config",
		Description: "Authenticate a device (EAB HMAC + nonce, optional EK certificate) and resolve its platform configuration; returns the delivered config or a pending interactive provisioning session",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": identityProperties(),
			"required":   []string{"eab_key_id", "eab_hmac", "nonce"},
		},
	})

	signProperties := identityProperties()
	signProperties["digest"] = map[string]interface{}{
		"type":        "string",
		"description": "Standard-base64 encoding of the pre-computed message digest to sign",
	}
	signProperties["key_ref"] = map[string]interface{}{
		"type":        "string",
		"description": "Secure Boot key selector (default: db)",
	}
	r.addTool(ToolDefinition{
		Name:        "provision_sign_digest",
		Description: "Sign a UKI or kernel-module digest with the control-plane Secure Boot DB key; the private key never leaves the control plane",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": signProperties,
			"required":   []string{"eab_key_id", "eab_hmac", "nonce", "digest"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "provision_poll_session",
		Description: "Poll a pending provisioning session; returns the delivered config once fulfilled or a pending status",
		InputSchema: sessionIDSchema,
	})

	r.addTool(ToolDefinition{
		Name:        "provision_fulfill_session",
		Description: "Link a device profile to a pending provisioning session so the polling device receives its configuration",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"session_id": map[string]interface{}{
					"type":        "string",
					"description": "Provisioning session identifier",
				},
				"profile_id": map[string]interface{}{
					"type":        []interface{}{"integer", "string"},
					"description": "Device profile ID (uint64; pass as a decimal string to avoid JSON number precision loss past 2^53)",
				},
			},
			"required": []string{"session_id", "profile_id"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "provision_list_sessions",
		Description: "List all active (non-expired) provisioning sessions awaiting operator fulfillment",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "provision_get_session",
		Description: "Get a provisioning session by ID",
		InputSchema: sessionIDSchema,
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// provisionToolHandler dispatches a provisioning tool by name. Map-based
// dispatch keeps routing O(1) per project conventions.
type provisionToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var provisionToolDispatch = map[string]provisionToolHandler{
	"provision_get_nonce":       (*ToolRegistry).executeProvisionGetNonce,
	"provision_fetch_config":    (*ToolRegistry).executeProvisionFetchConfig,
	"provision_sign_digest":     (*ToolRegistry).executeProvisionSignDigest,
	"provision_poll_session":    (*ToolRegistry).executeProvisionPollSession,
	"provision_fulfill_session": (*ToolRegistry).executeProvisionFulfillSession,
	"provision_list_sessions":   (*ToolRegistry).executeProvisionListSessions,
	"provision_get_session":     (*ToolRegistry).executeProvisionGetSession,
}

// dispatchProvisionTool looks up a provisioning tool and invokes it.
// Returns (result, handled, err) so the caller can fall through when
// handled is false (tool name doesn't belong to provisioning).
func (r *ToolRegistry) dispatchProvisionTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := provisionToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// provisionSessionID extracts the required session_id argument. Returns
// ErrProvisionSessionIDRequired when missing or empty.
func provisionSessionID(args map[string]interface{}) (string, error) {
	id := getString(args, "session_id")
	if id == "" {
		return "", ErrProvisionSessionIDRequired
	}
	return id, nil
}

// provisionProfileID extracts the required profile_id argument as a uint64.
// It accepts JSON numbers and decimal strings; uint64 IDs SHOULD be passed
// as strings to avoid precision loss past 2^53 (repo convention for uint64
// IDs on the wire). Returns ErrProvisionProfileIDRequired when missing or
// zero and ErrProvisionInvalidProfileID when unparseable.
func provisionProfileID(args map[string]interface{}) (uint64, error) {
	switch v := args["profile_id"].(type) {
	case nil:
		return 0, ErrProvisionProfileIDRequired
	case float64:
		if v < 0 {
			return 0, ErrProvisionInvalidProfileID{
				Value: strconv.FormatFloat(v, 'f', -1, 64),
				Cause: errors.New("negative value"),
			}
		}
		if v == 0 {
			return 0, ErrProvisionProfileIDRequired
		}
		return uint64(v), nil
	case int:
		if v < 0 {
			return 0, ErrProvisionInvalidProfileID{
				Value: strconv.Itoa(v),
				Cause: errors.New("negative value"),
			}
		}
		if v == 0 {
			return 0, ErrProvisionProfileIDRequired
		}
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, ErrProvisionInvalidProfileID{
				Value: strconv.FormatInt(v, 10),
				Cause: errors.New("negative value"),
			}
		}
		if v == 0 {
			return 0, ErrProvisionProfileIDRequired
		}
		return uint64(v), nil
	case uint64:
		if v == 0 {
			return 0, ErrProvisionProfileIDRequired
		}
		return v, nil
	case string:
		if v == "" {
			return 0, ErrProvisionProfileIDRequired
		}
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, ErrProvisionInvalidProfileID{Value: v, Cause: err}
		}
		if id == 0 {
			return 0, ErrProvisionProfileIDRequired
		}
		return id, nil
	default:
		return 0, ErrProvisionInvalidProfileID{
			Value: fmt.Sprintf("%v", v),
			Cause: fmt.Errorf("unsupported type %T", v),
		}
	}
}

// provisionDigest extracts and decodes the required base64 digest argument.
func provisionDigest(args map[string]interface{}) ([]byte, error) {
	encoded := getString(args, "digest")
	if encoded == "" {
		return nil, ErrProvisionDigestRequired
	}
	digest, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrProvisionInvalidDigest{Cause: err}
	}
	if len(digest) == 0 {
		return nil, ErrProvisionDigestRequired
	}
	return digest, nil
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeProvisionGetNonce(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	result, err := p.ProvisionGetNonce(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProvisionFetchConfig(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	// EAB + nonce authentication is enforced inside the config delivery
	// service; missing credentials surface as its typed errors, matching
	// the gRPC surface.
	result, err := p.ProvisionFetchConfig(ctx, &ProvisionFetchConfigRequest{
		EKSerial:   getString(args, "ek_serial"),
		MACAddress: getString(args, "mac_address"),
		EKCert:     getString(args, "ek_cert"),
		EABKeyID:   getString(args, "eab_key_id"),
		EABHMAC:    getString(args, "eab_hmac"),
		Nonce:      getString(args, "nonce"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProvisionSignDigest(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	digest, err := provisionDigest(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProvisionSignDigest(ctx, &ProvisionSignDigestRequest{
		EKSerial:   getString(args, "ek_serial"),
		MACAddress: getString(args, "mac_address"),
		EKCert:     getString(args, "ek_cert"),
		EABKeyID:   getString(args, "eab_key_id"),
		EABHMAC:    getString(args, "eab_hmac"),
		Nonce:      getString(args, "nonce"),
		Digest:     digest,
		KeyRef:     getString(args, "key_ref"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProvisionPollSession(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	sessionID, err := provisionSessionID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProvisionPollSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProvisionFulfillSession(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	sessionID, err := provisionSessionID(args)
	if err != nil {
		return nil, err
	}
	profileID, err := provisionProfileID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProvisionFulfillSession(ctx, sessionID, profileID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProvisionListSessions(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	result, err := p.ProvisionListSessions(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeProvisionGetSession(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.provisionProvider()
	if p == nil {
		return nil, ErrProvisionNotConfigured
	}
	sessionID, err := provisionSessionID(args)
	if err != nil {
		return nil, err
	}
	result, err := p.ProvisionGetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
