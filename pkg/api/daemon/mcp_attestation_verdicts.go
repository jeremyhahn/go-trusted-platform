// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var _ mcp.DeviceVerdictProvider = (*MCPServiceProvider)(nil)

// verdictPageJSON renders a verdict page in the proto's own field names, with
// RFC 3339 timestamps, so the SDK decodes it with protojson.
var verdictPageJSON = protojson.MarshalOptions{UseProtoNames: true}

// AttestationPollDeviceVerdicts implements mcp.DeviceVerdictProvider. MCP has
// no peer identity to fall back on, so a caller without a platform token
// holding attestation:read is refused.
func (p *MCPServiceProvider) AttestationPollDeviceVerdicts(ctx context.Context, cursor string, waitMs uint32) (any, error) {
	if p.attestationServer == nil {
		return nil, mcp.ErrDeviceVerdictsNotConfigured
	}
	authCtx, _ := mcp.AuthorizedContextFromContext(ctx)
	audience, err := verdictAudienceOfToken(authCtx)
	if err != nil {
		return nil, verdictStatus(err)
	}
	page, err := p.attestationServer.PollDeviceVerdictsFor(ctx, audience,
		&platformv1.PollDeviceVerdictsRequest{Cursor: cursor, WaitMs: waitMs})
	if err != nil {
		return nil, err
	}
	data, err := verdictPageJSON.Marshal(page)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}
