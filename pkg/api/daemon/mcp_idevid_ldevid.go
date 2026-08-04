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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

// Compile-time assertion that the MCP service provider implements the LDevID
// capability the idevid_create_ldevid tool type-asserts at runtime.
var _ mcp.LDevIDCreator = (*MCPServiceProvider)(nil)

// CreateLDevID provisions a Local Device Identifier (IEEE 802.1AR) over MCP.
// It converts the transport-agnostic MCP request to the pb request and
// delegates to the shared IDevIDGRPCService.CreateLDevID, so the MCP tool has
// identical semantics — TPM key creation, CSR, CA issuance, proven-IDevID
// gate — as every other transport. The returned pb response is JSON-marshaled
// by the tool layer (marshalResult), which is wire-symmetric with the SDK MCP
// adapter decoding it back into the pb reply.
func (p *MCPServiceProvider) CreateLDevID(ctx context.Context, req *mcp.CreateLDevIDMCPRequest) (interface{}, error) {
	if p.idevidService == nil {
		return nil, ErrLDevIDServiceNotConfigured{}
	}

	pbReq := &platformv1.CreateLDevIDRequest{}
	if req != nil {
		if algo, ok := idevidsvc.AlgorithmToProto(req.Algorithm); ok {
			pbReq.Algorithm = algo
		}
		pbReq.Handle = req.Handle
		pbReq.Profile = req.Profile
		pbReq.ValidityDays = req.ValidityDays
		pbReq.Overwrite = req.Overwrite
		if t := req.Template; t != nil {
			pbReq.Template = &platformv1.CSRTemplate{
				CommonName:         t.CommonName,
				Organization:       t.Organization,
				OrganizationalUnit: t.OrganizationalUnit,
				Country:            t.Country,
				Province:           t.Province,
				Locality:           t.Locality,
				DnsNames:           t.DNSNames,
				EmailAddresses:     t.EmailAddresses,
			}
		}
	}

	resp, err := p.idevidService.CreateLDevID(ctx, pbReq)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
