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

// CA argument mapping for the MCP transport.
//
// The ca_issue tool (pkg/api/mcp/tools.go) takes the certificate request
// flat — subject fields and SANs at the top level, the key algorithm as a
// string under "algorithm" — where the pb IssueCertificateRequest nests them,
// so IssueCertificate has its own argument builder (#691). The tools answer
// with the gRPC service's own pb replies, which the generic JSON round-trip
// decodes.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/internal/cawire"
)

func init() {
	mcpArgBuilders[platformv1.CAService_IssueCertificate_FullMethodName] = buildCAIssueArgs
}

// buildCAIssueArgs flattens the pb issue request into the ca_issue tool
// arguments. A missing request or subject is sent without a common name,
// and the tool refuses it, as the gRPC service does.
func buildCAIssueArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.IssueCertificateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.CAService_IssueCertificate_FullMethodName}
	}
	req := in.GetRequest()
	algorithm, err := cawire.KeyAlgorithmName(req.GetKeyAlgorithm())
	if err != nil {
		return nil, err
	}
	subject := req.GetSubject()
	sans := req.GetSans()
	return map[string]interface{}{
		"common_name":         subject.GetCommonName(),
		"organization":        subject.GetOrganization(),
		"organizational_unit": subject.GetOrganizationalUnit(),
		"country":             subject.GetCountry(),
		"province":            subject.GetProvince(),
		"locality":            subject.GetLocality(),
		"address":             subject.GetAddress(),
		"postal_code":         subject.GetPostalCode(),
		"dns_names":           sans.GetDnsNames(),
		"ip_addresses":        sans.GetIpAddresses(),
		"email_addresses":     sans.GetEmailAddresses(),
		"uris":                sans.GetUris(),
		"valid_days":          req.GetValidDays(),
		"algorithm":           algorithm,
		"store_type":          req.GetStoreType(),
		"key_usage":           req.GetKeyUsage(),
		"ext_key_usage":       req.GetExtKeyUsage(),
		"is_ca":               req.GetIsCa(),
		"max_path_len":        req.GetMaxPathLen(),
	}, nil
}
