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
	"errors"
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/internal/cawire"
)

// The daemon round trip lives in pkg/api/daemon (TestCACertificateParity),
// which drives the real ca_issue and ca_get tools.

func fullIssueRequest() *platformv1.IssueCertificateRequest {
	return &platformv1.IssueCertificateRequest{Request: &platformv1.CertificateRequest{
		Subject: &platformv1.Subject{
			CommonName: "cn", Organization: "o", OrganizationalUnit: "ou", Country: "US",
			Province: "st", Locality: "l", Address: "street", PostalCode: "zip",
		},
		Sans: &platformv1.SubjectAlternativeNames{
			DnsNames: []string{"d"}, IpAddresses: []string{"192.0.2.1"},
			EmailAddresses: []string{"e@x"}, Uris: []string{"spiffe://x/y"},
		},
		ValidDays:    7,
		KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
		StoreType:    "pkcs8",
		KeyUsage:     []string{"DIGITAL_SIGNATURE"},
		ExtKeyUsage:  []string{"CLIENT_AUTH"},
		IsCa:         true,
		MaxPathLen:   1,
	}}
}

// ca_issue takes the request flat with a string algorithm; the builder
// carries every pb field onto it (#691).
func TestBuildCAIssueArgs_FlattensEveryField(t *testing.T) {
	if _, ok := mcpArgBuilders[platformv1.CAService_IssueCertificate_FullMethodName]; !ok {
		t.Fatalf("no MCP argument builder for %s", platformv1.CAService_IssueCertificate_FullMethodName)
	}

	got, err := buildCAIssueArgs(fullIssueRequest())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := map[string]interface{}{
		"common_name": "cn", "organization": "o", "organizational_unit": "ou", "country": "US",
		"province": "st", "locality": "l", "address": "street", "postal_code": "zip",
		"dns_names": []string{"d"}, "ip_addresses": []string{"192.0.2.1"},
		"email_addresses": []string{"e@x"}, "uris": []string{"spiffe://x/y"},
		"valid_days": int32(7), "algorithm": "RSA-3072", "store_type": "pkcs8",
		"key_usage": []string{"DIGITAL_SIGNATURE"}, "ext_key_usage": []string{"CLIENT_AUTH"},
		"is_ca": true, "max_path_len": int32(1),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
}

func TestBuildCAIssueArgs_RefusesWrongArgsAndUnknownAlgorithm(t *testing.T) {
	var wrong ErrUnexpectedArgsType
	if _, err := buildCAIssueArgs(&platformv1.SignCSRRequest{}); !errors.As(err, &wrong) {
		t.Fatalf("wrong args type: got %v, want ErrUnexpectedArgsType", err)
	}
	req := fullIssueRequest()
	req.Request.KeyAlgorithm = platformv1.KeyAlgorithm(99)
	var unknown cawire.ErrUnknownKeyAlgorithm
	if _, err := buildCAIssueArgs(req); !errors.As(err, &unknown) {
		t.Fatalf("unknown algorithm: got %v, want ErrUnknownKeyAlgorithm", err)
	}
}

// An empty request is sent without a common name, which the tool refuses.
func TestBuildCAIssueArgs_EmptyRequestHasNoCommonName(t *testing.T) {
	got, err := buildCAIssueArgs(&platformv1.IssueCertificateRequest{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got["common_name"] != "" || got["algorithm"] != "" {
		t.Fatalf("args = %v, want an empty common name and algorithm", got)
	}
}
