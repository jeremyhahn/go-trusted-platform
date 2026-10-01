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

package tenant

import (
	"errors"
	"testing"
)

// TestKeyspacePaths covers every key helper on valid input.
func TestKeyspacePaths(t *testing.T) {
	tests := []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"tenant", func() (string, error) { return TenantPath("acme") }, "tenants/acme"},
		{"resource", func() (string, error) { return ResourcePath("acme", KindNetworks, "n1") }, "tenants/acme/networks/n1"},
		{"param leaf", func() (string, error) { return ParamPath("acme", KindCA, "root", "subject") }, "tenants/acme/ca/root/params/subject"},
		{"param base", func() (string, error) { return ParamPath("acme", KindClusters, "c1", "") }, "tenants/acme/clusters/c1/params"},
		{"secret leaf", func() (string, error) { return SecretPath("acme", KindNodes, "n1", NodeSecretBMCPassword) }, "tenants/acme/nodes/n1/secrets/bmc/password"},
		{"secret base", func() (string, error) { return SecretPath("acme", KindNodes, "n1", "") }, "tenants/acme/nodes/n1/secrets"},
		{"node param", func() (string, error) { return NodeParam("acme", "n1", NodeParamHostname) }, "tenants/acme/nodes/n1/params/hostname"},
		{"node secret", func() (string, error) { return NodeSecret("acme", "n1", NodeSecretTPMSRKAuth) }, "tenants/acme/nodes/n1/secrets/tpm/srk_auth"},
		{"node prefix", func() (string, error) { return NodePrefix("acme", "n1") }, "tenants/acme/nodes/n1"},
	}
	for _, tc := range tests {
		got, err := tc.got()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestKeyspacePaths_InvalidSegments refuses ids that would corrupt a path
// and kinds outside the known set.
func TestKeyspacePaths_InvalidSegments(t *testing.T) {
	for _, bad := range []string{"", "a/b", "a b", "a\tb", "a\x01b", "a\x7fb"} {
		if _, err := TenantPath(bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("TenantPath(%q) error = %v, want ErrInvalidID", bad, err)
		}
	}
	if _, err := ResourcePath("bad/tenant", KindNodes, "n1"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("ResourcePath with bad tenant: error = %v, want ErrInvalidID", err)
	}
	if _, err := ResourcePath("acme", KindNodes, ""); !errors.Is(err, ErrInvalidID) {
		t.Errorf("ResourcePath with empty id: error = %v, want ErrInvalidID", err)
	}
	var msg *MessageError
	if _, err := ResourcePath("acme", "vlans", "n1"); !errors.As(err, &msg) {
		t.Errorf("ResourcePath with unknown kind: error = %v, want MessageError", err)
	}
	if _, err := ParamPath("acme", "vlans", "n1", "x"); err == nil {
		t.Error("ParamPath with unknown kind: expected an error")
	}
	if _, err := SecretPath("", KindNodes, "n1", "x"); err == nil {
		t.Error("SecretPath with empty tenant: expected an error")
	}
	var wrapped *WrappedError
	if _, err := NodeParam("acme", "", "x"); !errors.As(err, &wrapped) || wrapped.Msg != "id" {
		t.Errorf("NodeParam with empty node: error = %v, want WrappedError id", err)
	}
}
