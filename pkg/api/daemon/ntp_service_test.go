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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
)

// TestNTPStatusToPbCarriesServeNameFindings asserts the advertised-name
// mismatch reaches the wire on every transport, not only the health
// component. An operator reading `platformctl ntp status` on a control plane
// must see that it is serving a name it refuses without first knowing to look
// at health (#509).
func TestNTPStatusToPbCarriesServeNameFindings(t *testing.T) {
	pb := ntpStatusToPb(&ntp.Status{
		Synced:  true,
		Stratum: 3,
		ServeNameFindings: []ntp.ServeNameFinding{{
			Kind:           ntp.ServeNameUnreachable,
			Name:           "cp.example.internal",
			Address:        "198.18.1.140",
			ListenNetworks: []string{"198.18.0.0/24", "172.16.201.0/24"},
		}},
	})

	findings := pb.GetServeNameFindings()
	if len(findings) != 1 {
		t.Fatalf("serve_name_findings = %+v, want one", findings)
	}
	if findings[0].GetName() != "cp.example.internal" {
		t.Errorf("name = %q", findings[0].GetName())
	}
	if findings[0].GetAddress() != "198.18.1.140" {
		t.Errorf("address = %q", findings[0].GetAddress())
	}
	if len(findings[0].GetListenNetworks()) != 2 {
		t.Errorf("listen_networks = %v, want both allow entries", findings[0].GetListenNetworks())
	}
	if findings[0].GetKind() != string(ntp.ServeNameUnreachable) {
		t.Errorf("kind = %q, want %q", findings[0].GetKind(), ntp.ServeNameUnreachable)
	}
}

// TestNTPStatusToPbCarriesTheUnresolvableKind asserts the second kind reaches
// the wire with the resolver's own words and WITHOUT an address or allow
// list, which it has no basis to assert.
func TestNTPStatusToPbCarriesTheUnresolvableKind(t *testing.T) {
	pb := ntpStatusToPb(&ntp.Status{
		Synced: true,
		ServeNameFindings: []ntp.ServeNameFinding{{
			Kind:  ntp.ServeNameUnresolvable,
			Name:  "time.example.internal",
			Error: "lookup time.example.internal: no such host",
		}},
	})

	findings := pb.GetServeNameFindings()
	if len(findings) != 1 {
		t.Fatalf("serve_name_findings = %+v, want one", findings)
	}
	f := findings[0]
	if f.GetKind() != string(ntp.ServeNameUnresolvable) {
		t.Errorf("kind = %q, want %q", f.GetKind(), ntp.ServeNameUnresolvable)
	}
	if f.GetError() != "lookup time.example.internal: no such host" {
		t.Errorf("error = %q, want the resolver's own words", f.GetError())
	}
	if f.GetAddress() != "" {
		t.Errorf("address = %q, want empty for an unresolvable name", f.GetAddress())
	}
	if len(f.GetListenNetworks()) != 0 {
		t.Errorf("listen_networks = %v, want empty: not an allow-list verdict", f.GetListenNetworks())
	}
}

// TestNTPStatusToPbOmitsAbsentServeNameFindings asserts a correctly
// configured node sends no empty list for a consumer to interpret.
func TestNTPStatusToPbOmitsAbsentServeNameFindings(t *testing.T) {
	if got := ntpStatusToPb(&ntp.Status{Synced: true}).GetServeNameFindings(); got != nil {
		t.Fatalf("serve_name_findings = %+v, want nil on a healthy node", got)
	}
	if got := ntpServeNameFindingsToPb(nil); got != nil {
		t.Fatalf("ntpServeNameFindingsToPb(nil) = %+v, want nil", got)
	}
}
