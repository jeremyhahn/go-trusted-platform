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

package tunnel

import (
	"errors"
	"testing"

	vnl "github.com/vishvananda/netlink"
)

// TestRemoveStaleWireGuardHub covers a datapath that restarts with no hub
// plane, in every build: a FIPS gatewayd that replaces a non-FIPS one after
// an ungraceful exit still removes the WireGuard hub device its predecessor
// left in the kernel, with its peers, while it creates none.
func TestRemoveStaleWireGuardHub(t *testing.T) {
	for name, tc := range map[string]struct {
		dev  vnl.Link
		kept bool
	}{
		"stale hub":      {dev: &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: "wg-vpn0"}}},
		"foreign device": {dev: &vnl.Dummy{LinkAttrs: vnl.LinkAttrs{Name: "wg-vpn0"}}, kept: true},
		"no device":      {},
	} {
		t.Run(name, func(t *testing.T) {
			nl := newMockNetlinkOps()
			if tc.dev != nil {
				nl.links["wg-vpn0"] = tc.dev
			}
			if err := removeStaleWireGuardHub(nil, nl, "wg-vpn0"); err != nil {
				t.Fatalf("err = %v", err)
			}
			_, ok := nl.links["wg-vpn0"]
			if ok != tc.kept {
				t.Fatalf("device kept = %v, want %v", ok, tc.kept)
			}
		})
	}
	t.Run("delete fails", func(t *testing.T) {
		nl := newMockNetlinkOps()
		nl.links["wg-vpn0"] = &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: "wg-vpn0"}}
		boom := errors.New("busy")
		nl.linkDelFn = func(vnl.Link) error { return boom }
		var rf *ErrTunnelRemoveFailed
		if err := removeStaleWireGuardHub(nil, nl, "wg-vpn0"); !errors.As(err, &rf) || !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
	// Only a typed link-not-found result proves the device absent: a
	// permission, transport or decoding failure of the lookup is returned, so
	// the datapath does not start beside a hub it could not see.
	t.Run("lookup fails", func(t *testing.T) {
		nl := newMockNetlinkOps()
		nl.links["wg-vpn0"] = &vnl.Wireguard{LinkAttrs: vnl.LinkAttrs{Name: "wg-vpn0"}}
		boom := errors.New("operation not permitted")
		nl.linkByNameFn = func(string) (vnl.Link, error) { return nil, boom }
		var rf *ErrTunnelRemoveFailed
		if err := removeStaleWireGuardHub(nil, nl, "wg-vpn0"); !errors.As(err, &rf) || !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the lookup failure", err)
		}
	})
}
