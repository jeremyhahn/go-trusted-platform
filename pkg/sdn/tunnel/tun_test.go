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
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	vnl "github.com/vishvananda/netlink"
)

// tunPipe makes the mock's LinkAdd hand back a pipe end as the TUN
// descriptor, so Read/Write/Close exercise the real os.File path without a
// kernel device. The returned writer feeds "packets" into the device.
func tunPipe(t *testing.T, nl *mockNetlinkOps) *os.File {
	t.Helper()
	// A socketpair, not a pipe: the device end must be both readable and
	// writable, exactly as a real TUN descriptor is.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := os.NewFile(uintptr(fds[0]), "tun-device")
	w := os.NewFile(uintptr(fds[1]), "tun-peer")
	t.Cleanup(func() { _ = w.Close() })
	nl.linkAddFn = func(link vnl.Link) error {
		tt, ok := link.(*vnl.Tuntap)
		if !ok {
			t.Fatalf("expected a Tuntap link, got %T", link)
		}
		if tt.Mode != vnl.TUNTAP_MODE_TUN || tt.Flags&vnl.TUNTAP_NO_PI == 0 || !tt.NonPersist {
			t.Fatalf("tuntap not requested as a non-persistent, no-PI TUN: %+v", tt)
		}
		tt.Fds = []*os.File{r}
		nl.mu.Lock()
		nl.links[tt.Name] = tt
		nl.mu.Unlock()
		return nil
	}
	return w
}

func tunConfig() TUNConfig {
	return TUNConfig{Name: "masque0", Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/24"), netip.MustParsePrefix("fd00:9::1/64")}}
}

func TestOpenTUN_BringsUpAndForwards(t *testing.T) {
	nl := newMockNetlinkOps()
	feed := tunPipe(t, nl)
	dev, err := openTUN(nl, tunConfig())
	if err != nil {
		t.Fatalf("openTUN: %v", err)
	}
	if dev.Name() != "masque0" {
		t.Fatalf("name = %q", dev.Name())
	}
	link := nl.links["masque0"]
	if link.Attrs().MTU != defaultTUNMTU || link.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("link not configured: mtu=%d flags=%v", link.Attrs().MTU, link.Attrs().Flags)
	}
	if got := len(nl.addrs["masque0"]); got != 2 {
		t.Fatalf("addresses programmed = %d, want 2", got)
	}
	if nl.addrs["masque0"][0].IPNet.String() != "10.9.0.1/24" {
		t.Fatalf("v4 address kept host bits? got %s", nl.addrs["masque0"][0].IPNet)
	}
	pkt := []byte{0x45, 0, 0, 20}
	if _, err := feed.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := dev.Read(buf)
	if err != nil || n != len(pkt) {
		t.Fatalf("Read = %d, %v", n, err)
	}
	out := []byte{0x45, 0, 0, 21, 9}
	if n, err := dev.Write(out); err != nil || n != len(out) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	back := make([]byte, 64)
	if n, err := feed.Read(back); err != nil || n != len(out) {
		t.Fatalf("peer Read = %d, %v", n, err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, ok := nl.links["masque0"]; ok {
		t.Fatal("link not removed on Close")
	}
	if _, err := dev.Read(buf); err == nil {
		t.Fatal("Read after Close succeeded")
	}
}

func TestOpenTUN_CustomMTU(t *testing.T) {
	nl := newMockNetlinkOps()
	tunPipe(t, nl)
	cfg := tunConfig()
	cfg.MTU = 1420
	dev, err := openTUN(nl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if nl.links["masque0"].Attrs().MTU != 1420 {
		t.Fatalf("mtu = %d", nl.links["masque0"].Attrs().MTU)
	}
}

func TestOpenTUN_RoutesThePrefixesIntoTheDevice(t *testing.T) {
	nl := newMockNetlinkOps()
	tunPipe(t, nl)
	cfg := tunConfig()
	cfg.Routes = []netip.Prefix{netip.MustParsePrefix("10.20.1.1/16"), netip.MustParsePrefix("fd00:20::/48")}

	dev, err := openTUN(nl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	index := nl.links["masque0"].Attrs().Index
	var got []string
	for _, r := range nl.routes {
		if r.LinkIndex != index || r.Scope != vnl.SCOPE_LINK {
			t.Fatalf("route %s not a link route through the device", r.Dst)
		}
		got = append(got, r.Dst.String())
	}
	if strings.Join(got, ",") != "10.20.0.0/16,fd00:20::/48" {
		t.Fatalf("routes = %v", got)
	}
}

func TestOpenTUN_ARouteThatFailsRemovesTheDevice(t *testing.T) {
	boom := errors.New("boom")
	nl := newMockNetlinkOps()
	tunPipe(t, nl)
	nl.routeReplaceFn = func(*vnl.Route) error { return boom }
	cfg := tunConfig()
	cfg.Routes = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}

	_, err := openTUN(nl, cfg)

	var cf *ErrTunnelCreateFailed
	if !errors.As(err, &cf) || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want ErrTunnelCreateFailed wrapping boom", err)
	}
	if _, ok := nl.links["masque0"]; ok {
		t.Fatal("link not rolled back")
	}
}

func TestTUNConfig_Validate(t *testing.T) {
	cases := map[string]struct {
		mutate func(*TUNConfig)
		reason string
	}{
		"empty name":    {func(c *TUNConfig) { c.Name = "" }, "device name"},
		"long name":     {func(c *TUNConfig) { c.Name = "sixteen-chars-xx" }, "device name"},
		"no addresses":  {func(c *TUNConfig) { c.Addresses = nil }, "address"},
		"zero prefix":   {func(c *TUNConfig) { c.Addresses = []netip.Prefix{{}} }, "not valid"},
		"mtu too small": {func(c *TUNConfig) { c.MTU = 10 }, "MTU"},
		"zero route":    {func(c *TUNConfig) { c.Routes = []netip.Prefix{{}} }, "route"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := tunConfig()
			tc.mutate(&cfg)
			_, err := openTUN(newMockNetlinkOps(), cfg)
			var invalid *ErrInvalidTunnelConfig
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v, want ErrInvalidTunnelConfig", err)
			}
			if !strings.Contains(invalid.Reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", invalid.Reason, tc.reason)
			}
		})
	}
}

func TestOpenTUN_Failures(t *testing.T) {
	boom := errors.New("boom")
	t.Run("link add fails", func(t *testing.T) {
		nl := newMockNetlinkOps()
		nl.linkAddFn = func(vnl.Link) error { return boom }
		_, err := openTUN(nl, tunConfig())
		var cf *ErrTunnelCreateFailed
		if !errors.As(err, &cf) || !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no descriptor returned", func(t *testing.T) {
		nl := newMockNetlinkOps()
		_, err := openTUN(nl, tunConfig())
		var notUp *ErrDeviceNotUp
		if !errors.As(err, &notUp) {
			t.Fatalf("err = %v, want ErrDeviceNotUp", err)
		}
		if _, ok := nl.links["masque0"]; ok {
			t.Fatal("link left behind")
		}
	})
	for name, arm := range map[string]func(*mockNetlinkOps){
		"addr add fails": func(nl *mockNetlinkOps) { nl.addrAddFn = func(vnl.Link, *vnl.Addr) error { return boom } },
		"mtu fails":      func(nl *mockNetlinkOps) { nl.linkSetMTUFn = func(vnl.Link, int) error { return boom } },
		"set up fails":   func(nl *mockNetlinkOps) { nl.linkSetUpFn = func(vnl.Link) error { return boom } },
		"lookup fails":   func(nl *mockNetlinkOps) { nl.linkByNameFn = func(string) (vnl.Link, error) { return nil, boom } },
	} {
		t.Run(name, func(t *testing.T) {
			nl := newMockNetlinkOps()
			feed := tunPipe(t, nl)
			arm(nl)
			_, err := openTUN(nl, tunConfig())
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want boom", err)
			}
			if _, ok := nl.links["masque0"]; ok {
				t.Fatal("link not rolled back")
			}
			// The descriptor was closed on rollback: writing into the pipe
			// now fails with EPIPE.
			if _, err := feed.Write([]byte{1}); err == nil {
				t.Fatal("descriptor still open after rollback")
			}
		})
	}
}

func TestPrefixToIPNet(t *testing.T) {
	v4 := prefixToIPNet(netip.MustParsePrefix("10.9.0.7/24"))
	if v4.String() != "10.9.0.7/24" || len(v4.IP) != 4 {
		t.Fatalf("v4 = %s (len %d)", v4, len(v4.IP))
	}
	v6 := prefixToIPNet(netip.MustParsePrefix("fd00:9::7/64"))
	if v6.String() != "fd00:9::7/64" || len(v6.IP) != 16 {
		t.Fatalf("v6 = %s (len %d)", v6, len(v6.IP))
	}
}

func TestOpenTUN_RealOpsRefuseAnInvalidConfig(t *testing.T) {
	// OpenTUN validates before it touches netlink, so the refusal path runs
	// without CAP_NET_ADMIN.
	_, err := OpenTUN(TUNConfig{})
	var invalid *ErrInvalidTunnelConfig
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidTunnelConfig", err)
	}
}
