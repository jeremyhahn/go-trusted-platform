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
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// shippedTemplateRoot is the tree of shipped platformd templates.
const shippedTemplateRoot = "../../../configs/platform/templates"

// templatePublicIPv4 stands in for the public IPv4 platformd detects at
// startup; a template that leaves vtep-address unset falls back to it.
var templatePublicIPv4 = net.ParseIP("203.0.113.7")

// loadShippedTemplate decodes a platformd template the way platformd does:
// viper plus the platform decode hook.
func loadShippedTemplate(t *testing.T, path string) *app.App {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(raw)); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var a app.App
	if err := v.Unmarshal(&a, config.DecodeHook()); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return &a
}

// shippedOverlayTemplates returns every platformd template (gatewayd's own
// file excluded) that enables the overlay, keyed by its path.
func shippedOverlayTemplates(t *testing.T) map[string]*app.App {
	t.Helper()
	out := make(map[string]*app.App)
	err := filepath.WalkDir(shippedTemplateRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" || filepath.Base(path) == "gatewayd.yaml" {
			return nil
		}
		a := loadShippedTemplate(t, path)
		if a.SDNConfig != nil && a.SDNConfig.Overlay != nil && a.SDNConfig.Overlay.Enabled {
			out[path] = a
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", shippedTemplateRoot, err)
	}
	if len(out) == 0 {
		t.Fatal("no shipped template enables the overlay; the check below would prove nothing")
	}
	return out
}

// templateInterfaceAddrs answers the IPsec fabric-interface lookup for a
// template: the host binds the configured local address. The test checks
// the template's configuration, not this host's interfaces.
func templateInterfaceAddrs(a *app.App) interfaceAddrsFunc {
	return func(string) ([]netip.Addr, error) {
		addr, err := netip.ParseAddr(a.SDNConfig.Overlay.IPsec.LocalAddress)
		if err != nil {
			return nil, err
		}
		return []netip.Addr{addr}, nil
	}
}

// TestShippedTemplates_OverlayVTEPResolves runs every shipped template that
// enables the overlay through resolveOverlayVTEP, the check platformd runs
// before it starts the overlay: a template that names no underlay (and runs
// no IPsec) would stop platformd, so it fails here instead.
func TestShippedTemplates_OverlayVTEPResolves(t *testing.T) {
	for path, a := range shippedOverlayTemplates(t) {
		rel, err := filepath.Rel(shippedTemplateRoot, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(rel, func(t *testing.T) {
			vtep, err := resolveOverlayVTEP(templatePublicIPv4, a.SDNConfig.Overlay, templateInterfaceAddrs(a))
			if err != nil {
				t.Fatalf("platformd would refuse to start: %v", err)
			}
			if vtep.iface == "" || vtep.iface == "lo" || vtep.addr.IsLoopback() {
				t.Fatalf("VTEP %+v: a shipped template's VTEP sits on its fabric, not loopback", vtep)
			}
		})
	}
}

// TestShippedTemplates_OverlayWithoutUnderlayRefused proves the check above
// can fail: a shipped overlay template stripped of its underlay interface is
// refused with the setting to add.
func TestShippedTemplates_OverlayWithoutUnderlayRefused(t *testing.T) {
	for path, a := range shippedOverlayTemplates(t) {
		if a.SDNConfig.Overlay.IPsec != nil && a.SDNConfig.Overlay.IPsec.Enabled {
			continue
		}
		cfg := *a.SDNConfig.Overlay
		cfg.UnderlayInterface = ""
		_, err := resolveOverlayVTEP(templatePublicIPv4, &cfg, noInterfaceLookup(t))
		var settingErr *OverlayVTEPSettingError
		if !errors.As(err, &settingErr) || settingErr.Setting != overlayUnderlayInterfaceKey {
			t.Fatalf("%s without underlay-interface: err = %v, want an OverlayVTEPSettingError naming %s",
				path, err, overlayUnderlayInterfaceKey)
		}
		return
	}
	t.Fatal("no shipped overlay template runs without IPsec")
}
