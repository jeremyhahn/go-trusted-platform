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

package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// get serves a GET for path through the fixture's real route table.
func get(t *testing.T, s *vbmcServer, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s: body is not JSON: %v", path, err)
		}
	}
	return rec, body
}

// advertisedLinks returns every @odata.id the resource names, whether as a
// direct link ({"Systems": {"@odata.id": ...}}) or as a collection member.
func advertisedLinks(body map[string]any) []string {
	var links []string
	for key, v := range body {
		switch val := v.(type) {
		case map[string]any:
			if id, ok := val["@odata.id"].(string); ok && key != "Oem" {
				links = append(links, id)
			}
		case []any:
			for _, m := range val {
				if member, ok := m.(map[string]any); ok {
					if id, ok := member["@odata.id"].(string); ok {
						links = append(links, id)
					}
				}
			}
		}
	}
	return links
}

// TestLoadConfig_Defaults verifies loadConfig picks up defaults for
// all vBMC settings when no VBMC_* env vars are set. Ensures a fresh
// container boot binds the expected HTTPS + IPMI ports.
func TestLoadConfig_Defaults(t *testing.T) {
	// Clear any env that would override defaults.
	for _, k := range []string{
		"VBMC_HTTPS_ADDR", "VBMC_VENDOR", "VBMC_CN", "VBMC_LOG_LEVEL",
		"VBMC_IPMI_ADDR", "VBMC_IPMI_USER", "VBMC_IPMI_PASSWORD",
	} {
		t.Setenv(k, "")
	}
	c := loadConfig()
	if c.httpsAddr != ":8443" {
		t.Errorf("httpsAddr = %q, want :8443", c.httpsAddr)
	}
	if c.vendor != "Supermicro" {
		t.Errorf("vendor = %q, want Supermicro", c.vendor)
	}
	if c.cn != "vbmc.example.internal" {
		t.Errorf("cn = %q", c.cn)
	}
	if c.logLevel != slog.LevelInfo {
		t.Errorf("logLevel = %v, want Info", c.logLevel)
	}
	if c.ipmiAddr != ":6230" {
		t.Errorf("ipmiAddr = %q, want :6230", c.ipmiAddr)
	}
	if c.ipmiUser != "ADMIN" {
		t.Errorf("ipmiUser = %q, want ADMIN", c.ipmiUser)
	}
	if c.ipmiPassword != "ADMIN" {
		t.Errorf("ipmiPassword = %q, want ADMIN", c.ipmiPassword)
	}
}

// TestLoadConfig_Overrides verifies every vBMC env var can be
// overridden. Asserts the IPMI fields in particular are wired.
func TestLoadConfig_Overrides(t *testing.T) {
	t.Setenv("VBMC_HTTPS_ADDR", ":28443")
	t.Setenv("VBMC_VENDOR", "Dell")
	t.Setenv("VBMC_CN", "custom.example")
	t.Setenv("VBMC_LOG_LEVEL", "debug")
	t.Setenv("VBMC_IPMI_ADDR", ":16230")
	t.Setenv("VBMC_IPMI_USER", "root")
	t.Setenv("VBMC_IPMI_PASSWORD", "s3cret")

	c := loadConfig()
	if c.httpsAddr != ":28443" {
		t.Errorf("httpsAddr = %q", c.httpsAddr)
	}
	if c.vendor != "Dell" {
		t.Errorf("vendor = %q", c.vendor)
	}
	if c.cn != "custom.example" {
		t.Errorf("cn = %q", c.cn)
	}
	if c.logLevel != slog.LevelDebug {
		t.Errorf("logLevel = %v, want Debug", c.logLevel)
	}
	if c.ipmiAddr != ":16230" {
		t.Errorf("ipmiAddr = %q", c.ipmiAddr)
	}
	if c.ipmiUser != "root" {
		t.Errorf("ipmiUser = %q", c.ipmiUser)
	}
	if c.ipmiPassword != "s3cret" {
		t.Errorf("ipmiPassword = %q", c.ipmiPassword)
	}
}

// TestLoadConfig_LogLevels covers each branch of the VBMC_LOG_LEVEL
// switch.
func TestLoadConfig_LogLevels(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":       slog.LevelDebug,
		"info":        slog.LevelInfo,
		"warn":        slog.LevelWarn,
		"error":       slog.LevelError,
		"garbage-val": slog.LevelInfo,
		"":            slog.LevelInfo,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Setenv("VBMC_LOG_LEVEL", in)
			c := loadConfig()
			if c.logLevel != want {
				t.Errorf("VBMC_LOG_LEVEL=%q -> %v, want %v", in, c.logLevel, want)
			}
		})
	}
}

// TestGetenv covers the tiny getenv helper.
func TestGetenv(t *testing.T) {
	t.Setenv("VBMC_TEST_KEY", "")
	if got := getenv("VBMC_TEST_KEY", "default"); got != "default" {
		t.Errorf("getenv unset = %q, want default", got)
	}
	t.Setenv("VBMC_TEST_KEY", "value")
	if got := getenv("VBMC_TEST_KEY", "default"); got != "value" {
		t.Errorf("getenv set = %q, want value", got)
	}
}

// TestServiceRoot_AdvertisedLinksAnswer follows every link the service root
// names, and every member of the collections those links return, and requires
// 200. A resource added to the root without a handler fails here.
func TestServiceRoot_AdvertisedLinksAnswer(t *testing.T) {
	for _, vendor := range []string{"Supermicro", "Dell", "Generic"} {
		t.Run(vendor, func(t *testing.T) {
			s := &vbmcServer{cfg: config{vendor: vendor}}
			rec, root := get(t, s, "/redfish/v1/")
			if rec.Code != http.StatusOK {
				t.Fatalf("service root = %d, want 200", rec.Code)
			}
			links := advertisedLinks(root)
			if len(links) == 0 {
				t.Fatal("service root advertises no links")
			}
			for _, link := range links {
				rec, body := get(t, s, link)
				if rec.Code != http.StatusOK {
					t.Errorf("GET %s = %d, want 200 (advertised by the service root)", link, rec.Code)
					continue
				}
				for _, member := range advertisedLinks(body) {
					if rec, _ := get(t, s, member); rec.Code != http.StatusOK {
						t.Errorf("GET %s = %d, want 200 (member of %s)", member, rec.Code, link)
					}
				}
			}
		})
	}
}

// TestServiceRoot_AdvertisesSystemsAndChassis pins the two collections the
// issue found unserved, so removing them from the root is a deliberate change.
func TestServiceRoot_AdvertisesSystemsAndChassis(t *testing.T) {
	s := &vbmcServer{cfg: config{vendor: "Supermicro"}}
	_, root := get(t, s, "/redfish/v1/")
	got := map[string]bool{}
	for _, l := range advertisedLinks(root) {
		got[l] = true
	}
	for _, want := range []string{"/redfish/v1/Systems", "/redfish/v1/Chassis"} {
		if !got[want] {
			t.Errorf("service root does not advertise %s", want)
		}
	}
}

// TestSystemIdentity_ResolvesQuirks reads the identity the way a Redfish
// client does (service root -> Systems -> first member) and requires
// pkg/quirks to resolve it to the quirk of the configured vendor.
func TestSystemIdentity_ResolvesQuirks(t *testing.T) {
	tests := []struct {
		vendor           string
		wantManufacturer string
		wantQuirkModel   string
	}{
		{"Supermicro", "Supermicro", "X10SDV"},
		{"Dell", "Dell Inc.", ""},
	}
	for _, tc := range tests {
		t.Run(tc.vendor, func(t *testing.T) {
			s := &vbmcServer{cfg: config{vendor: tc.vendor}}
			_, root := get(t, s, "/redfish/v1/")
			systems := root["Systems"].(map[string]any)["@odata.id"].(string)
			_, collection := get(t, s, systems)
			members := advertisedLinks(collection)
			if len(members) == 0 {
				t.Fatalf("%s has no members", systems)
			}
			rec, sys := get(t, s, members[0])
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d", members[0], rec.Code)
			}
			for _, field := range []string{"Manufacturer", "Model", "PartNumber", "SerialNumber", "SKU"} {
				if v, _ := sys[field].(string); v == "" {
					t.Errorf("System.%s is empty", field)
				}
			}
			if sys["Manufacturer"] != tc.wantManufacturer {
				t.Errorf("Manufacturer = %v, want %q", sys["Manufacturer"], tc.wantManufacturer)
			}
			q := quirks.ResolveIdentity(quirks.Identity{
				Manufacturer: sys["Manufacturer"].(string),
				Model:        sys["Model"].(string),
				PartNumber:   sys["PartNumber"].(string),
			})
			if q.Manufacturer != tc.wantManufacturer || q.Model != tc.wantQuirkModel {
				t.Errorf("quirk = %q/%q, want %q/%q", q.Manufacturer, q.Model, tc.wantManufacturer, tc.wantQuirkModel)
			}
		})
	}
}

// TestChassisIdentity_MatchesSystem requires Chassis to carry the same
// identity as the System, so a client reading either resolves the same quirk.
func TestChassisIdentity_MatchesSystem(t *testing.T) {
	s := &vbmcServer{cfg: config{vendor: "Dell"}}
	_, sys := get(t, s, "/redfish/v1/Systems/1")
	_, chassis := get(t, s, "/redfish/v1/Chassis/1")
	for _, field := range []string{"Manufacturer", "Model", "PartNumber", "SerialNumber", "SKU"} {
		if sys[field] != chassis[field] {
			t.Errorf("%s: System %v != Chassis %v", field, sys[field], chassis[field])
		}
	}
}

// TestSystemIdentity_CustomVendor serves an unrecognised vendor as its own
// manufacturer instead of a Supermicro or Dell identity.
func TestSystemIdentity_CustomVendor(t *testing.T) {
	s := &vbmcServer{cfg: config{vendor: "Acme"}}
	_, sys := get(t, s, "/redfish/v1/Systems/1")
	if sys["Manufacturer"] != "Acme" {
		t.Errorf("Manufacturer = %v, want Acme", sys["Manufacturer"])
	}
	if sys["SerialNumber"] == "" || sys["SKU"] == "" {
		t.Errorf("custom vendor identity incomplete: %v", sys)
	}
}

// TestSystemsAndChassis_UnknownMembersNotFound proves the fixture still
// answers 404 for members it does not have, rather than a catch-all 200.
func TestSystemsAndChassis_UnknownMembersNotFound(t *testing.T) {
	s := &vbmcServer{cfg: config{vendor: "Supermicro"}}
	for _, path := range []string{"/redfish/v1/Systems/2", "/redfish/v1/Chassis/2"} {
		if rec, _ := get(t, s, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}
