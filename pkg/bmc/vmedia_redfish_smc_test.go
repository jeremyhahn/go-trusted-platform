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

package bmc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

const smcLicenseErrorBody = `{
  "error": {
    "code": "Base.v1_4_0.GeneralError",
    "Message": "A general error has occurred.",
    "@Message.ExtendedInfo": [
      {
        "MessageId": "Base.v1_4_0.OemLicenseNotPassed",
        "Message": "Required license not present"
      }
    ]
  }
}`

// newSmcTestClient builds a redfishClient pointed at the given test server.
func newSmcTestClient(t *testing.T, server *httptest.Server) *redfishClient {
	t.Helper()
	logger := slog.Default()
	return &redfishClient{
		logger: logger,
		transport: &redfishTransport{
			httpClient: server.Client(),
			baseURL:    server.URL,
			username:   "admin",
			password:   memguard.NewFromString("admin"),
			logger:     logger,
		},
	}
}

func TestVmediaRedfishSmc_LicenseDetection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(smcVirtualMediaPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(smcLicenseErrorBody))
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	rc := newSmcTestClient(t, server)
	backend := newVmediaRedfishSmc(rc)
	spec := &MediaSpec{URL: "cifs://server/share/boot.iso", Protocol: MediaProtocolCIFS}

	err := backend.Mount(context.Background(), spec)
	if err == nil {
		t.Fatalf("Mount() returned nil, want license error")
	}
	var licErr ErrVirtualMediaLicenseRequired
	if !errors.As(err, &licErr) {
		t.Fatalf("Mount() returned %T, want ErrVirtualMediaLicenseRequired", err)
	}
	if licErr.Vendor != "Supermicro" || licErr.License != "DCMS" {
		t.Errorf("license = %+v, want Supermicro/DCMS", licErr)
	}
}

func TestVmediaRedfishSmc_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(smcVirtualMediaPath, func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	rc := newSmcTestClient(t, server)
	backend := newVmediaRedfishSmc(rc)
	spec := &MediaSpec{URL: "https://example.com/boot.iso", Protocol: MediaProtocolHTTPS}

	err := backend.Mount(context.Background(), spec)
	var unsupErr ErrVirtualMediaUnsupported
	if !errors.As(err, &unsupErr) {
		t.Fatalf("Mount() returned %T, want ErrVirtualMediaUnsupported", err)
	}
	if unsupErr.Vendor != "Supermicro" {
		t.Errorf("vendor = %q, want Supermicro", unsupErr.Vendor)
	}
}

func TestVmediaRedfishSmc_HappyPath(t *testing.T) {
	// Track which requests the backend makes. Mount must now do three
	// things: (1) POST IsoConfig.UnMount for idempotent cleanup of any
	// stale prior attachment, (2) PATCH CfgCD to store Host/Path, and
	// (3) POST IsoConfig.Mount to actually attach media to the virtual
	// drive. Unmount() mirrors: POST IsoConfig.UnMount followed by
	// PATCH CfgCD to clear the config. See the comment on Mount() in
	// vmedia_redfish_smc.go for why each step is required on
	// Supermicro X10/X11/X12 OEM firmware.
	var (
		gotPatch         bool
		gotMountAction   bool
		gotUnmountAct    bool
		unmountCallCount int
	)
	mux := http.NewServeMux()
	mux.HandleFunc(smcVirtualMediaPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			gotPatch = true
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Image":"cifs://server/share/boot.iso","Inserted":true}`))
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc(smcCD1Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// CD1 is the actual device-state endpoint and reports the same
		// Image/Inserted values once IsoConfig.Mount has fired.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Image":"cifs://server/share/boot.iso","Inserted":true}`))
	})
	mux.HandleFunc(smcIsoConfigMountPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST expected", http.StatusMethodNotAllowed)
			return
		}
		gotMountAction = true
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(smcIsoConfigUnmountPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST expected", http.StatusMethodNotAllowed)
			return
		}
		gotUnmountAct = true
		unmountCallCount++
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	rc := newSmcTestClient(t, server)
	backend := newVmediaRedfishSmc(rc)
	spec := &MediaSpec{
		URL:            "cifs://server/share/boot.iso",
		Protocol:       MediaProtocolCIFS,
		Username:       "u",
		Password:       "p",
		WriteProtected: true,
	}

	if err := backend.Mount(context.Background(), spec); err != nil {
		t.Fatalf("Mount() error: %v", err)
	}
	if !gotPatch {
		t.Errorf("Mount(): expected PATCH to CfgCD, did not occur")
	}
	if !gotMountAction {
		t.Errorf("Mount(): expected POST to IsoConfig.Mount action, did not occur")
	}

	info, err := backend.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if !info.Mounted || info.ImageURL != "cifs://server/share/boot.iso" {
		t.Errorf("Status() = %+v, want mounted with cifs URL", info)
	}

	if err := backend.Unmount(context.Background()); err != nil {
		t.Fatalf("Unmount() error: %v", err)
	}
	if !gotUnmountAct {
		t.Errorf("Unmount(): expected POST to IsoConfig.UnMount action, did not occur")
	}
	// Mount should have called UnMount once (idempotent pre-mount
	// cleanup) and Unmount should have called UnMount again, so
	// total calls == 2.
	if unmountCallCount != 2 {
		t.Errorf("UnMount total call count = %d, want 2 (one from Mount pre-clean, one from Unmount)", unmountCallCount)
	}
}

// TestVmediaRedfishSmc_StatusPrefersCD1 confirms Status() reads the
// VM1/CD1 device-state endpoint first (where Inserted reflects the actual
// virtual drive) instead of the CfgCD config shell.
func TestVmediaRedfishSmc_StatusPrefersCD1(t *testing.T) {
	mux := http.NewServeMux()
	// CfgCD reports the stale config — Inserted=true reflects past intent
	// but no current attachment. If Status reads here, the test fails.
	mux.HandleFunc(smcVirtualMediaPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Image":"cifs://stale","Inserted":true}`))
	})
	// CD1 reports the actual device state: drive is empty.
	mux.HandleFunc(smcCD1Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Image":"","Inserted":false}`))
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	rc := newSmcTestClient(t, server)
	backend := newVmediaRedfishSmc(rc)
	info, err := backend.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if info.Mounted {
		t.Errorf("Status().Mounted = true, want false (CD1 empty)")
	}
	if info.ImageURL != "" {
		t.Errorf("Status().ImageURL = %q, want empty (CD1 reports empty)", info.ImageURL)
	}
}

// TestVmediaRedfishSmc_StatusFallbackToCfgCD covers older firmware that
// exposes only the OEM CfgCD shell and 404s on VM1/CD1.
func TestVmediaRedfishSmc_StatusFallbackToCfgCD(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(smcCD1Path, func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	mux.HandleFunc(smcVirtualMediaPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Image":"https://server/boot.iso","Inserted":true}`))
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	rc := newSmcTestClient(t, server)
	backend := newVmediaRedfishSmc(rc)
	info, err := backend.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if !info.Mounted || info.ImageURL != "https://server/boot.iso" {
		t.Errorf("Status() = %+v, want mounted with HTTPS URL via CfgCD fallback", info)
	}
}

// TestVmediaRedfishSmc_StatusBothMissing confirms ErrVirtualMediaUnsupported
// when neither CD1 nor CfgCD is exposed.
func TestVmediaRedfishSmc_StatusBothMissing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(smcCD1Path, func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	mux.HandleFunc(smcVirtualMediaPath, func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	rc := newSmcTestClient(t, server)
	backend := newVmediaRedfishSmc(rc)
	_, err := backend.Status(context.Background())
	var unsupErr ErrVirtualMediaUnsupported
	if !errors.As(err, &unsupErr) {
		t.Fatalf("Status() returned %T, want ErrVirtualMediaUnsupported", err)
	}
}

func TestVmediaRedfishSmc_Supports(t *testing.T) {
	b := newVmediaRedfishSmc(nil)
	cases := map[MediaProtocol]bool{
		MediaProtocolHTTP:  true,
		MediaProtocolHTTPS: true,
		MediaProtocolCIFS:  true,
		MediaProtocolNFS:   false,
	}
	for proto, want := range cases {
		got := b.Supports(&MediaSpec{Protocol: proto})
		if got != want {
			t.Errorf("Supports(%q) = %v, want %v", proto, got, want)
		}
	}
	if b.Supports(nil) {
		t.Errorf("Supports(nil) = true, want false")
	}
}

func TestSmcDetectLicense(t *testing.T) {
	if smcDetectLicense([]byte(`{"ok":true}`)) != nil {
		t.Errorf("expected nil for non-license body")
	}
	err := smcDetectLicense([]byte(smcLicenseErrorBody))
	var licErr ErrVirtualMediaLicenseRequired
	if !errors.As(err, &licErr) {
		t.Fatalf("smcDetectLicense returned %T, want license error", err)
	}
}

func TestSplitCIFS(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPath string
	}{
		{"cifs://server/share/boot.iso", "server", "/share/boot.iso"},
		{"smb://srv2/share/x.iso", "srv2", "/share/x.iso"},
		{"//srv3/share/x.iso", "srv3", "/share/x.iso"},
		{"srv4/share/x.iso", "srv4", "/share/x.iso"},
		{"srv5", "srv5", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			host, path := splitCIFS(tc.in)
			if host != tc.wantHost || path != tc.wantPath {
				t.Errorf("splitCIFS(%q) = (%q, %q), want (%q, %q)",
					tc.in, host, path, tc.wantHost, tc.wantPath)
			}
		})
	}
}
