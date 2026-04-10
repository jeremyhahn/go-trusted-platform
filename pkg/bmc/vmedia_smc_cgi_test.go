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
	"testing"
)

// TestVmediaSmcCGI_StubReturnsUnsupported is the canary test that fails
// the moment a real SMC CGI implementation is wired in. When that happens,
// flip these assertions to exercise the real protocol against an httptest
// server replaying the captured iKVM HAR. See vmedia_smc_cgi.go for the
// HAR capture procedure.
func TestVmediaSmcCGI_StubReturnsUnsupported(t *testing.T) {
	b := newVmediaSmcCGI(nil)
	spec := &MediaSpec{URL: "cifs://server/share/boot.iso", Protocol: MediaProtocolCIFS}

	t.Run("Mount", func(t *testing.T) {
		err := b.Mount(context.Background(), spec)
		assertUnsupported(t, err)
	})

	t.Run("Unmount", func(t *testing.T) {
		err := b.Unmount(context.Background())
		assertUnsupported(t, err)
	})

	t.Run("Status", func(t *testing.T) {
		_, err := b.Status(context.Background())
		assertUnsupported(t, err)
	})
}

func TestVmediaSmcCGI_SupportsCIFSOnly(t *testing.T) {
	b := newVmediaSmcCGI(nil)
	cases := map[MediaProtocol]bool{
		MediaProtocolCIFS:  true,
		MediaProtocolHTTP:  false,
		MediaProtocolHTTPS: false,
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

func TestVmediaSmcCGI_Name(t *testing.T) {
	b := newVmediaSmcCGI(nil)
	if b.Name() != "smc-cgi" {
		t.Errorf("Name() = %q, want %q", b.Name(), "smc-cgi")
	}
}

func assertUnsupported(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected ErrVirtualMediaUnsupported, got nil")
	}
	var unsupErr ErrVirtualMediaUnsupported
	if !errors.As(err, &unsupErr) {
		t.Fatalf("err = %T, want ErrVirtualMediaUnsupported", err)
	}
	if unsupErr.Backend != "smc-cgi" {
		t.Errorf("backend = %q, want smc-cgi", unsupErr.Backend)
	}
	if unsupErr.Vendor != "Supermicro" {
		t.Errorf("vendor = %q, want Supermicro", unsupErr.Vendor)
	}
}
