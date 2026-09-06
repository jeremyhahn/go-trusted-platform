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
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

func newMCPProvider() *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{})
}

func newMCPProviderWithVTPM(mock *mockVTPMService) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mock,
	})
}

// TestMCPServiceProvider_VTPMStubs verifies VTPM operations with nil service.
func TestMCPServiceProvider_VTPMOps_NilService(t *testing.T) {
	ctx := context.Background()
	p := newMCPProvider()

	nilTests := []struct {
		name string
		fn   func() error
	}{
		{"VTPMGet", func() error { _, err := p.VTPMGet(ctx, "x"); return err }},
		{"VTPMValidate", func() error { _, err := p.VTPMValidate(ctx, "x"); return err }},
		{"VTPMExport", func() error { _, err := p.VTPMExport(ctx, "x"); return err }},
		{"VTPMImport", func() error { _, err := p.VTPMImport(ctx, []byte("x")); return err }},
		{"VTPMCreateTemplate", func() error { _, err := p.VTPMCreateTemplate(ctx, "id", "desc", "RSA", false); return err }},
		{"VTPMGetTemplate", func() error { _, err := p.VTPMGetTemplate(ctx, "id"); return err }},
		{"VTPMDeleteTemplate", func() error { return p.VTPMDeleteTemplate(ctx, "id") }},
		{"VTPMListTemplates", func() error { _, err := p.VTPMListTemplates(ctx); return err }},
		{"VTPMCloneTemplate", func() error { _, err := p.VTPMCloneTemplate(ctx, "tpl", "host", nil); return err }},
		{"VTPMGetBundlePath", func() error { _, err := p.VTPMGetBundlePath(ctx, "x"); return err }},
		{"VTPMGetTPMSocketPath", func() error { _, err := p.VTPMGetTPMSocketPath(ctx, "x"); return err }},
		{"VTPMGetNVRAMPath", func() error { _, err := p.VTPMGetNVRAMPath(ctx, "x"); return err }},
		{"VTPMIsRunning", func() error { _, err := p.VTPMIsRunning(ctx, "x"); return err }},
	}

	for _, tt := range nilTests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if _, ok := err.(ErrServiceNotAvailable); !ok {
				t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}

// TestMCPServiceProvider_VTPMOps_WithMock verifies VTPM delegation happy paths.
func TestMCPServiceProvider_VTPMOps_WithMock(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		getBundleFunc: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			return &vtpm.Bundle{ID: id}, nil
		},
		validateBundleFunc: func(ctx context.Context, id string) error { return nil },
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			_, err := w.Write([]byte("data"))
			return err
		},
		importBundleFunc: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			return &vtpm.Bundle{ID: "imported"}, nil
		},
		createTemplateFunc: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			return &vtpm.Template{ID: opts.ID}, nil
		},
		getTemplateFunc: func(ctx context.Context, id string) (*vtpm.Template, error) {
			return &vtpm.Template{ID: id}, nil
		},
		deleteTemplateFunc: func(ctx context.Context, id string) error { return nil },
		listTemplatesFunc:  func(ctx context.Context) ([]*vtpm.Template, error) { return []*vtpm.Template{{ID: "t1"}}, nil },
		cloneTemplateFunc: func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			return &vtpm.Bundle{ID: opts.Hostname}, nil
		},
		getBundlePathFunc:    func(id string) string { return "/path/" + id },
		getTPMSocketPathFunc: func(id string) string { return "/sock/" + id },
		getNVRAMPathFunc:     func(id string) string { return "/nvram/" + id },
		isRunningFunc:        func(bundleID string) bool { return true },
	}
	p := newMCPProviderWithVTPM(mock)

	t.Run("VTPMGet", func(t *testing.T) {
		result, err := p.VTPMGet(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("VTPMValidate_Valid", func(t *testing.T) {
		result, err := p.VTPMValidate(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["valid"] != true {
			t.Error("expected valid=true")
		}
	})

	t.Run("VTPMValidate_Invalid", func(t *testing.T) {
		mock2 := &mockVTPMService{
			validateBundleFunc: func(ctx context.Context, id string) error { return errors.New("bad") },
		}
		p2 := newMCPProviderWithVTPM(mock2)
		result, err := p2.VTPMValidate(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["valid"] != false {
			t.Error("expected valid=false")
		}
	})

	t.Run("VTPMExport", func(t *testing.T) {
		result, err := p.VTPMExport(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["id"] != "b1" {
			t.Errorf("expected id=b1, got %v", m["id"])
		}
	})

	t.Run("VTPMImport", func(t *testing.T) {
		_, err := p.VTPMImport(ctx, []byte("archive"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMCreateTemplate_RSA", func(t *testing.T) {
		_, err := p.VTPMCreateTemplate(ctx, "tpl1", "desc", "RSA", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMCreateTemplate_ECC", func(t *testing.T) {
		_, err := p.VTPMCreateTemplate(ctx, "tpl2", "desc", "ECC", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMGetTemplate", func(t *testing.T) {
		_, err := p.VTPMGetTemplate(ctx, "tpl1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMDeleteTemplate", func(t *testing.T) {
		err := p.VTPMDeleteTemplate(ctx, "tpl1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMListTemplates", func(t *testing.T) {
		_, err := p.VTPMListTemplates(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMCloneTemplate", func(t *testing.T) {
		_, err := p.VTPMCloneTemplate(ctx, "tpl1", "host1", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("VTPMGetBundlePath", func(t *testing.T) {
		result, err := p.VTPMGetBundlePath(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["path"] != "/path/b1" {
			t.Errorf("unexpected path: %v", m["path"])
		}
	})

	t.Run("VTPMGetTPMSocketPath", func(t *testing.T) {
		result, err := p.VTPMGetTPMSocketPath(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["path"] != "/sock/b1" {
			t.Errorf("unexpected path: %v", m["path"])
		}
	})

	t.Run("VTPMGetNVRAMPath", func(t *testing.T) {
		result, err := p.VTPMGetNVRAMPath(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["path"] != "/nvram/b1" {
			t.Errorf("unexpected path: %v", m["path"])
		}
	})

	t.Run("VTPMIsRunning", func(t *testing.T) {
		result, err := p.VTPMIsRunning(ctx, "b1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["running"] != true {
			t.Error("expected running=true")
		}
	})
}

// TestMCPServiceProvider_DaemonOps_NilService verifies daemon operations with nil health service.
func TestMCPServiceProvider_DaemonOps_NilService(t *testing.T) {
	ctx := context.Background()
	p := newMCPProvider()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"DaemonStatus", func() error { _, err := p.DaemonStatus(ctx); return err }},
		{"DaemonVersion", func() error { _, err := p.DaemonVersion(ctx); return err }},
		{"DaemonListServices", func() error { _, err := p.DaemonListServices(ctx); return err }},
		{"DaemonGetService", func() error { _, err := p.DaemonGetService(ctx, "ca"); return err }},
		{"DaemonStartService", func() error { _, err := p.DaemonStartService(ctx, "ca"); return err }},
		{"DaemonStopService", func() error { _, err := p.DaemonStopService(ctx, "ca"); return err }},
		{"DaemonRestartService", func() error { _, err := p.DaemonRestartService(ctx, "ca"); return err }},
		{"DaemonListProtocols", func() error { _, err := p.DaemonListProtocols(ctx); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if _, ok := err.(ErrServiceNotAvailable); !ok {
				t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
		})
	}
}

// TestMCPServiceProvider_OverlayStubs verifies overlay stub methods.
func TestMCPServiceProvider_OverlayStubs(t *testing.T) {
	ctx := context.Background()
	p := newMCPProvider()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"OverlayStatus", func() error { _, err := p.OverlayStatus(ctx); return err }},
		{"OverlayVTEPList", func() error { _, err := p.OverlayVTEPList(ctx); return err }},
		{"OverlayVTEPGet", func() error { _, err := p.OverlayVTEPGet(ctx, "n1"); return err }},
		{"OverlayVNIList", func() error { _, err := p.OverlayVNIList(ctx); return err }},
		{"OverlayVNICreate", func() error { _, err := p.OverlayVNICreate(ctx, 100, 10, "t"); return err }},
		{"OverlayVNIDelete", func() error { return p.OverlayVNIDelete(ctx, 100) }},
		{"OverlayTunnelList", func() error { _, err := p.OverlayTunnelList(ctx, 100); return err }},
		{"OverlayMACList", func() error { _, err := p.OverlayMACList(ctx, 100); return err }},
		{"OverlayMACForget", func() error { return p.OverlayMACForget(ctx, "aa:bb:cc:dd:ee:ff", 100) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestMCPServiceProvider_GatewayStubs verifies gateway stub methods.
func TestMCPServiceProvider_GatewayStubs(t *testing.T) {
	ctx := context.Background()
	p := newMCPProvider()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GatewayStatus", func() error { _, err := p.GatewayStatus(ctx); return err }},
		{"GatewayModeSet", func() error { _, err := p.GatewayModeSet(ctx, []string{"router"}); return err }},
		{"GatewayBGPStatus", func() error { _, err := p.GatewayBGPStatus(ctx); return err }},
		{"GatewayBGPPeers", func() error { _, err := p.GatewayBGPPeers(ctx); return err }},
		{"GatewayBGPAnnounce", func() error { return p.GatewayBGPAnnounce(ctx, "10.0.0.0/24", "10.0.0.1") }},
		{"GatewayBGPWithdraw", func() error { return p.GatewayBGPWithdraw(ctx, "10.0.0.0/24") }},
		{"GatewayBGPPrefixes", func() error { _, err := p.GatewayBGPPrefixes(ctx); return err }},
		{"GatewayIPAMPools", func() error { _, err := p.GatewayIPAMPools(ctx, ""); return err }},
		{"GatewayIPAMAllocate", func() error { _, err := p.GatewayIPAMAllocate(ctx, "p", "d", "h"); return err }},
		{"GatewayIPAMRelease", func() error { return p.GatewayIPAMRelease(ctx, "10.0.0.5") }},
		{"GatewayIPAMAllocations", func() error { _, err := p.GatewayIPAMAllocations(ctx, "p"); return err }},
		{"GatewayIPAMPoolCreate", func() error { _, err := p.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{}); return err }},
		{"GatewayIPAMPoolDelete", func() error { return p.GatewayIPAMPoolDelete(ctx, "p1") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestMCPServiceProvider_TPMStubs verifies TPM stub methods.
func TestMCPServiceProvider_TPMStubs(t *testing.T) {
	ctx := context.Background()
	p := newMCPProvider()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"TPMInfo", func() error { _, err := p.TPMInfo(ctx); return err }},
		{"TPMProvision", func() error { _, err := p.TPMProvision(ctx, "pw"); return err }},
		{"TPMClear", func() error { _, err := p.TPMClear(ctx, "pw"); return err }},
		{"TPMGetEK", func() error { _, err := p.TPMGetEK(ctx); return err }},
		{"TPMGetEKCert", func() error { _, err := p.TPMGetEKCert(ctx); return err }},
		{"TPMImportEKCert", func() error { _, err := p.TPMImportEKCert(ctx, []byte("c")); return err }},
		{"TPMCreateEK", func() error { _, err := p.TPMCreateEK(ctx); return err }},
		{"TPMDeleteEK", func() error { _, err := p.TPMDeleteEK(ctx); return err }},
		{"TPMGetSRK", func() error { _, err := p.TPMGetSRK(ctx, 0); return err }},
		{"TPMCreateSRK", func() error { _, err := p.TPMCreateSRK(ctx); return err }},
		{"TPMDeleteSRK", func() error { _, err := p.TPMDeleteSRK(ctx); return err }},
		{"TPMGetIAK", func() error { _, err := p.TPMGetIAK(ctx); return err }},
		{"TPMCreateIAK", func() error { _, err := p.TPMCreateIAK(ctx); return err }},
		{"TPMDeleteIAK", func() error { _, err := p.TPMDeleteIAK(ctx); return err }},
		{"TPMQuote", func() error { _, err := p.TPMQuote(ctx, []byte("n"), []int{0}); return err }},
		{"TPMVerifyQuote", func() error { _, err := p.TPMVerifyQuote(ctx, []byte("q"), []byte("s"), []byte("n")); return err }},
		{"TPMReadPCRs", func() error { _, err := p.TPMReadPCRs(ctx, []int{0}); return err }},
		{"TPMExtendPCR", func() error { _, err := p.TPMExtendPCR(ctx, 0, []byte("d")); return err }},
		{"TPMEventLog", func() error { _, err := p.TPMEventLog(ctx); return err }},
		{"TPMCapabilities", func() error { _, err := p.TPMCapabilities(ctx); return err }},
		{"TPMRandom", func() error { _, err := p.TPMRandom(ctx, 32); return err }},
		{"TPMSeal", func() error { _, err := p.TPMSeal(ctx, []byte("d"), []int{0}); return err }},
		{"TPMUnseal", func() error { _, err := p.TPMUnseal(ctx, "cn"); return err }},
		{"TPMCertify", func() error { _, err := p.TPMCertify(ctx, 1); return err }},
		{"TPMNVList", func() error { _, err := p.TPMNVList(ctx); return err }},
		{"TPMNVRead", func() error { _, err := p.TPMNVRead(ctx, 1, 32); return err }},
		{"TPMNVWrite", func() error { _, err := p.TPMNVWrite(ctx, 1, []byte("d")); return err }},
		{"TPMNVDelete", func() error { _, err := p.TPMNVDelete(ctx, 1); return err }},
		{"TPMPlatform", func() error { _, err := p.TPMPlatform(ctx); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error for nil TPM service")
			}
		})
	}
}
