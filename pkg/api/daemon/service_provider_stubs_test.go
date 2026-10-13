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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// TestPlatformServiceProvider_IDevIDStubs verifies all IDevID stub methods
// return ErrTPM2ServiceNotAvailable.
func TestPlatformServiceProvider_IDevIDStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("IDevIDGenerate", func(t *testing.T) {
		_, err := provider.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{})
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDInfo", func(t *testing.T) {
		_, err := provider.IDevIDInfo(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDDelete", func(t *testing.T) {
		err := provider.IDevIDDelete(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDCSR", func(t *testing.T) {
		_, err := provider.IDevIDCSR(ctx, &mcp.IDevIDCSRMCPRequest{})
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDInstallCert", func(t *testing.T) {
		_, err := provider.IDevIDInstallCert(ctx, "-----BEGIN CERTIFICATE-----")
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDGetCert", func(t *testing.T) {
		_, err := provider.IDevIDGetCert(ctx, true)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDDeleteCert", func(t *testing.T) {
		err := provider.IDevIDDeleteCert(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IDevIDExists", func(t *testing.T) {
		exists, err := provider.IDevIDExists(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
		if exists {
			t.Error("expected exists=false for stub")
		}
	})
}

// TestPlatformServiceProvider_IAKStubs verifies all IAK stub methods
// return ErrTPM2ServiceNotAvailable.
func TestPlatformServiceProvider_IAKStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("IAKGenerate", func(t *testing.T) {
		_, err := provider.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{})
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKInfo", func(t *testing.T) {
		_, err := provider.IAKInfo(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKDelete", func(t *testing.T) {
		err := provider.IAKDelete(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKCSR", func(t *testing.T) {
		_, err := provider.IAKCSR(ctx, &mcp.IDevIDCSRMCPRequest{})
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKInstallCert", func(t *testing.T) {
		_, err := provider.IAKInstallCert(ctx, "-----BEGIN CERTIFICATE-----")
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKGetCert", func(t *testing.T) {
		_, err := provider.IAKGetCert(ctx, true)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKDeleteCert", func(t *testing.T) {
		err := provider.IAKDeleteCert(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAKExists", func(t *testing.T) {
		exists, err := provider.IAKExists(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
		if exists {
			t.Error("expected exists=false for stub")
		}
	})
}

// TestPlatformServiceProvider_DeviceAttributeStubs verifies device attribute stubs.
func TestPlatformServiceProvider_DeviceAttributeStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("DeviceAttributes", func(t *testing.T) {
		_, err := provider.DeviceAttributes(ctx)
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ActivateCredential", func(t *testing.T) {
		_, err := provider.ActivateCredential(ctx, []byte("blob"), []byte("secret"))
		if _, ok := err.(ErrTPM2ServiceNotAvailable); !ok {
			t.Errorf("expected ErrTPM2ServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// TestPlatformServiceProvider_OverlayStubs verifies all overlay stub methods
// return ErrOverlayOperationNotImplemented.
func TestPlatformServiceProvider_OverlayStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	tests := []struct {
		name string
		fn   func() error
	}{
		{"OverlayStatus", func() error { _, err := provider.OverlayStatus(ctx); return err }},
		{"OverlayVTEPList", func() error { _, err := provider.OverlayVTEPList(ctx); return err }},
		{"OverlayVTEPGet", func() error { _, err := provider.OverlayVTEPGet(ctx, "node1"); return err }},
		{"OverlayVNIList", func() error { _, err := provider.OverlayVNIList(ctx); return err }},
		{"OverlayVNICreate", func() error { _, err := provider.OverlayVNICreate(ctx, 100, 10, "test"); return err }},
		{"OverlayVNIDelete", func() error { return provider.OverlayVNIDelete(ctx, 100) }},
		{"OverlayTunnelList", func() error { _, err := provider.OverlayTunnelList(ctx, 100); return err }},
		{"OverlayMACList", func() error { _, err := provider.OverlayMACList(ctx, 100); return err }},
		{"OverlayMACForget", func() error { return provider.OverlayMACForget(ctx, "00:11:22:33:44:55", 100) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if _, ok := err.(ErrOverlayOperationNotImplemented); !ok {
				t.Errorf("expected ErrOverlayOperationNotImplemented, got %T: %v", err, err)
			}
		})
	}
}

// TestPlatformServiceProvider_GatewayBGPUnwired pins the BGP tools on a
// provider with no gateway service wired: each answers that the gateway
// service is not available, not that it is unimplemented (#65).
func TestPlatformServiceProvider_GatewayBGPUnwired(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GatewayBGPStatus", func() error { _, err := provider.GatewayBGPStatus(ctx); return err }},
		{"GatewayBGPPeers", func() error { _, err := provider.GatewayBGPPeers(ctx); return err }},
		{"GatewayBGPAnnounce", func() error { return provider.GatewayBGPAnnounce(ctx, "10.0.0.0/24", "10.0.0.1") }},
		{"GatewayBGPWithdraw", func() error { return provider.GatewayBGPWithdraw(ctx, "10.0.0.0/24") }},
		{"GatewayBGPPrefixes", func() error { _, err := provider.GatewayBGPPrefixes(ctx); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err != (ErrServiceNotAvailable{Service: "gateway"}) {
				t.Errorf("expected ErrServiceNotAvailable{gateway}, got %T: %v", err, err)
			}
		})
	}
}

// TestPlatformServiceProvider_GatewayToolsUnwired checks that the status,
// mode and IPAM tools are real (#65): with no gateway service or allocator
// wired they report the missing service rather than a stub.
func TestPlatformServiceProvider_GatewayToolsUnwired(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	tests := []struct {
		name    string
		service string
		fn      func() error
	}{
		{"GatewayStatus", "gateway", func() error { _, err := provider.GatewayStatus(ctx); return err }},
		{"GatewayModeSet", "gateway", func() error { _, err := provider.GatewayModeSet(ctx, []string{"edge"}); return err }},
		{"GatewayIPAMPools", "ipam", func() error { _, err := provider.GatewayIPAMPools(ctx, ""); return err }},
		{"GatewayIPAMPoolGet", "ipam", func() error { _, err := provider.GatewayIPAMPoolGet(ctx, "pool1"); return err }},
		{"GatewayIPAMAllocate", "ipam", func() error {
			_, err := provider.GatewayIPAMAllocate(ctx, "pool1", "dev1", "host1")
			return err
		}},
		{"GatewayIPAMRelease", "ipam", func() error { return provider.GatewayIPAMRelease(ctx, "10.0.0.5") }},
		{"GatewayIPAMAllocations", "ipam", func() error {
			_, err := provider.GatewayIPAMAllocations(ctx, "pool1")
			return err
		}},
		{"GatewayIPAMPoolCreate", "ipam", func() error {
			_, err := provider.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{})
			return err
		}},
		{"GatewayIPAMPoolUpdate", "ipam", func() error {
			_, err := provider.GatewayIPAMPoolUpdate(ctx, "pool1", &mcp.IPAMPoolUpdateRequest{})
			return err
		}},
		{"GatewayIPAMPoolDelete", "ipam", func() error { return provider.GatewayIPAMPoolDelete(ctx, "pool1") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			var notAvailable ErrServiceNotAvailable
			if !errors.As(err, &notAvailable) || notAvailable.Service != tt.service {
				t.Errorf("expected ErrServiceNotAvailable{%q}, got %T: %v", tt.service, err, err)
			}
		})
	}
}

// TestPlatformServiceProvider_TPMStubs verifies all TPM stub methods
// return ErrTPMOperationNotImplemented.
func TestPlatformServiceProvider_TPMStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	tests := []struct {
		name string
		fn   func() error
	}{
		{"TPMInfo", func() error { _, err := provider.TPMInfo(ctx); return err }},
		{"TPMProvision", func() error { _, err := provider.TPMProvision(ctx, "password"); return err }},
		{"TPMClear", func() error { _, err := provider.TPMClear(ctx, "password"); return err }},
		{"TPMGetEK", func() error { _, err := provider.TPMGetEK(ctx); return err }},
		{"TPMGetEKCert", func() error { _, err := provider.TPMGetEKCert(ctx); return err }},
		{"TPMImportEKCert", func() error { _, err := provider.TPMImportEKCert(ctx, []byte("cert")); return err }},
		{"TPMCreateEK", func() error { _, err := provider.TPMCreateEK(ctx); return err }},
		{"TPMDeleteEK", func() error { _, err := provider.TPMDeleteEK(ctx); return err }},
		{"TPMGetSRK", func() error { _, err := provider.TPMGetSRK(ctx, 0); return err }},
		{"TPMCreateSRK", func() error { _, err := provider.TPMCreateSRK(ctx); return err }},
		{"TPMDeleteSRK", func() error { _, err := provider.TPMDeleteSRK(ctx); return err }},
		{"TPMGetIAK", func() error { _, err := provider.TPMGetIAK(ctx); return err }},
		{"TPMCreateIAK", func() error { _, err := provider.TPMCreateIAK(ctx); return err }},
		{"TPMDeleteIAK", func() error { _, err := provider.TPMDeleteIAK(ctx); return err }},
		{"TPMQuote", func() error { _, err := provider.TPMQuote(ctx, []byte("nonce"), []int{0, 1}); return err }},
		{"TPMVerifyQuote", func() error {
			_, err := provider.TPMVerifyQuote(ctx, []byte("q"), []byte("s"), []byte("n"), nil)
			return err
		}},
		{"TPMReadPCRs", func() error { _, err := provider.TPMReadPCRs(ctx, []int{0, 1}); return err }},
		{"TPMExtendPCR", func() error { _, err := provider.TPMExtendPCR(ctx, 0, []byte("data")); return err }},
		{"TPMEventLog", func() error { _, err := provider.TPMEventLog(ctx); return err }},
		{"TPMCapabilities", func() error { _, err := provider.TPMCapabilities(ctx); return err }},
		{"TPMRandom", func() error { _, err := provider.TPMRandom(ctx, 32); return err }},
		{"TPMSeal", func() error { _, err := provider.TPMSeal(ctx, []byte("data"), []int{0}); return err }},
		{"TPMUnseal", func() error { _, err := provider.TPMUnseal(ctx, "cn"); return err }},
		{"TPMCertify", func() error { _, err := provider.TPMCertify(ctx, 0x81000001); return err }},
		{"TPMNVList", func() error { _, err := provider.TPMNVList(ctx); return err }},
		{"TPMNVRead", func() error { _, err := provider.TPMNVRead(ctx, 0x1500000, 32); return err }},
		{"TPMNVWrite", func() error { _, err := provider.TPMNVWrite(ctx, 0x1500000, []byte("data")); return err }},
		{"TPMNVDelete", func() error { _, err := provider.TPMNVDelete(ctx, 0x1500000); return err }},
		{"TPMPlatform", func() error { _, err := provider.TPMPlatform(ctx); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if _, ok := err.(ErrTPMOperationNotImplemented); !ok {
				t.Errorf("expected ErrTPMOperationNotImplemented, got %T: %v", err, err)
			}
		})
	}
}

// TestPlatformServiceProvider_IAMGroupTenantTokenStubs verifies remaining
// IAM stub methods that were not covered by previous tests.
func TestPlatformServiceProvider_IAMGroupTenantTokenStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("IAMCreateGroup", func(t *testing.T) {
		_, err := provider.IAMCreateGroup(ctx, &mcp.IAMCreateGroupRequest{})
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMDeleteGroup", func(t *testing.T) {
		err := provider.IAMDeleteGroup(ctx, "tenant1", "group1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMGetGroup", func(t *testing.T) {
		_, err := provider.IAMGetGroup(ctx, "tenant1", "group1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMListGroups", func(t *testing.T) {
		_, err := provider.IAMListGroups(ctx, "tenant1", 10, 0)
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMAddGroupMember", func(t *testing.T) {
		err := provider.IAMAddGroupMember(ctx, "tenant1", "group1", "user1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMRemoveGroupMember", func(t *testing.T) {
		err := provider.IAMRemoveGroupMember(ctx, "tenant1", "group1", "user1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMCreateTenant", func(t *testing.T) {
		_, err := provider.IAMCreateTenant(ctx, &mcp.IAMCreateTenantRequest{})
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMDeleteTenant", func(t *testing.T) {
		err := provider.IAMDeleteTenant(ctx, "tenant1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMGetTenant", func(t *testing.T) {
		_, err := provider.IAMGetTenant(ctx, "tenant1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMListTenants", func(t *testing.T) {
		_, err := provider.IAMListTenants(ctx, 10, 0)
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMCreateToken", func(t *testing.T) {
		_, err := provider.IAMCreateToken(ctx, &mcp.IAMCreateTokenRequest{})
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMRevokeToken", func(t *testing.T) {
		err := provider.IAMRevokeToken(ctx, "token1")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("IAMVerifyToken", func(t *testing.T) {
		_, err := provider.IAMVerifyToken(ctx, "token-string")
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// TestPlatformServiceProvider_ContainerStubs verifies all container stub methods.
func TestPlatformServiceProvider_ContainerStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("ContainerCreate", func(t *testing.T) {
		_, err := provider.ContainerCreate(ctx, "test-container", "nginx:latest", nil)
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerStart", func(t *testing.T) {
		err := provider.ContainerStart(ctx, "container1")
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerStop", func(t *testing.T) {
		err := provider.ContainerStop(ctx, "container1", 10)
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerRemove", func(t *testing.T) {
		err := provider.ContainerRemove(ctx, "container1", false)
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerGet", func(t *testing.T) {
		_, err := provider.ContainerGet(ctx, "container1")
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerList", func(t *testing.T) {
		_, err := provider.ContainerList(ctx, true, nil, 10)
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerLogs", func(t *testing.T) {
		_, err := provider.ContainerLogs(ctx, "container1", false, true, true, "100", false)
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("ContainerAttest", func(t *testing.T) {
		_, err := provider.ContainerAttest(ctx, "container1")
		if _, ok := err.(ErrContainerServiceNotAvailable); !ok {
			t.Errorf("expected ErrContainerServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

// TestPlatformServiceProvider_KMSGenerateDataKeyStubs verifies remaining KMS stubs.
func TestPlatformServiceProvider_KMSGenerateDataKeyStubs(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("KMSGenerateDataKey", func(t *testing.T) {
		_, err := provider.KMSGenerateDataKey(ctx, &mcp.KMSGenerateDataKeyRequest{})
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})

	t.Run("KMSGenerateWrappedDataKey", func(t *testing.T) {
		_, err := provider.KMSGenerateWrappedDataKey(ctx, &mcp.KMSGenerateWrappedDataKeyRequest{})
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}
