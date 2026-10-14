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

package mcp

import (
	"context"
	"encoding/base64"
	"testing"
)

// errorServiceProvider wraps mockServiceProvider and makes specific methods return errors.
type errorServiceProvider struct {
	*mockServiceProvider
	failMethods map[string]bool
}

func newErrorServiceProvider(failMethods ...string) *errorServiceProvider {
	e := &errorServiceProvider{
		mockServiceProvider: newMockServiceProvider(),
		failMethods:         make(map[string]bool),
	}
	for _, m := range failMethods {
		e.failMethods[m] = true
	}
	return e
}

func (e *errorServiceProvider) shouldFail(method string) bool {
	return e.failMethods[method]
}

// Overlay overrides
func (e *errorServiceProvider) OverlayStatus(ctx context.Context) (interface{}, error) {
	if e.shouldFail("OverlayStatus") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayStatus(ctx)
}

func (e *errorServiceProvider) OverlayVTEPList(ctx context.Context) ([]interface{}, error) {
	if e.shouldFail("OverlayVTEPList") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayVTEPList(ctx)
}

func (e *errorServiceProvider) OverlayVTEPGet(ctx context.Context, nodeID string) (interface{}, error) {
	if e.shouldFail("OverlayVTEPGet") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayVTEPGet(ctx, nodeID)
}

func (e *errorServiceProvider) OverlayVNIList(ctx context.Context) ([]interface{}, error) {
	if e.shouldFail("OverlayVNIList") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayVNIList(ctx)
}

func (e *errorServiceProvider) OverlayVNICreate(ctx context.Context, vni uint32, vlan uint16, name string) (interface{}, error) {
	if e.shouldFail("OverlayVNICreate") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayVNICreate(ctx, vni, vlan, name)
}

func (e *errorServiceProvider) OverlayVNIDelete(ctx context.Context, vni uint32) error {
	if e.shouldFail("OverlayVNIDelete") {
		return ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayVNIDelete(ctx, vni)
}

func (e *errorServiceProvider) OverlayTunnelList(ctx context.Context, vni uint32) ([]interface{}, error) {
	if e.shouldFail("OverlayTunnelList") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayTunnelList(ctx, vni)
}

func (e *errorServiceProvider) OverlayTunnelStats(ctx context.Context, remoteVTEP string, vni uint32) (interface{}, error) {
	if e.shouldFail("OverlayTunnelStats") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayTunnelStats(ctx, remoteVTEP, vni)
}

func (e *errorServiceProvider) OverlayMACList(ctx context.Context, vni uint32) ([]interface{}, error) {
	if e.shouldFail("OverlayMACList") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayMACList(ctx, vni)
}

func (e *errorServiceProvider) OverlayMACForget(ctx context.Context, mac string, vni uint32) error {
	if e.shouldFail("OverlayMACForget") {
		return ErrMockServiceError
	}
	return e.mockServiceProvider.OverlayMACForget(ctx, mac, vni)
}

// Gateway overrides
func (e *errorServiceProvider) GatewayStatus(ctx context.Context) (interface{}, error) {
	if e.shouldFail("GatewayStatus") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayStatus(ctx)
}

func (e *errorServiceProvider) GatewaySnapshot(ctx context.Context, gatewayID string) (interface{}, error) {
	if e.shouldFail("GatewaySnapshot") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewaySnapshot(ctx, gatewayID)
}

func (e *errorServiceProvider) GatewaySnapshots(ctx context.Context) ([]interface{}, error) {
	if e.shouldFail("GatewaySnapshots") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewaySnapshots(ctx)
}

func (e *errorServiceProvider) GatewayModeSet(ctx context.Context, modes []string) (interface{}, error) {
	if e.shouldFail("GatewayModeSet") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayModeSet(ctx, modes)
}

func (e *errorServiceProvider) GatewayBGPStatus(ctx context.Context) (interface{}, error) {
	if e.shouldFail("GatewayBGPStatus") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayBGPStatus(ctx)
}

func (e *errorServiceProvider) GatewayBGPPeers(ctx context.Context) ([]interface{}, error) {
	if e.shouldFail("GatewayBGPPeers") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayBGPPeers(ctx)
}

func (e *errorServiceProvider) GatewayBGPAnnounce(ctx context.Context, prefix string, nextHop string) error {
	if e.shouldFail("GatewayBGPAnnounce") {
		return ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayBGPAnnounce(ctx, prefix, nextHop)
}

func (e *errorServiceProvider) GatewayBGPWithdraw(ctx context.Context, prefix string) error {
	if e.shouldFail("GatewayBGPWithdraw") {
		return ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayBGPWithdraw(ctx, prefix)
}

func (e *errorServiceProvider) GatewayBGPPrefixes(ctx context.Context) ([]interface{}, error) {
	if e.shouldFail("GatewayBGPPrefixes") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayBGPPrefixes(ctx)
}

func (e *errorServiceProvider) GatewayIPAMPools(ctx context.Context, zone string) ([]interface{}, error) {
	if e.shouldFail("GatewayIPAMPools") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMPools(ctx, zone)
}

func (e *errorServiceProvider) GatewayIPAMPoolGet(ctx context.Context, poolID string) (interface{}, error) {
	if e.shouldFail("GatewayIPAMPoolGet") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMPoolGet(ctx, poolID)
}

func (e *errorServiceProvider) GatewayIPAMPoolCreate(ctx context.Context, req *IPAMPoolCreateRequest) (interface{}, error) {
	if e.shouldFail("GatewayIPAMPoolCreate") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMPoolCreate(ctx, req)
}

func (e *errorServiceProvider) GatewayIPAMPoolUpdate(ctx context.Context, poolID string, req *IPAMPoolUpdateRequest) (interface{}, error) {
	if e.shouldFail("GatewayIPAMPoolUpdate") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMPoolUpdate(ctx, poolID, req)
}

func (e *errorServiceProvider) GatewayIPAMPoolDelete(ctx context.Context, poolID string) error {
	if e.shouldFail("GatewayIPAMPoolDelete") {
		return ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMPoolDelete(ctx, poolID)
}

func (e *errorServiceProvider) GatewayIPAMRelease(ctx context.Context, ip string) error {
	if e.shouldFail("GatewayIPAMRelease") {
		return ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMRelease(ctx, ip)
}

func (e *errorServiceProvider) GatewayIPAMAllocations(ctx context.Context, poolID string) ([]interface{}, error) {
	if e.shouldFail("GatewayIPAMAllocations") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.GatewayIPAMAllocations(ctx, poolID)
}

// TPM overrides
func (e *errorServiceProvider) TPMInfo(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMInfo") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMInfo(ctx)
}

func (e *errorServiceProvider) TPMGetEK(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMGetEK") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMGetEK(ctx)
}

func (e *errorServiceProvider) TPMGetEKCert(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMGetEKCert") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMGetEKCert(ctx)
}

func (e *errorServiceProvider) TPMEventLog(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMEventLog") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMEventLog(ctx)
}

func (e *errorServiceProvider) TPMCapabilities(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMCapabilities") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMCapabilities(ctx)
}

func (e *errorServiceProvider) TPMRandom(ctx context.Context, numBytes int) ([]byte, error) {
	if e.shouldFail("TPMRandom") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMRandom(ctx, numBytes)
}

func (e *errorServiceProvider) TPMNVList(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMNVList") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMNVList(ctx)
}

func (e *errorServiceProvider) TPMNVRead(ctx context.Context, index uint32, size, offset uint16, password string) ([]byte, error) {
	if e.shouldFail("TPMNVRead") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMNVRead(ctx, index, size, offset, password)
}

func (e *errorServiceProvider) TPMNVDelete(ctx context.Context, index uint32, parentPassword string) (interface{}, error) {
	if e.shouldFail("TPMNVDelete") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMNVDelete(ctx, index, parentPassword)
}

func (e *errorServiceProvider) TPMPlatform(ctx context.Context) (interface{}, error) {
	if e.shouldFail("TPMPlatform") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMPlatform(ctx)
}

func (e *errorServiceProvider) TPMCertify(ctx context.Context, keyHandle int) (interface{}, error) {
	if e.shouldFail("TPMCertify") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMCertify(ctx, keyHandle)
}

func (e *errorServiceProvider) TPMUnseal(ctx context.Context, cn string) ([]byte, error) {
	if e.shouldFail("TPMUnseal") {
		return nil, ErrMockServiceError
	}
	return e.mockServiceProvider.TPMUnseal(ctx, cn)
}

func TestServiceErrorPaths(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	tests := []struct {
		name       string
		toolName   string
		args       map[string]interface{}
		failMethod string
	}{
		// Overlay errors
		{"overlay_status error", "overlay_status", map[string]interface{}{}, "OverlayStatus"},
		{"overlay_vtep_list error", "overlay_vtep_list", map[string]interface{}{}, "OverlayVTEPList"},
		{"overlay_vtep_get error", "overlay_vtep_get", map[string]interface{}{"node_id": "n1"}, "OverlayVTEPGet"},
		{"overlay_vni_list error", "overlay_vni_list", map[string]interface{}{}, "OverlayVNIList"},
		{"overlay_vni_create error", "overlay_vni_create", map[string]interface{}{"vni": float64(100)}, "OverlayVNICreate"},
		{"overlay_vni_delete error", "overlay_vni_delete", map[string]interface{}{"vni": float64(100)}, "OverlayVNIDelete"},
		{"overlay_tunnel_list error", "overlay_tunnel_list", map[string]interface{}{"vni": float64(100)}, "OverlayTunnelList"},
		{"overlay_tunnel_stats error", "overlay_tunnel_stats", map[string]interface{}{"remote_vtep": "10.0.0.2"}, "OverlayTunnelStats"},
		{"overlay_mac_list error", "overlay_mac_list", map[string]interface{}{"vni": float64(100)}, "OverlayMACList"},
		{"overlay_mac_forget error", "overlay_mac_forget", map[string]interface{}{"mac": "aa:bb:cc:dd:ee:ff", "vni": float64(100)}, "OverlayMACForget"},

		// Gateway errors
		{"gateway_status error", "gateway_status", map[string]interface{}{}, "GatewayStatus"},
		{"gateway_snapshot error", "gateway_snapshot", map[string]interface{}{}, "GatewaySnapshot"},
		{"gateway_snapshots error", "gateway_snapshots", map[string]interface{}{}, "GatewaySnapshots"},
		{"gateway_mode_set error", "gateway_mode_set", map[string]interface{}{"modes": []interface{}{"router"}}, "GatewayModeSet"},
		{"gateway_bgp_status error", "gateway_bgp_status", map[string]interface{}{}, "GatewayBGPStatus"},
		{"gateway_bgp_peers error", "gateway_bgp_peers", map[string]interface{}{}, "GatewayBGPPeers"},
		{"gateway_bgp_announce error", "gateway_bgp_announce", map[string]interface{}{"prefix": "10.0.0.0/24"}, "GatewayBGPAnnounce"},
		{"gateway_bgp_withdraw error", "gateway_bgp_withdraw", map[string]interface{}{"prefix": "10.0.0.0/24"}, "GatewayBGPWithdraw"},
		{"gateway_bgp_prefixes error", "gateway_bgp_prefixes", map[string]interface{}{}, "GatewayBGPPrefixes"},
		{"gateway_ipam_pools error", "gateway_ipam_pools", map[string]interface{}{}, "GatewayIPAMPools"},
		{"gateway_ipam_pool_delete error", "gateway_ipam_pool_delete", map[string]interface{}{"pool_id": "p1"}, "GatewayIPAMPoolDelete"},
		{"gateway_ipam_release error", "gateway_ipam_release", map[string]interface{}{"ip": "10.0.0.5"}, "GatewayIPAMRelease"},
		{"gateway_ipam_allocations error", "gateway_ipam_allocations", map[string]interface{}{"pool_id": "p1"}, "GatewayIPAMAllocations"},

		// TPM errors
		{"tpm_info error", "platform_tpm_info", map[string]interface{}{}, "TPMInfo"},
		{"tpm_ek error", "platform_tpm_ek", map[string]interface{}{}, "TPMGetEK"},
		{"tpm_ek_cert error", "platform_tpm_ek_cert", map[string]interface{}{}, "TPMGetEKCert"},
		{"tpm_eventlog error", "platform_tpm_eventlog", map[string]interface{}{}, "TPMEventLog"},
		{"tpm_capabilities error", "platform_tpm_capabilities", map[string]interface{}{}, "TPMCapabilities"},
		{"tpm_random error", "platform_tpm_random", map[string]interface{}{"num_bytes": float64(16)}, "TPMRandom"},
		{"tpm_nv_list error", "platform_tpm_nv_list", map[string]interface{}{}, "TPMNVList"},
		{"tpm_nv_read error", "platform_tpm_nv_read", map[string]interface{}{"index": float64(1), "size": float64(32)}, "TPMNVRead"},
		{"tpm_nv_delete error", "platform_tpm_nv_delete", map[string]interface{}{"index": float64(1)}, "TPMNVDelete"},
		{"tpm_platform error", "platform_tpm_platform", map[string]interface{}{}, "TPMPlatform"},
		{"tpm_certify error", "platform_tpm_certify", map[string]interface{}{"key_handle": float64(0x81000001)}, "TPMCertify"},
		{"tpm_unseal error", "platform_tpm_unseal", map[string]interface{}{"cn": "test.example.com"}, "TPMUnseal"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eSvc := newErrorServiceProvider(tc.failMethod)
			registry := NewToolRegistry(eSvc, log)

			_, err := registry.ExecuteTool(ctx, tc.toolName, tc.args)
			if err == nil {
				t.Fatalf("expected error for %s", tc.toolName)
			}
		})
	}
}

func TestAdditionalErrorPaths(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	// Test IAK/IDevID error paths not yet covered
	t.Run("iak_info service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakInfoFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_info", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_delete service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakDeleteFunc = func(ctx context.Context) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_delete", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_delete_cert service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakDeleteCertFunc = func(ctx context.Context) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_delete_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_exists service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakExistsFunc = func(ctx context.Context) (bool, error) {
			return false, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_exists", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("idevid_install_cert service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidInstallCertFunc = func(ctx context.Context, certPEM string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_install_cert", map[string]interface{}{
			"certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("idevid_get_cert service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_get_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("idevid_csr service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_csr", map[string]interface{}{
			"common_name": "test.example.com",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_generate service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_generate", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_csr service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_csr", map[string]interface{}{
			"common_name": "test.example.com",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_install_cert service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakInstallCertFunc = func(ctx context.Context, certPEM string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_install_cert", map[string]interface{}{
			"certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("iak_get_cert service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_get_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("activate_credential service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.activateCredentialFunc = func(ctx context.Context, credentialBlob []byte, secret []byte) ([]byte, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "activate_credential", map[string]interface{}{
			"credential_blob": base64.StdEncoding.EncodeToString([]byte("blob")),
			"secret":          base64.StdEncoding.EncodeToString([]byte("secret")),
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
