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

package initrd

import (
	"context"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewTPMPCRStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewTPMPCRStrategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewTPMPCRStrategy returned nil")
	}

	if strategy.Name() != "TPM-PCR" {
		t.Errorf("expected name TPM-PCR, got %s", strategy.Name())
	}

	if strategy.Priority() != 1 {
		t.Errorf("expected priority 1, got %d", strategy.Priority())
	}
}

func TestTPMPCRStrategyCanUnlockNoTPM(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMPCRStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false when TPM is nil")
	}
}

func TestTPMPCRStrategyGetEFIPath(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewTPMPCRStrategy(platform, logger)

	path := strategy.getEFIPath()
	if path != pcrEfiMountPoint {
		t.Errorf("expected EFI path %s, got %s", pcrEfiMountPoint, path)
	}
}

func TestTPMPCRStrategyGetPlatformKeystoreSRKHandleDefault(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMPCRStrategy(platform, logger)

	handle := strategy.getPlatformKeystoreSRKHandle()
	if handle != 0x81000002 {
		t.Errorf("expected default handle 0x81000002, got 0x%08x", handle)
	}
}

func TestTPMPCRStrategyGetPlatformPolicyDefault(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMPCRStrategy(platform, logger)

	policy := strategy.getPlatformPolicy()
	if !policy {
		t.Error("expected default platform policy to be true")
	}
}

// TestSealedObjectAttrs_TwoAxes asserts the seal/unseal contract on the
// two-axes model (#52): the CHILD (sealed object) is PCR-bound —
// TPMPolicy "platform" — for BOTH parent SRK authorization modes, and the
// parent's configured mode travels only on the parent attributes. Install
// and unsealPlatformKeyStore both build their attributes through this
// helper, so this is the producer/consumer agreement test.
func TestSealedObjectAttrs_TwoAxes(t *testing.T) {
	for _, parentMode := range []bool{true, false} {
		parentPolicy := common.PlatformTPMPolicy(parentMode)
		parent := &xkmssdk.KeyAttributes{
			CN:        "platform-keystore-srk",
			TPMPolicy: parentPolicy,
		}
		attrs := sealedObjectAttrs("luks-root", parent)

		if attrs.TPMPolicy != common.TPMPolicyPlatform {
			t.Errorf("parent mode %v: sealed object must ALWAYS be PCR-bound, got TPMPolicy %q",
				parentMode, attrs.TPMPolicy)
		}
		if attrs.Parent.TPMPolicy != parentPolicy {
			t.Errorf("parent mode %v: parent authorization mode must be preserved, got %q",
				parentMode, attrs.Parent.TPMPolicy)
		}
		if attrs.CN != "luks-root" {
			t.Errorf("CN = %q, want luks-root", attrs.CN)
		}
		if attrs.KeyType != xkmssdk.KeyTypeHMAC {
			t.Errorf("KeyType = %v, want KeyTypeHMAC", attrs.KeyType)
		}
	}
}
