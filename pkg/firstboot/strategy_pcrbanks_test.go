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

package firstboot

import (
	"strings"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// TestFormatPCRBanksContent asserts the authoritative pcr-banks content
// carries every field the unseal-side parser requires — most importantly
// keystore-platform-policy, the parent authorization mode whose absence
// let seal and unseal disagree and fail every TPM unseal (#52).
func TestFormatPCRBanksContent(t *testing.T) {
	got := formatPCRBanksContent("0,7,9", "7,9", 23, "sha256", 0x81000001, false, 0x81000001)

	for _, want := range []string{
		"seal-pcrs=0,7,9\n",
		"platform-pcr=23\n",
		"platform-pcr-bank=sha256\n",
		"golden-pcrs=7,9\n",
		"keystore-srk-handle=0x81000001\n",
		"keystore-platform-policy=false\n",
		"ssrk-handle=0x81000001\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("pcr-banks content missing %q; got:\n%s", want, got)
		}
	}
}

// TestFormatPCRBanksContent_PolicyTrue asserts the policy mode is faithfully
// recorded when the seal parent DOES carry the platform policy.
func TestFormatPCRBanksContent_PolicyTrue(t *testing.T) {
	got := formatPCRBanksContent("0,7,9", "7,9", 23, "sha256", 0x81000002, true, 0x81000001)
	if !strings.Contains(got, "keystore-platform-policy=true\n") {
		t.Errorf("expected keystore-platform-policy=true, got:\n%s", got)
	}
	if !strings.Contains(got, "keystore-srk-handle=0x81000002\n") {
		t.Errorf("expected keystore-srk-handle=0x81000002, got:\n%s", got)
	}
}

// TestPlatformKeystoreSealAttrs_TwoAxes asserts the two independent
// TPMPolicy axes (#52): the CHILD (sealed object) is ALWAYS
// PCR-bound regardless of the parent's authorization mode, while the
// PARENT mode is what pcr-banks records for the initrd to replay during
// load.
func TestPlatformKeystoreSealAttrs_TwoAxes(t *testing.T) {
	for _, parentMode := range []bool{true, false} {
		parentPolicy := common.PlatformTPMPolicy(parentMode)
		parent := &xkmssdk.KeyAttributes{CN: "srk", TPMPolicy: parentPolicy}

		attrs := platformKeystoreSealAttrs(parent)
		if attrs.TPMPolicy != common.TPMPolicyPlatform {
			t.Errorf("parent mode %v: sealed object must ALWAYS be PCR-bound, got TPMPolicy %q",
				parentMode, attrs.TPMPolicy)
		}
		if attrs.Parent.TPMPolicy != parentPolicy {
			t.Errorf("parent mode %v: parent attrs mutated to %q",
				parentMode, attrs.Parent.TPMPolicy)
		}
		// pcr-banks records the PARENT mode — the load-session contract.
		content := formatPCRBanksContent("0,7,9", "7,9", 23, "sha256", 0x81000001, parentMode, 0x81000001)
		want := "keystore-platform-policy=false\n"
		if parentMode {
			want = "keystore-platform-policy=true\n"
		}
		if !strings.Contains(content, want) {
			t.Errorf("parent mode %v: pcr-banks missing %q", parentMode, want)
		}
	}
}
