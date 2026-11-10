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

// strategy_sealparent_test.go asserts the LUKS seal parent contract (#61):
// the seal parent is the Platform KeyStore SRK, never the SSRK. Sealing under
// the SSRK left platformd — which adopts an existing Platform SRK but
// re-provisions (TPM2_Clear) when it finds none — to regenerate the storage
// seed and invalidate the seal between firstboot and the next boot.

package firstboot

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newSealParentTestStrategy builds a strategy over an executor with no TPM,
// so handle resolution exercises the configuration defaults.
func newSealParentTestStrategy() *FirstbootSealStrategy {
	executor := &Executor{
		logger: logging.DefaultLogger(),
		config: DefaultConfig(),
	}
	return NewFirstbootSealStrategy(executor, nil, logging.DefaultLogger())
}

// TestGetLUKSSealParentHandle_DefaultsToPlatformKeystoreSRK asserts the
// fallback parent is the conventional Platform KeyStore SRK handle — NOT the
// SSRK at 0x81000001.
func TestGetLUKSSealParentHandle_DefaultsToPlatformKeystoreSRK(t *testing.T) {
	strategy := newSealParentTestStrategy()

	handle := strategy.getLUKSSealParentHandle()
	if handle != 0x81000002 {
		t.Fatalf("seal parent handle = 0x%08x, want the Platform KeyStore SRK 0x81000002 "+
			"(sealing under the SSRK is the #61 defect: platformd re-provisions and "+
			"TPM2_Clears when the Platform SRK is absent, invalidating the seal)", handle)
	}
	if handle == strategy.getSSRKHandle() {
		t.Fatal("seal parent must not resolve to the SSRK")
	}
}
