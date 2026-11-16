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

//go:build !opa

package container

import (
	"context"
	"errors"
	"testing"
)

// TestOPAEngine_NoOPABuild_ReturnsErrOPANotBuilt checks that a build
// without the opa tag keeps the engine API and refuses it with
// ErrOPANotBuilt (#1691).
func TestOPAEngine_NoOPABuild_ReturnsErrOPANotBuilt(t *testing.T) {
	engine, err := NewOPAEngine()
	if engine != nil {
		t.Errorf("NewOPAEngine: got engine %v, want nil", engine)
	}
	if !errors.Is(err, ErrOPANotBuilt) {
		t.Fatalf("NewOPAEngine: got error %v, want ErrOPANotBuilt", err)
	}

	var stub OPAEngine
	ctx := context.Background()
	if err := stub.LoadBundle(ctx, &PolicyBundle{}); !errors.Is(err, ErrOPANotBuilt) {
		t.Errorf("LoadBundle: got error %v, want ErrOPANotBuilt", err)
	}
	decision, err := stub.Evaluate(ctx, OPAPolicyInput{})
	if decision != nil {
		t.Errorf("Evaluate: got decision %v, want nil", decision)
	}
	if !errors.Is(err, ErrOPANotBuilt) {
		t.Errorf("Evaluate: got error %v, want ErrOPANotBuilt", err)
	}
	if err := stub.Close(); err != nil {
		t.Errorf("Close: got error %v, want nil", err)
	}

	_, err = NewContainerPolicyEvaluator(PolicyConfig{})
	if err == nil {
		t.Error("NewContainerPolicyEvaluator: got nil error, want one")
	}
}
