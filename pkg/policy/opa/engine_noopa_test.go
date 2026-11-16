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

package opa

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// TestEngine_NoOPABuild_ReturnsErrOPANotBuilt checks that a build without
// the opa tag keeps the engine API and refuses every operation with
// ErrOPANotBuilt (#1691).
func TestEngine_NoOPABuild_ReturnsErrOPANotBuilt(t *testing.T) {
	ctx := context.Background()
	engine := NewOPAEngine()
	if engine == nil {
		t.Fatal("NewOPAEngine returned nil")
	}

	assertNotBuilt := func(name string, err error) {
		t.Helper()
		var target ErrOPANotBuilt
		if !errors.As(err, &target) {
			t.Errorf("%s: got error %v, want ErrOPANotBuilt", name, err)
		}
	}

	assertNotBuilt("Initialize", engine.Initialize(ctx, &config.PolicyConfig{}))
	assertNotBuilt("LoadPolicy", engine.LoadPolicy(ctx, "p", []byte("package p")))
	assertNotBuilt("UnloadPolicy", engine.UnloadPolicy(ctx, "p"))

	res, err := engine.Evaluate(ctx, "p", map[string]interface{}{})
	if res != nil {
		t.Errorf("Evaluate: got result %v, want nil", res)
	}
	assertNotBuilt("Evaluate", err)

	res, err = engine.EvaluateWithData(ctx, "p", nil, nil)
	if res != nil {
		t.Errorf("EvaluateWithData: got result %v, want nil", res)
	}
	assertNotBuilt("EvaluateWithData", err)

	bundle, err := engine.GetPolicy("p")
	if bundle != nil {
		t.Errorf("GetPolicy: got bundle %v, want nil", bundle)
	}
	assertNotBuilt("GetPolicy", err)

	assertNotBuilt("Reload", engine.Reload(ctx))

	if got := engine.ListPolicies(); len(got) != 0 {
		t.Errorf("ListPolicies: got %d policies, want 0", len(got))
	}
	if engine.IsInitialized() {
		t.Error("IsInitialized: got true, want false")
	}
	if stats := engine.Stats(); stats != (EngineStats{}) {
		t.Errorf("Stats: got %+v, want zero", stats)
	}
	if err := engine.Close(); err != nil {
		t.Errorf("Close: got error %v, want nil", err)
	}
}

// TestErrOPANotBuilt_Message checks the error text names the build tag.
func TestErrOPANotBuilt_Message(t *testing.T) {
	want := "OPA policy engine not built: rebuild with the opa build tag"
	if got := (ErrOPANotBuilt{}).Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
