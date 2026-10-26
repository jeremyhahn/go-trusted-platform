// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package backends

import (
	"crypto/fips140"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

// TestFIPSAddKeyOptionsApplyPolicy covers the option builders themselves.
func TestFIPSAddKeyOptionsApplyPolicy(t *testing.T) {
	opts, err := fipsAddKeyOptions()
	if err != nil {
		t.Fatalf("building add-key options must succeed: %v", err)
	}
	if opts == nil {
		t.Fatal("options must never be nil — a nil AddKeyOptions is exactly what let go-luks2 default to argon2id")
	}
	if luksFIPSActive() {
		if opts.KDFType != fips.KDFPBKDF2 {
			t.Errorf("under FIPS the KDF must be resolved to %q, got %q", fips.KDFPBKDF2, opts.KDFType)
		}
	} else if opts.KDFType != "" {
		t.Errorf("outside FIPS nothing may change, got KDFType=%q", opts.KDFType)
	}

	var kdf string
	if err := fipsRecoveryKeyPolicy(&kdf); err != nil {
		t.Fatalf("recovery-key policy must succeed: %v", err)
	}
	if luksFIPSActive() && kdf != fips.KDFPBKDF2 {
		t.Errorf("under FIPS a recovery keyslot must resolve to %q, got %q", fips.KDFPBKDF2, kdf)
	}
}

// TestResolveLUKSKeyslotPolicy covers the backend's wrapper over the platform
// policy: an unset KDF resolves to PBKDF2 whenever the Go cryptographic module
// is in FIPS 140-3 mode, whatever the kernel indicator says, and a KDF the
// policy does not know is still refused.
func TestResolveLUKSKeyslotPolicy(t *testing.T) {
	t.Run("unset KDF follows the module's FIPS mode", func(t *testing.T) {
		var kdf, hash string
		if err := resolveLUKSKeyslotPolicy(&kdf, &hash); err != nil {
			t.Fatalf("resolving an unset KDF must succeed: %v", err)
		}
		if fips140.Enabled() && kdf != fips.KDFPBKDF2 {
			t.Errorf("with the module in FIPS 140-3 mode the KDF must be %q, got %q", fips.KDFPBKDF2, kdf)
		}
		if !luksFIPSActive() && kdf != "" {
			t.Errorf("outside FIPS the KDF must stay unset, got %q", kdf)
		}
	})
	t.Run("unknown KDF is refused", func(t *testing.T) {
		kdf, hash := "not-a-kdf", ""
		if err := resolveLUKSKeyslotPolicy(&kdf, &hash); err == nil {
			t.Fatal("an unknown KDF must be refused")
		}
	})
}

// TestEveryEnrollmentAppliesFIPSPolicy is the guard the hosted review asked for.
//
// The daemon LUKS API is the surface that was persisting non-approved keyslots:
// every enrolment called luks2.AddKey/AddRecoveryKey with nil options, and
// go-luks2 defaults an unset KDF to argon2id. Unit tests confined to pkg/fips
// cannot detect a future omission here, and these paths need a real device to
// exercise end-to-end — so this asserts the wiring structurally instead.
//
// Any function that calls luks2.AddKey or luks2.AddRecoveryKey must also call
// one of the policy builders. Adding a fifth enrolment path without the policy
// fails this test by construction.
func TestEveryEnrollmentAppliesFIPSPolicy(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "luks.go", nil, 0)
	if err != nil {
		t.Fatalf("parse luks.go: %v", err)
	}

	const (
		addKey      = "AddKey"
		addRecovery = "AddRecoveryKey"
	)
	policyBuilders := map[string]bool{
		"fipsAddKeyOptions":     true,
		"fipsRecoveryKeyPolicy": true,
	}

	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		var createsKeyslot, appliesPolicy bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.SelectorExpr: // luks2.AddKey / luks2.AddRecoveryKey
				if pkg, ok := f.X.(*ast.Ident); ok && pkg.Name == "luks2" {
					if f.Sel.Name == addKey || f.Sel.Name == addRecovery {
						createsKeyslot = true
					}
				}
			case *ast.Ident: // fipsAddKeyOptions() / fipsRecoveryKeyPolicy()
				if policyBuilders[f.Name] {
					appliesPolicy = true
				}
			}
			return true
		})

		if createsKeyslot {
			checked++
			if !appliesPolicy {
				t.Errorf("%s creates a LUKS keyslot without applying the FIPS policy — "+
					"go-luks2 defaults an unset KDF to argon2id, so this persists a "+
					"non-approved keyslot on a FIPS-activated host", fn.Name.Name)
			}
		}
	}

	// Guard the guard: if the call sites are ever renamed or moved, this test
	// would silently pass while checking nothing.
	if checked < 4 {
		t.Errorf("expected at least 4 keyslot-creating functions, found %d — "+
			"has the API moved? this test would otherwise verify nothing", checked)
	}
}
