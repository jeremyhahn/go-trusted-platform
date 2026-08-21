// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryLUKSKeyslotCallAppliesFIPSPolicy is a REPO-WIDE guard.
//
// It exists because a narrower version of it failed. The first attempt scanned
// only pkg/app/backends/luks.go, so it could not see the bypass in
// pkg/installer/fido2_enroll.go — a keyslot path that set PBKDF2 only when a
// config flag was true and never consulted the running kernel. A guard that
// looks in one place proves only that one place is correct.
//
// Rule: any function that creates a LUKS keyslot must also either
//   - apply the platform FIPS policy (fips.ResolveKeyslotPolicy /
//     ResolveFormatKeyslotPolicy, or a package-local wrapper), or
//   - set the KDF to an explicit literal, which is safe by construction.
//
// go-luks2 defaults an unset KDF to argon2id and does not consult
// /proc/sys/crypto/fips_enabled itself, so an unpoliced call with empty options
// persists a non-approved keyslot on a FIPS-activated host.
func TestEveryLUKSKeyslotCallAppliesFIPSPolicy(t *testing.T) {
	keyslotCreators := map[string]bool{
		"AddKey": true, "AddRecoveryKey": true, "Format": true,
	}
	policyMarkers := []string{
		"ResolveKeyslotPolicy", "ResolveFormatKeyslotPolicy",
		"applyFIPSKeyslotPolicy", "applyFIPSFormatPolicy",
		"fipsAddKeyOptions", "fipsRecoveryKeyPolicy",
		"resolveLUKSAlgorithms",
	}

	root := ".."
	var offenders []string
	checked := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not our business to fail on unparseable files
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var creates, policed, literalKDF bool
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.SelectorExpr:
					// luks2.AddKey / goluks.Format / ...
					if pkg, ok := v.X.(*ast.Ident); ok {
						if (pkg.Name == "luks2" || pkg.Name == "goluks") && keyslotCreators[v.Sel.Name] {
							creates = true
						}
					}
					for _, m := range policyMarkers {
						if v.Sel.Name == m {
							policed = true
						}
					}
				case *ast.Ident:
					for _, m := range policyMarkers {
						if v.Name == m {
							policed = true
						}
					}
				case *ast.KeyValueExpr:
					// KDFType: "pbkdf2" — an explicit literal is safe.
					// Composite-literal field only: luks2.AddKeyOptions{KDFType: "pbkdf2"}
					if k, ok := v.Key.(*ast.Ident); ok && k.Name == "KDFType" {
						if lit, ok := v.Value.(*ast.BasicLit); ok && strings.Contains(lit.Value, "pbkdf2") {
							literalKDF = true
						}
					}
					// NOTE: a plain assignment (addKeyOpts.KDFType = "pbkdf2") is
					// deliberately NOT accepted as safe. That is exactly the
					// shape the fido2_enroll.go bypass had: the literal sat
					// inside `if config.FIPSMode`, so the field stayed empty
					// whenever the flag was false and go-luks2 defaulted to
					// argon2id. An earlier version of this guard accepted it
					// and therefore failed to catch the very bug it was written
					// for. Only an unconditional composite-literal field counts.
				}
				return true
			})
			if creates {
				checked++
				if !policed && !literalKDF {
					offenders = append(offenders,
						strings.TrimPrefix(path, "../")+":"+fn.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for _, o := range offenders {
		t.Errorf("%s creates a LUKS keyslot without applying the FIPS policy or an explicit PBKDF2 literal — "+
			"go-luks2 defaults an unset KDF to argon2id, so this persists a non-approved keyslot "+
			"on a FIPS-activated host", o)
	}

	// Guard the guard: if the call sites move or are renamed, this must fail
	// loudly rather than pass while inspecting nothing.
	if checked < 8 {
		t.Errorf("found only %d keyslot-creating functions; expected at least 8. "+
			"Have the go-luks2 call sites moved? This guard would otherwise verify nothing", checked)
	}
}
