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
	"testing"
)

// The cert-renewal defects fixed under issue #31 were both STRUCTURAL: the code
// was correct wherever it ran, and the bug was that it did not run on some
// paths. Behavioural tests on the helpers cannot see that — they pass whether
// or not the call sites exist. These guards watch the call sites themselves.

// parseFn returns the named top-level function from a file.
func parseFn(t *testing.T, path, name string) (*token.FileSet, *ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Body != nil {
			return fset, fn
		}
	}
	t.Fatalf("%s: function %q not found — it was renamed or removed, and the "+
		"guard that depends on it can no longer protect anything", path, name)
	return nil, nil
}

// callsFunc reports whether the function body calls the named function, either
// bare (initCertManagement(...)) or on a receiver (app.registerX(...)).
func callsFunc(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				found = true
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				found = true
			}
		}
		return true
	})
	return found
}

// TestEveryCertLoadedPathRegistersACertTarget guards the restart bug.
//
// initWebServiceKeyAttributes (reached from InitWebServer) contains `goto
// certLoaded` jumps taken when the CA already holds the certificate — the
// ordinary-restart case. Registration used to live only in
// issueWebServiceCertificate, which those jumps skip, so after any restart the
// target registry was empty: renewal was scheduled but had nothing to sweep and
// certificates ran silently to expiry.
//
// The fix registers unconditionally in the certLoaded tail, which every path
// reaches. This guard asserts that the registration call is still positioned
// AFTER the certLoaded label, so a future `goto certLoaded` cannot reintroduce
// the bypass. Adding a third goto is safe by construction; moving the call back
// above the label is not.
func TestEveryCertLoadedPathRegistersACertTarget(t *testing.T) {
	const path = "../app/app.go"
	fset, fn := parseFn(t, path, "initWebServiceKeyAttributes")

	var labelPos token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if lbl, ok := n.(*ast.LabeledStmt); ok && lbl.Label.Name == "certLoaded" {
			labelPos = lbl.Pos()
		}
		return true
	})
	if !labelPos.IsValid() {
		t.Fatal("initWebServiceKeyAttributes no longer has a certLoaded label; the control flow " +
			"this guard reasons about has changed and the guard must be rewritten")
	}

	var registrations []token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
			sel.Sel.Name == "registerWebServiceCertTarget" {
			registrations = append(registrations, call.Pos())
		}
		return true
	})

	if len(registrations) == 0 {
		t.Fatal("initWebServiceKeyAttributes never registers a cert renewal target. Every " +
			"webservice certificate on this node will run to expiry: the renewal " +
			"sweep only renews targets that are in the registry.")
	}
	for _, pos := range registrations {
		if pos > labelPos {
			return // at least one registration is on the unconditional tail
		}
	}
	t.Errorf("%s: registerWebServiceCertTarget is called only BEFORE the "+
		"certLoaded label (line %d). The `goto certLoaded` jumps taken on an "+
		"ordinary restart skip it, so restarted nodes register no targets and "+
		"their certificates are never renewed.",
		path, fset.Position(labelPos).Line)
}

// TestBothDaemonRunPathsScheduleCertRenewal guards the daemon-only bug.
//
// A node configured with bmc.certificate but no webservices takes runDaemonOnly.
// While the scheduling call lived only in runWithWebservices, those nodes never
// created a platform.cert-renewal job at all, so the BMC certificate was never
// issued, registered, or renewed.
func TestBothDaemonRunPathsScheduleCertRenewal(t *testing.T) {
	const path = "../daemon/commands/serve.go"
	for _, runPath := range []string{"runWithWebservices", "runDaemonOnly"} {
		t.Run(runPath, func(t *testing.T) {
			_, fn := parseFn(t, path, runPath)
			if !callsFunc(fn, "initCertManagement") {
				t.Errorf("%s never calls initCertManagement, so a node taking this "+
					"boot path schedules no renewal sweep. Its webservice and BMC "+
					"certificates will run to expiry with nothing reporting it.",
					runPath)
			}
		})
	}
}

// TestBothDaemonRunPathsInitializeTheACMEClient guards the second half of the
// same restart problem that motivated this whole change.
//
// App.ACMEClient is initialized as a SIDE EFFECT of issueWebServiceCertificate.
// On an ordinary restart InitWebServer finds the certificate already in the CA
// and jumps to certLoaded, skipping issuance — so the side effect never happens
// and App.ACMEClient stays nil. With RequireACME set, BMC provisioning then
// fails on a webservices node exactly as it did on a daemon-only one.
//
// Both paths must therefore initialize it explicitly, and before cert
// management runs.
func TestBothDaemonRunPathsInitializeTheACMEClient(t *testing.T) {
	const path = "../daemon/commands/serve.go"
	for _, runPath := range []string{"runWithWebservices", "runDaemonOnly"} {
		t.Run(runPath, func(t *testing.T) {
			fset, fn := parseFn(t, path, runPath)

			var acmeInit, certMgmt token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				switch id.Name {
				case "initACMEClientForCertManagement":
					if !acmeInit.IsValid() {
						acmeInit = call.Pos()
					}
				case "initCertManagement":
					if !certMgmt.IsValid() {
						certMgmt = call.Pos()
					}
				}
				return true
			})

			if !acmeInit.IsValid() {
				t.Fatalf("%s never initializes the ACME client. A BMC declaring ACME "+
					"dns-01 has no issuer, and with RequireACME set its certificate "+
					"is never issued or renewed on this boot path.", runPath)
			}
			if !certMgmt.IsValid() {
				t.Fatalf("%s does not call initCertManagement", runPath)
			}
			if acmeInit > certMgmt {
				t.Errorf("%s:%d: the ACME client is initialized AFTER cert management "+
					"(line %d). Cert management captures the issuer state at that "+
					"moment, so BMC provisioning sees no issuer.",
					path, fset.Position(acmeInit).Line, fset.Position(certMgmt).Line)
			}
		})
	}
}

// TestCertRenewalIsScheduledAfterTheServiceRegistry guards the ORDERING, which
// is a separate failure from the call being absent.
//
// App.ServiceRegistry() is what lazily materializes the DAO factory — and so the
// scheduler engine — and assigns App.DNSService (pkg/app/app.go). BMC cert init
// passes App.DNSService as its dns-01 updater. Scheduling before that call
// therefore either finds no scheduler and skips renewal entirely, or wires BMC
// ACME issuance to a nil DNS updater. Both are silent.
func TestCertRenewalIsScheduledAfterTheServiceRegistry(t *testing.T) {
	const path = "../daemon/commands/serve.go"
	for _, runPath := range []string{"runWithWebservices", "runDaemonOnly"} {
		t.Run(runPath, func(t *testing.T) {
			fset, fn := parseFn(t, path, runPath)

			var firstRegistry, firstSchedule token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					if f.Sel.Name == "ServiceRegistry" && !firstRegistry.IsValid() {
						firstRegistry = call.Pos()
					}
				case *ast.Ident:
					if f.Name == "initCertManagement" && !firstSchedule.IsValid() {
						firstSchedule = call.Pos()
					}
				}
				return true
			})

			if !firstSchedule.IsValid() {
				t.Fatalf("%s does not call initCertManagement at all", runPath)
			}
			if !firstRegistry.IsValid() {
				t.Fatalf("%s no longer calls App.ServiceRegistry(); the ordering this "+
					"guard checks no longer exists and it must be rewritten", runPath)
			}
			if firstSchedule < firstRegistry {
				t.Errorf("%s:%d: initCertManagement is called BEFORE App.ServiceRegistry() "+
					"(line %d). The scheduler engine and App.DNSService do not exist yet, "+
					"so renewal is either skipped outright or wired to a nil dns-01 updater.",
					path, fset.Position(firstSchedule).Line, fset.Position(firstRegistry).Line)
			}
		})
	}
}

// TestBMCCertInitGetsARealLogger guards a wiring gap that no behavioural test
// can see.
//
// InitCertManagement builds bmcCertInitOptions and previously hardcoded
// `Logger: nil`, which silenced BMC certificate init entirely on the production
// path — including its warning that the configured ACME issuer is missing and
// certificates are being issued from the local CA instead. Every unit test of
// the issuance code passes its own logger, so all of them stayed green while the
// real daemon logged nothing.
//
// A nil literal here is a silenced subsystem, not a default.
func TestBMCCertInitGetsARealLogger(t *testing.T) {
	const path = "../app/bmc_cert_init.go"
	_, fn := parseFn(t, path, "InitCertManagement")

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "bmcCertInitOptions" {
			return true
		}
		found = true
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Logger" {
				continue
			}
			if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "nil" {
				t.Error("InitCertManagement passes Logger: nil to bmcCertInitOptions. " +
					"BMC certificate init is then completely silent in the daemon: the " +
					"warning that ACME is configured but unwired, and certificates are " +
					"being issued from the local CA instead, never reaches any log.")
			}
		}
		return true
	})
	if !found {
		t.Fatal("InitCertManagement no longer constructs bmcCertInitOptions; this " +
			"guard must be rewritten against the new shape")
	}
}

// TestBMCCertInitGetsTrustRootsAndRequiresACME guards two production-only
// wirings that no behavioural test in pkg/app can observe, because every unit
// test constructs bmcCertInitOptions itself and passes whatever it needs.
//
// Both defaults are unsafe in opposite directions, which is why they must be
// set explicitly at the one production call site:
//
//   - TrustRoots nil means no certificate can be shown to be ours, so every
//     restart reissues and redeploys — regenerating the BMC key, restarting its
//     web interface and invalidating the TOFU pin each time.
//   - RequireACME false means a missing ACME issuer silently downgrades to the
//     local CA, putting a certificate on the BMC signed by an authority the
//     operator never selected.
//
// A missing TrustRoots was caught once only by accident: golangci-lint reported
// the helper as unused. Nothing would have caught it had the helper had another
// caller.
func TestBMCCertInitGetsTrustRootsAndRequiresACME(t *testing.T) {
	const path = "../app/bmc_cert_init.go"
	_, fn := parseFn(t, path, "InitCertManagement")

	present := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "bmcCertInitOptions" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			// A field set to the bare `nil`/`false` literal counts as absent:
			// that is the unsafe default written out longhand.
			if val, ok := kv.Value.(*ast.Ident); ok && (val.Name == "nil" || val.Name == "false") {
				continue
			}
			present[key.Name] = true
		}
		return true
	})

	if !present["TrustRoots"] {
		t.Error("InitCertManagement does not supply TrustRoots to bmcCertInitOptions. " +
			"No certificate on a BMC can then be shown to be one we issued, so every " +
			"daemon restart reissues and redeploys: new key, BMC web interface " +
			"restart, invalidated TOFU pin, republished DANE records.")
	}
	if !present["RequireACME"] {
		t.Error("InitCertManagement does not set RequireACME on bmcCertInitOptions. " +
			"A BMC that declares ACME dns-01 would then silently receive a local-CA " +
			"certificate when no ACME issuer is wired — signed by an authority the " +
			"configuration did not select.")
	}
}

// TestIssuanceInstallsTheCertOnTheLiveListener guards the difference between
// renewal and rotation.
//
// The listener's TLS config is a static snapshot taken at startup, so issuing a
// replacement into the CA changes nothing clients see. If
// issueWebServiceCertificate stops calling installWebServiceCert, the sweep
// silently degrades into a daily re-issue loop against an endpoint that keeps
// serving the original certificate until it expires — and every test of the
// issuance code still passes, because the defect is the absence of a call.
func TestIssuanceInstallsTheCertOnTheLiveListener(t *testing.T) {
	const path = "../app/app.go"
	_, fn := parseFn(t, path, "issueWebServiceCertificate")

	if !callsFunc(fn, "installWebServiceCert") {
		t.Error("issueWebServiceCertificate never installs the new certificate on " +
			"the running listener. Renewal then issues certificates nobody serves: " +
			"the endpoint keeps presenting the previous one until it expires and " +
			"TLS breaks.")
	}
}

// TestWebservicesRegisterACertInstaller guards the other end of the same seam.
func TestWebservicesRegisterACertInstaller(t *testing.T) {
	const path = "../daemon/commands/serve.go"
	_, fn := parseFn(t, path, "runWithWebservices")

	if !callsFunc(fn, "RegisterWebServiceCertInstaller") {
		t.Error("runWithWebservices never registers a certificate installer, so " +
			"issuance has nothing to call and renewed certificates are never put " +
			"into service on the running listener.")
	}
}

// TestRenewalRequiresTheCertToBeInstalled guards the fail-open the installation
// step exists to close.
//
// The sweep records a target's outcome from the Reissue callback's return value.
// If renewal issues with installOptional, a missing or failing installer is
// swallowed, Reissue returns nil, and the job history says "renewed" while the
// endpoint still serves the expiring certificate — a renewal that did not
// happen, reported as one that did.
func TestRenewalRequiresTheCertToBeInstalled(t *testing.T) {
	const path = "../app/app.go"
	_, fn := parseFn(t, path, "buildWebServiceCertTarget")

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "issueWebServiceCertificate" {
			return true
		}
		for _, arg := range call.Args {
			if id, ok := arg.(*ast.Ident); ok && id.Name == "installRequired" {
				found = true
			}
		}
		return true
	})

	if !found {
		t.Error("the renewal Reissue callback does not issue with installRequired. " +
			"A missing or failing installer would then be swallowed and the sweep " +
			"would record the target renewed while the listener still serves the " +
			"expiring certificate.")
	}
}

// TestCertReloadUsesTheSharedTLSBuilder guards cross-sign preservation.
//
// startHTTPS honours Certificate.ACME.CrossSign; if ReloadCertificate builds its
// replacement any other way, the first renewal swaps a cross-signed chain for an
// ordinary one and breaks every client relying on that trust path — silently,
// and only after the first rotation.
func TestCertReloadUsesTheSharedTLSBuilder(t *testing.T) {
	const path = "../webservice/webserver_v1.go"
	for _, fnName := range []string{"startHTTPS", "ReloadCertificate"} {
		t.Run(fnName, func(t *testing.T) {
			_, fn := parseFn(t, path, fnName)
			if !callsFunc(fn, "buildTLSConfig") {
				t.Errorf("%s does not build its TLS config through buildTLSConfig. "+
					"The two paths then diverge, and cross-sign configuration is "+
					"honoured on startup but dropped on the first renewal.", fnName)
			}
			// Building it directly is what divergence looks like.
			for _, direct := range []string{"ServerTLSConfig", "TLSConfigWithXSigner"} {
				if callsFunc(fn, direct) {
					t.Errorf("%s calls %s directly instead of going through "+
						"buildTLSConfig; that is how the two paths drift apart.",
						fnName, direct)
				}
			}
		})
	}
}
