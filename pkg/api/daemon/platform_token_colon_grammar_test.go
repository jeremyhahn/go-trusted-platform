// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"testing"
)

// TestCheckPermission_ColonGrammar locks the Stage-3 grammar flip: the platform
// validator builds the required scope as the qrdb-canonical colon
// "resource:action", so a token whose scp carries the colon permission is
// authorized and a token carrying the OLD dotted "resource.action" form is
// denied (the dotted form no longer matches the colon-joined requirement).
func TestCheckPermission_ColonGrammar(t *testing.T) {
	key := newPTIssuerKey(t)
	srv := key.jwksHandler(t)
	v := newSharedValidator(t, srv.URL, true)

	t.Run("colon scp is authorized", func(t *testing.T) {
		tok := key.sign(t, "user-1", "tenant-a", []string{"keys:get", "dns:write"})
		allowed, err := v.CheckPermission(context.Background(), tok, "keys", "get")
		if err != nil || !allowed {
			t.Fatalf("colon scp should authorize keys:get: allowed=%v err=%v", allowed, err)
		}
	})

	t.Run("dotted scp no longer matches colon requirement", func(t *testing.T) {
		// A legacy dotted token must NOT satisfy the colon requirement; this is
		// the regression guard for the one-vocabulary flip.
		tok := key.sign(t, "user-1", "tenant-a", []string{"keys.get"})
		allowed, err := v.CheckPermission(context.Background(), tok, "keys", "get")
		if err != nil {
			t.Fatalf("CheckPermission error: %v", err)
		}
		if allowed {
			t.Error("dotted scp must not satisfy the colon resource:action requirement")
		}
	})

	t.Run("missing permission is denied", func(t *testing.T) {
		tok := key.sign(t, "user-1", "tenant-a", []string{"dns:read"})
		allowed, err := v.CheckPermission(context.Background(), tok, "dns", "write")
		if err != nil {
			t.Fatalf("CheckPermission error: %v", err)
		}
		if allowed {
			t.Error("a token lacking dns:write must be denied")
		}
	})
}
