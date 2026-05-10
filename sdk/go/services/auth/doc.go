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

// Package auth provides the platform SDK surface for the canonical
// "auth login" / "auth factor *" CLI subcommands. It is a thin
// adapter over the go-quicbaas SDK Security().Auth().Factors() M10
// surface so that platformctl never imports go-quicbaas/pkg or
// go-qrdb/pkg directly (per
// docs/architecture/08-bootstrap-auth-architecture.md §5d).
//
// Usage:
//
//	cli, err := auth.NewClient(quicbaasAddr)
//	if err != nil {
//	    return err
//	}
//	defer cli.Close()
//	resp, err := cli.ListFactors(ctx, "")
//
// The N-AuthFactor data model lives in go-qrdb (pkg/auth/factors.go);
// the SDK re-export is owned by go-quicbaas (sdk/go/services_security.go).
package auth
