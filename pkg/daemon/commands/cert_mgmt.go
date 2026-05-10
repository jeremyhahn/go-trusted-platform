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

package commands

import (
	"os"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// deriveNodeIDForCertMgmt returns a stable node identifier used for
// cert-renewal job NodeAffinity binding.
//
// Resolution order:
//  1. PLATFORM_NODE_ID env var (explicit operator override)
//  2. HOSTNAME env var
//  3. os.Hostname() — the OS-reported hostname
//  4. "unknown" — last resort so RegisterCertRenewal doesn't reject
//
// The returned value is lowercased and dots/colons are replaced
// with hyphens so it's safe for use as part of a scheduler job
// Name ("platform.cert-renewal.<nodeID>").
func deriveNodeIDForCertMgmt(_ *app.App) string {
	candidates := []string{
		os.Getenv("PLATFORM_NODE_ID"),
		os.Getenv("HOSTNAME"),
	}
	if h, err := os.Hostname(); err == nil {
		candidates = append(candidates, h)
	}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		return sanitizeNodeID(c)
	}
	return "unknown"
}

// sanitizeNodeID normalizes a node-id candidate for use as part of
// a scheduler job name. Lowercases + replaces characters that would
// confuse the job-name tokenization.
func sanitizeNodeID(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(":", "-", ".", "-", " ", "-", "/", "-").Replace(s)
	return s
}
