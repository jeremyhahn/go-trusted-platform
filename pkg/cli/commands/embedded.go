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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// startEmbeddedHost hosts platformd in this process for an embedded
// context. It reads the platformd configuration from the locations
// platformd itself searches, so on a node it runs with the node's own
// configuration and this process's credentials.
func startEmbeddedHost(ctx context.Context, _ *cli.Context) (cli.EmbeddedHost, error) {
	host, err := daemon.StartEmbeddedHost(ctx, daemon.EmbeddedHostOptions{
		WireBackends: appbackends.WireEmbeddedHost,
	})
	if err != nil {
		// A nil *EmbeddedHost in the interface would not compare nil.
		return nil, err
	}
	return host, nil
}
