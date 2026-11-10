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
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// webserviceIAMClient adapts the daemon's QuicBaaS SDK IAM client to the
// IAMClient the web service's /api/v1/iam router consumes. cfg is the
// QuicBaaS backend configuration the platform runs on.
//
// The embedded transport, which is also what a nil configuration means, gets
// the embedded adapter: it refuses the operations the embedded SDK cannot
// serve, such as a change of a user's roles. A gRPC or Unix backend gets the
// remote adapter, which serves them. The daemon plane's REST listener decides
// by the same rule (quicbaasEmbedded and iamRESTAdapter in pkg/api/daemon).
func webserviceIAMClient(client quicbaassdk.IAMClient, cfg *platformquicbaas.Config) restiam.IAMClient {
	if cfg == nil || cfg.IsEmbedded() {
		return restiam.NewQuicBaaSIAMAdapter(client)
	}
	return restiam.NewRemoteQuicBaaSIAMAdapter(client)
}
