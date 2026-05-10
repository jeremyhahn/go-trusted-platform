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

// Package credentials provides CredentialStore adapters that bind the
// parent bmc package's abstract credential interface to concrete
// backing services. The canonical production backend is the QuicBaaS
// SecretsService; this package isolates the QuicBaaS SDK dependency
// from the pure bmc core.
package credentials
