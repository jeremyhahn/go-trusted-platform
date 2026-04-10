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

// Package quicbaas provides an ACME storage factory backed by QuicBaaS ObjectStorage.
// It implements go-trusted-ca's acmestorage.Factory interface, mapping GenericDAO
// operations onto the QuicBaaS ObjectStorage client for multi-tenant isolation,
// DEK encryption, and cluster replication of all ACME state.
//
// Key encoding follows the same namespace scheme as the go-trusted-ca objstore
// implementation for data compatibility: "acme/{collection}/{entityID}".
package quicbaas
