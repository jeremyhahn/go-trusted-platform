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

// Package quicbaas provides a client wrapper for accessing QuicBaaS services
// through the go-trusted-platform SDK.
//
// This package wraps the go-quicbaas SDK to expose all 28 QuicBaaS services
// to platform SDK consumers with full multi-transport support (embedded,
// Unix socket, gRPC, REST, QUIC).
//
// # Services
//
// The QuicBaaS client provides access to the following service categories:
//
// Core Data Services:
//   - KV: Key-value CRUD operations with Watch support
//   - Batch: Atomic batch operations
//   - Transaction: Compare-and-swap transactions
//   - Query: Secondary index queries
//   - TimeSeries: Time-series data with aggregations
//   - Backup: Backup and restore operations
//
// AI/ML Services:
//   - Vector: Vector similarity search (k-NN)
//   - Embedding: Multi-provider embedding generation
//   - Ollama: Local LLM/embedding via Ollama
//
// Security Services:
//   - Auth: Authentication (login, tokens)
//   - KMS: Key management service
//   - Secrets: Secret storage with versioning
//   - Crypto: Encryption/decryption, signatures
//   - DynamicSecrets: Dynamic credential generation
//   - Certificate: X.509 certificate management
//   - Seal: Seal/unseal operations
//   - RBAC: Role-based access control
//   - DEK: Data encryption keys
//
// Infrastructure Services:
//   - Cluster: Cluster status and management
//   - Health: Health checks (ping, liveness)
//   - Operations: Migration, upgrade, rebalance
//   - Cache: Cache management and stats
//   - ParameterStore: Hierarchical parameters
//   - Scheduler: Job scheduling
//   - ObjectStorage: Distributed object storage
//   - ObjectStorageAdmin: Object storage admin operations
//   - ObjectTransfer: Peer-to-peer data transfer
//
// Identity Services:
//   - IAM: Full IAM with sub-clients (Tenant, User, Group, Role, Policy, etc.)
//
// # Usage
//
// The QuicBaaS client is typically accessed through the platform Client:
//
//	client, err := platform.NewClient(ctx,
//	    platform.WithGRPCAddr("platform.example.com:10443"),
//	    platform.WithQuicBaaSAddress("quicbaas.example.com:10443"),
//	    platform.WithQuicBaaSTransport(platform.QuicBaaSGRPC),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Access QuicBaaS services
//	db := client.QuicBaaS()
//
//	// KV operations
//	err = db.KV().Put(ctx, &quicbaas.PutRequest{
//	    Key:   "mykey",
//	    Value: []byte("myvalue"),
//	})
//
//	// Vector search
//	results, err := db.Vector().Search(ctx, &quicbaas.VectorSearchRequest{
//	    Namespace: "embeddings",
//	    Vector:    embedding,
//	    TopK:      10,
//	})
//
// Direct usage without the platform client is also supported:
//
//	import quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
//
//	client, err := quicbaas.NewClient("/var/run/quicbaas.sock")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
// # Transport Options
//
// QuicBaaS supports multiple transport protocols:
//   - Embedded: In-process direct service access (default)
//   - Unix Socket: Local IPC via Unix domain socket
//   - gRPC: High-performance remote procedure calls
//   - REST: HTTP/HTTPS for web clients
//   - QUIC: Low-latency UDP-based transport
package quicbaas
