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

package device

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

var (
	DatastorePartition = "devices"

	Configuration *Config

	DefaultConfig = Config{
		QuicBaaS: &quicbaas.Config{
			StorageBackend: "pebble",
			DataDir:        "trusted-data/quicbaas",
			WALDir:         "trusted-data/quicbaas/wal",
			// Dev placeholder identity, consistent with the example.*
			// convention; deployments set the real internal domain.
			SPIFFETrustDomain: "example.internal",
			NodeID:            1,
			CacheSize:         64 * 1024 * 1024, // 64MB
			LogLevel:          "warn",
			ConsistencyLevel:  quicbaas.ConsistencyLinearizable,
		},
		ShardID:   0, // Default shard
		Partition: "devices",
	}
)

type Config struct {
	QuicBaaS  *quicbaas.Config `yaml:"quicbaas" json:"quicbaas" mapstructure:"quicbaas"`
	ShardID   uint64           `yaml:"shard-id" json:"shard_id" mapstructure:"shard-id"`
	Partition string           `yaml:"partition" json:"partition" mapstructure:"partition"`
}
