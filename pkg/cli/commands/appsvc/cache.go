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

package appsvc

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NewCacheCommand creates the cache command group.
func NewCacheCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect, tune and clear the platform cache",
		Long: `Inspect, tune and clear the L1 cache in front of the platform data store.

Examples:
  # Hit rate, size and evictions, for the whole cache or one entity type
  platformctl cache stats
  platformctl cache stats --entity-type users

  # Show the configuration, then change the L1 TTL
  platformctl cache config get
  platformctl cache config set --l1-ttl 5m

  # Drop the entries of one entity type, or every entry
  platformctl cache clear --entity-type users
  platformctl cache clear --all`,
	}

	config := &cobra.Command{
		Use:   "config",
		Short: "Show or change the cache configuration",
	}
	config.AddCommand(newCacheConfigGetCommand(getFlags), newCacheConfigSetCommand(getFlags))

	cmd.AddCommand(newCacheStatsCommand(getFlags), config, newCacheClearCommand(getFlags))
	return cmd
}

func newCacheStatsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var entityType string
	cmd := newCommand(getFlags, "stats", "Show the cache hit rate, size and evictions", cobra.NoArgs,
		func(flags *cli.CommonFlags, _ []string) error {
			return call(flags, newCacheClient, "failed to get the cache statistics",
				platformv1.CacheServiceClient.GetStats, &platformv1.GetCacheStatsRequest{EntityType: entityType},
				fieldsTable[*platformv1.GetCacheStatsResponse])
		})
	cmd.Flags().StringVar(&entityType, "entity-type", "", "report only this entity type")
	return cmd
}

func newCacheConfigGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return newCommand(getFlags, "get", "Show the cache configuration", cobra.NoArgs,
		func(flags *cli.CommonFlags, _ []string) error {
			return call(flags, newCacheClient, "failed to get the cache configuration",
				platformv1.CacheServiceClient.GetConfig, &platformv1.GetCacheConfigRequest{},
				func(reply *platformv1.GetCacheConfigResponse) *cli.TableData { return fieldsTable(reply.GetConfig()) })
		})
}

// cacheConfigFlags are the settings `cache config set` changes. Only the
// flags given on the command line are sent.
var cacheConfigFlags = struct{ size, ttl, cleanup string }{"l1-size", "l1-ttl", "cleanup-interval"}

func newCacheConfigSetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		size    int64
		ttl     time.Duration
		cleanup time.Duration
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Change the cache configuration",
		Long: `Change the cache configuration. Only the settings given change.

Examples:
  platformctl cache config set --l1-size 50000
  platformctl cache config set --l1-ttl 5m --cleanup-interval 1m`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request := &platformv1.UpdateCacheConfigRequest{}
			changed := cmd.Flags().Changed
			if changed(cacheConfigFlags.size) {
				request.L1Size = &size
			}
			if changed(cacheConfigFlags.ttl) {
				request.L1TtlMs = millis(ttl)
			}
			if changed(cacheConfigFlags.cleanup) {
				request.CleanupIntervalMs = millis(cleanup)
			}
			return call(getFlags(), newCacheClient, "failed to update the cache configuration",
				platformv1.CacheServiceClient.UpdateConfig, request,
				func(reply *platformv1.UpdateCacheConfigResponse) *cli.TableData {
					return fieldsTable(reply.GetConfig())
				})
		},
	}
	cmd.Flags().Int64Var(&size, cacheConfigFlags.size, 0, "maximum number of L1 entries")
	cmd.Flags().DurationVar(&ttl, cacheConfigFlags.ttl, 0, "how long an L1 entry lives")
	cmd.Flags().DurationVar(&cleanup, cacheConfigFlags.cleanup, 0, "how often expired entries are removed")
	cmd.MarkFlagsOneRequired(cacheConfigFlags.size, cacheConfigFlags.ttl, cacheConfigFlags.cleanup)
	return cmd
}

func newCacheClearCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	request := &platformv1.ClearCacheRequest{}
	cmd := newCommand(getFlags, "clear", "Drop cache entries", cobra.NoArgs,
		func(flags *cli.CommonFlags, _ []string) error {
			return call(flags, newCacheClient, "failed to clear the cache",
				platformv1.CacheServiceClient.Clear, request, fieldsTable[*platformv1.ClearCacheResponse])
		})
	cmd.Flags().StringVar(&request.EntityType, "entity-type", "", "drop only the entries of this entity type")
	cmd.Flags().BoolVar(&request.All, "all", false, "drop every entry")
	cmd.MarkFlagsOneRequired("entity-type", "all")
	cmd.MarkFlagsMutuallyExclusive("entity-type", "all")
	return cmd
}

// millis converts a duration flag to the milliseconds a request carries.
func millis(d time.Duration) *int64 {
	ms := d.Milliseconds()
	return &ms
}
