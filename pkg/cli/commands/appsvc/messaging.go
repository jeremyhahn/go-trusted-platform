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

// NewMessagingCommand creates the messaging command group.
func NewMessagingCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "messaging",
		Short: "Manage pub/sub channels and publish messages",
		Long: `Manage the channels of the publish/subscribe service and publish to them.

Examples:
  # A persistent channel that keeps the last 100 messages for replay
  platformctl messaging channel create events --persistent --max-history 100
  platformctl messaging channel list
  platformctl messaging channel stats events

  # Publish; a repeated dedup key within the dedup window is dropped
  platformctl messaging publish events '{"kind":"rotated"}' --dedup-key rot-7

  # Service-wide counters
  platformctl messaging stats
  platformctl messaging dedup-stats`,
	}

	channel := &cobra.Command{
		Use:   "channel",
		Short: "Create, list, inspect and delete channels",
	}
	channel.AddCommand(
		newMessagingChannelCreateCommand(getFlags),
		newCommand(getFlags, "list", "List the channels", cobra.NoArgs,
			func(flags *cli.CommonFlags, _ []string) error {
				return call(flags, newMessagingClient, "failed to list the channels",
					platformv1.MessagingServiceClient.ListChannels, &platformv1.ListMessagingChannelsRequest{},
					func(reply *platformv1.ListMessagingChannelsResponse) *cli.TableData {
						return listTable(reply.GetChannels(),
							"name", "codec", "subscribers", "persistent", "max_history", "ttl_ms")
					})
			}),
		newCommand(getFlags, "get NAME", "Show one channel", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newMessagingClient, "failed to get the channel",
					platformv1.MessagingServiceClient.GetChannel, &platformv1.GetMessagingChannelRequest{Name: args[0]},
					func(reply *platformv1.GetMessagingChannelResponse) *cli.TableData {
						return fieldsTable(reply.GetChannel())
					})
			}),
		newCommand(getFlags, "delete NAME", "Delete a channel", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newMessagingClient, "failed to delete the channel",
					platformv1.MessagingServiceClient.DeleteChannel, &platformv1.DeleteMessagingChannelRequest{Name: args[0]},
					confirmation[*platformv1.DeleteMessagingChannelResponse]("channel", args[0], "deleted"))
			}),
		newCommand(getFlags, "stats NAME", "Show the subscribers and message counts of a channel", cobra.ExactArgs(1),
			func(flags *cli.CommonFlags, args []string) error {
				return call(flags, newMessagingClient, "failed to get the channel statistics",
					platformv1.MessagingServiceClient.GetChannelStats,
					&platformv1.GetMessagingChannelStatsRequest{Channel: args[0]},
					fieldsTable[*platformv1.GetMessagingChannelStatsResponse])
			}),
	)

	cmd.AddCommand(
		channel,
		newMessagingPublishCommand(getFlags),
		newCommand(getFlags, "stats", "Show the service-wide message counters", cobra.NoArgs,
			func(flags *cli.CommonFlags, _ []string) error {
				return call(flags, newMessagingClient, "failed to get the messaging statistics",
					platformv1.MessagingServiceClient.GetStats, &platformv1.GetMessagingStatsRequest{},
					fieldsTable[*platformv1.GetMessagingStatsResponse])
			}),
		newCommand(getFlags, "dedup-stats", "Show the deduplication counters", cobra.NoArgs,
			func(flags *cli.CommonFlags, _ []string) error {
				return call(flags, newMessagingClient, "failed to get the deduplication statistics",
					platformv1.MessagingServiceClient.GetDedupStats, &platformv1.GetMessagingDedupStatsRequest{},
					fieldsTable[*platformv1.GetMessagingDedupStatsResponse])
			}),
	)
	return cmd
}

// channelCreateOptions are the flags of `messaging channel create`.
type channelCreateOptions struct {
	codec          string
	persistent     bool
	maxHistory     int32
	bufferSize     int32
	maxSubscribers int32
	ttl            time.Duration
}

func newMessagingChannelCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &channelCreateOptions{}
	cmd := newCommand(getFlags, "create NAME", "Create a channel", cobra.ExactArgs(1),
		func(flags *cli.CommonFlags, args []string) error {
			request := &platformv1.CreateMessagingChannelRequest{
				Name:           args[0],
				Codec:          opts.codec,
				Persistent:     opts.persistent,
				MaxHistory:     opts.maxHistory,
				BufferSize:     opts.bufferSize,
				MaxSubscribers: opts.maxSubscribers,
				TtlMs:          opts.ttl.Milliseconds(),
			}
			return call(flags, newMessagingClient, "failed to create the channel",
				platformv1.MessagingServiceClient.CreateChannel, request,
				func(reply *platformv1.CreateMessagingChannelResponse) *cli.TableData {
					return fieldsTable(reply.GetChannel())
				})
		})
	f := cmd.Flags()
	f.StringVar(&opts.codec, "codec", "", "default codec of the channel's messages: json, msgpack or protobuf")
	f.BoolVar(&opts.persistent, "persistent", false, "keep the channel across restarts")
	f.Int32Var(&opts.maxHistory, "max-history", 0, "messages kept for replay (default none)")
	f.Int32Var(&opts.bufferSize, "buffer-size", 0, "per-subscriber delivery buffer")
	f.Int32Var(&opts.maxSubscribers, "max-subscribers", 0, "most subscribers the channel accepts")
	f.DurationVar(&opts.ttl, "ttl", 0, "how long a message lives")
	return cmd
}

// publishOptions are the flags of `messaging publish`.
type publishOptions struct {
	messageID string
	dedupKey  string
	codec     string
	metadata  map[string]string
}

func newMessagingPublishCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &publishOptions{}
	cmd := newCommand(getFlags, "publish CHANNEL PAYLOAD", "Publish a message to a channel", cobra.ExactArgs(2),
		func(flags *cli.CommonFlags, args []string) error {
			request := &platformv1.PublishMessageRequest{
				Channel:   args[0],
				Payload:   []byte(args[1]),
				MessageId: opts.messageID,
				DedupKey:  opts.dedupKey,
				Codec:     opts.codec,
				Metadata:  opts.metadata,
			}
			return call(flags, newMessagingClient, "failed to publish the message",
				platformv1.MessagingServiceClient.Publish, request,
				confirmation[*platformv1.PublishMessageResponse]("channel", args[0], "published"))
		})
	f := cmd.Flags()
	f.StringVar(&opts.messageID, "message-id", "", "message ID (default assigned by the service)")
	f.StringVar(&opts.dedupKey, "dedup-key", "", "key that collapses repeats within the dedup window")
	f.StringVar(&opts.codec, "codec", "", "codec of this message, overriding the channel's")
	f.StringToStringVar(&opts.metadata, "metadata", nil, "metadata as key=value; repeatable")
	return cmd
}
