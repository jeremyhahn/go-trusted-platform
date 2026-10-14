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

package appservices

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/messaging"
)

// knownCodecs are the codecs a channel or message may name. Empty selects
// the default.
var knownCodecs = map[string]struct{}{
	"":                      {},
	messaging.CodecJSON:     {},
	messaging.CodecMsgpack:  {},
	messaging.CodecProtobuf: {},
}

// MessagingService manages the channels of the composed SDK's push service
// and publishes to them. Subscribing is not part of it: a subscription
// delivers to the SDK session that opened it.
type MessagingService struct {
	resolver Resolver[messaging.Client]
}

// NewMessagingService returns a MessagingService that reaches the SDK's
// Messaging group through resolver.
func NewMessagingService(resolver Resolver[messaging.Client]) *MessagingService {
	return &MessagingService{resolver: resolver}
}

// CreateChannel creates a channel.
func (s *MessagingService) CreateChannel(ctx context.Context, req *messaging.CreateChannelRequest) (*messaging.Channel, error) {
	if err := validateCreateChannel(req); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return nil, err
	}
	channel, err := client.CreateChannel(ctx, req)
	return channel, callFailed(ServiceMessaging, "create channel", err)
}

// DeleteChannel deletes a channel.
func (s *MessagingService) DeleteChannel(ctx context.Context, name string) error {
	if err := requireName(ServiceMessaging, "name", name); err != nil {
		return err
	}
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return err
	}
	return callFailed(ServiceMessaging, "delete channel", client.DeleteChannel(ctx, name))
}

// GetChannel returns one channel.
func (s *MessagingService) GetChannel(ctx context.Context, name string) (*messaging.Channel, error) {
	if err := requireName(ServiceMessaging, "name", name); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return nil, err
	}
	channel, err := client.GetChannel(ctx, name)
	return channel, callFailed(ServiceMessaging, "get channel", err)
}

// ListChannels lists every channel.
func (s *MessagingService) ListChannels(ctx context.Context) (*messaging.ListChannelsResponse, error) {
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListChannels(ctx)
	return resp, callFailed(ServiceMessaging, "list channels", err)
}

// Publish publishes one message to a channel.
func (s *MessagingService) Publish(ctx context.Context, req *messaging.PublishRequest) error {
	if req == nil {
		return ErrInvalidArgument{Service: ServiceMessaging, Field: "request", Reason: "is required"}
	}
	if err := requireName(ServiceMessaging, "channel", req.Channel); err != nil {
		return err
	}
	if err := requireKnownCodec(req.Codec); err != nil {
		return err
	}
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return err
	}
	return callFailed(ServiceMessaging, "publish", client.Publish(ctx, req))
}

// Stats returns the push service counters.
func (s *MessagingService) Stats(ctx context.Context) (*messaging.Stats, error) {
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return nil, err
	}
	stats, err := client.GetStats(ctx)
	return stats, callFailed(ServiceMessaging, "stats", err)
}

// DedupStats returns the deduplication counters.
func (s *MessagingService) DedupStats(ctx context.Context) (*messaging.DedupStats, error) {
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return nil, err
	}
	stats, err := client.GetDedupStats(ctx)
	return stats, callFailed(ServiceMessaging, "dedup stats", err)
}

// ChannelStats returns the counters of one channel.
func (s *MessagingService) ChannelStats(ctx context.Context, channel string) (*messaging.ChannelStats, error) {
	if err := requireName(ServiceMessaging, "channel", channel); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceMessaging, s.resolver)
	if err != nil {
		return nil, err
	}
	stats, err := client.GetChannelStats(ctx, channel)
	return stats, callFailed(ServiceMessaging, "channel stats", err)
}

func validateCreateChannel(req *messaging.CreateChannelRequest) error {
	if req == nil {
		return ErrInvalidArgument{Service: ServiceMessaging, Field: "request", Reason: "is required"}
	}
	if err := requireName(ServiceMessaging, "name", req.Name); err != nil {
		return err
	}
	if err := requireKnownCodec(req.Codec); err != nil {
		return err
	}
	counts := []struct {
		field string
		value int
	}{
		{"max_history", req.MaxHistory},
		{"buffer_size", req.BufferSize},
		{"max_subscribers", req.MaxSubs},
	}
	for _, count := range counts {
		if err := requireNotNegative(ServiceMessaging, count.field, count.value); err != nil {
			return err
		}
	}
	return requireNotNegative(ServiceMessaging, "ttl", req.TTL)
}

func requireKnownCodec(codec string) error {
	if _, ok := knownCodecs[codec]; !ok {
		return ErrInvalidArgument{Service: ServiceMessaging, Field: "codec", Reason: "must be json, msgpack or protobuf"}
	}
	return nil
}
