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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/messaging"
)

// MessagingGRPCService implements platformv1.MessagingServiceServer over
// the appservices messaging service.
type MessagingGRPCService struct {
	platformv1.UnimplementedMessagingServiceServer

	service *appservices.MessagingService
	logger  *logging.Logger
}

// NewMessagingGRPCService returns the messaging gRPC service. A nil service
// answers every call with the not-configured status.
func NewMessagingGRPCService(logger *logging.Logger, service *appservices.MessagingService) *MessagingGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	if service == nil {
		service = appservices.NewMessagingService(nil)
	}
	return &MessagingGRPCService{service: service, logger: logger}
}

// CreateChannel creates a channel.
func (s *MessagingGRPCService) CreateChannel(ctx context.Context, req *platformv1.CreateMessagingChannelRequest) (*platformv1.CreateMessagingChannelResponse, error) {
	channel, err := s.service.CreateChannel(ctx, &messaging.CreateChannelRequest{
		Name:       req.GetName(),
		Codec:      req.GetCodec(),
		Persistent: req.GetPersistent(),
		MaxHistory: int(req.GetMaxHistory()),
		BufferSize: int(req.GetBufferSize()),
		MaxSubs:    int(req.GetMaxSubscribers()),
		TTL:        appDuration(req.GetTtlMs()),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "messaging create channel", err)
	}
	return &platformv1.CreateMessagingChannelResponse{Channel: messagingChannelToPb(channel)}, nil
}

// DeleteChannel deletes a channel.
func (s *MessagingGRPCService) DeleteChannel(ctx context.Context, req *platformv1.DeleteMessagingChannelRequest) (*platformv1.DeleteMessagingChannelResponse, error) {
	if err := s.service.DeleteChannel(ctx, req.GetName()); err != nil {
		return nil, appServiceError(s.logger, "messaging delete channel", err)
	}
	return &platformv1.DeleteMessagingChannelResponse{}, nil
}

// GetChannel returns one channel.
func (s *MessagingGRPCService) GetChannel(ctx context.Context, req *platformv1.GetMessagingChannelRequest) (*platformv1.GetMessagingChannelResponse, error) {
	channel, err := s.service.GetChannel(ctx, req.GetName())
	if err != nil {
		return nil, appServiceError(s.logger, "messaging get channel", err)
	}
	return &platformv1.GetMessagingChannelResponse{Channel: messagingChannelToPb(channel)}, nil
}

// ListChannels lists every channel.
func (s *MessagingGRPCService) ListChannels(ctx context.Context, _ *platformv1.ListMessagingChannelsRequest) (*platformv1.ListMessagingChannelsResponse, error) {
	resp, err := s.service.ListChannels(ctx)
	if err != nil {
		return nil, appServiceError(s.logger, "messaging list channels", err)
	}
	channels := make([]*platformv1.MessagingChannel, 0, len(resp.Channels))
	for _, channel := range resp.Channels {
		if channel != nil {
			channels = append(channels, messagingChannelToPb(channel))
		}
	}
	return &platformv1.ListMessagingChannelsResponse{Channels: channels}, nil
}

// Publish publishes one message to a channel.
func (s *MessagingGRPCService) Publish(ctx context.Context, req *platformv1.PublishMessageRequest) (*platformv1.PublishMessageResponse, error) {
	err := s.service.Publish(ctx, &messaging.PublishRequest{
		Channel:   req.GetChannel(),
		Payload:   req.GetPayload(),
		MessageID: req.GetMessageId(),
		DedupKey:  req.GetDedupKey(),
		Codec:     req.GetCodec(),
		Metadata:  req.GetMetadata(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "messaging publish", err)
	}
	return &platformv1.PublishMessageResponse{}, nil
}

// GetStats returns the push service counters.
func (s *MessagingGRPCService) GetStats(ctx context.Context, _ *platformv1.GetMessagingStatsRequest) (*platformv1.GetMessagingStatsResponse, error) {
	stats, err := s.service.Stats(ctx)
	if err != nil {
		return nil, appServiceError(s.logger, "messaging stats", err)
	}
	return &platformv1.GetMessagingStatsResponse{
		TotalChannels:      stats.TotalChannels,
		TotalSubscriptions: stats.TotalSubscriptions,
		MessagesPublished:  stats.MessagesPublished,
		MessagesDelivered:  stats.MessagesDelivered,
		DedupHits:          stats.DedupHits,
		DroppedMessages:    stats.DroppedMessages,
		BufferUtilization:  stats.BufferUtilization,
	}, nil
}

// GetDedupStats returns the deduplication counters.
func (s *MessagingGRPCService) GetDedupStats(ctx context.Context, _ *platformv1.GetMessagingDedupStatsRequest) (*platformv1.GetMessagingDedupStatsResponse, error) {
	stats, err := s.service.DedupStats(ctx)
	if err != nil {
		return nil, appServiceError(s.logger, "messaging dedup stats", err)
	}
	return &platformv1.GetMessagingDedupStatsResponse{
		TotalChecks:        stats.TotalChecks,
		DuplicatesDetected: stats.DuplicatesDetected,
		UniqueMessages:     stats.UniqueMessages,
		CacheSize:          stats.CacheSize,
		WindowMs:           stats.WindowDuration.Milliseconds(),
	}, nil
}

// GetChannelStats returns the counters of one channel.
func (s *MessagingGRPCService) GetChannelStats(ctx context.Context, req *platformv1.GetMessagingChannelStatsRequest) (*platformv1.GetMessagingChannelStatsResponse, error) {
	stats, err := s.service.ChannelStats(ctx, req.GetChannel())
	if err != nil {
		return nil, appServiceError(s.logger, "messaging channel stats", err)
	}
	return &platformv1.GetMessagingChannelStatsResponse{
		Name:              stats.Name,
		Subscribers:       stats.Subscribers,
		MessagesPublished: stats.MessagesPublished,
		MessagesInHistory: appInt32(stats.MessagesInHistory),
	}, nil
}

func messagingChannelToPb(channel *messaging.Channel) *platformv1.MessagingChannel {
	if channel == nil {
		return nil
	}
	return &platformv1.MessagingChannel{
		Name:            channel.Name,
		Codec:           channel.Codec,
		CreatedAtUnixMs: appUnixMillis(channel.CreatedAt),
		Subscribers:     channel.Subscribers,
		Persistent:      channel.Persistent,
		MaxHistory:      appInt32(channel.MaxHistory),
		BufferSize:      appInt32(channel.BufferSize),
		TtlMs:           channel.TTL.Milliseconds(),
	}
}
