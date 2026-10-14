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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/messaging"
)

// fakeMessagingClient serves the calls MessagingService makes. The embedded
// interface is nil: the subscription calls the service never makes would
// panic, which is what a test wants if one ever did.
type fakeMessagingClient struct {
	messaging.Client

	err        error
	name       string
	createReq  *messaging.CreateChannelRequest
	publishReq *messaging.PublishRequest
}

func (f *fakeMessagingClient) CreateChannel(_ context.Context, req *messaging.CreateChannelRequest) (*messaging.Channel, error) {
	f.createReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.Channel{Name: req.Name, Codec: req.Codec}, nil
}

func (f *fakeMessagingClient) DeleteChannel(_ context.Context, name string) error {
	f.name = name
	return f.err
}

func (f *fakeMessagingClient) GetChannel(_ context.Context, name string) (*messaging.Channel, error) {
	f.name = name
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.Channel{Name: name}, nil
}

func (f *fakeMessagingClient) ListChannels(context.Context) (*messaging.ListChannelsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.ListChannelsResponse{Channels: []*messaging.Channel{{Name: "events"}}}, nil
}

func (f *fakeMessagingClient) Publish(_ context.Context, req *messaging.PublishRequest) error {
	f.publishReq = req
	return f.err
}

func (f *fakeMessagingClient) GetStats(context.Context) (*messaging.Stats, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.Stats{TotalChannels: 1}, nil
}

func (f *fakeMessagingClient) GetDedupStats(context.Context) (*messaging.DedupStats, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.DedupStats{TotalChecks: 2}, nil
}

func (f *fakeMessagingClient) GetChannelStats(_ context.Context, channel string) (*messaging.ChannelStats, error) {
	f.name = channel
	if f.err != nil {
		return nil, f.err
	}
	return &messaging.ChannelStats{Name: channel}, nil
}

func messagingServiceWith(client *fakeMessagingClient) *MessagingService {
	return NewMessagingService(func() messaging.Client { return client })
}

// messagingCalls runs every MessagingService method once with a valid
// request and returns the errors, keyed by the op name ErrCallFailed carries.
func messagingCalls(svc *MessagingService) map[string]error {
	ctx := context.Background()
	errs := map[string]error{}
	_, errs["create channel"] = svc.CreateChannel(ctx, &messaging.CreateChannelRequest{Name: "events", Codec: messaging.CodecJSON})
	errs["delete channel"] = svc.DeleteChannel(ctx, "events")
	_, errs["get channel"] = svc.GetChannel(ctx, "events")
	_, errs["list channels"] = svc.ListChannels(ctx)
	errs["publish"] = svc.Publish(ctx, &messaging.PublishRequest{Channel: "events", Payload: []byte("hi")})
	_, errs["stats"] = svc.Stats(ctx)
	_, errs["dedup stats"] = svc.DedupStats(ctx)
	_, errs["channel stats"] = svc.ChannelStats(ctx, "events")
	return errs
}

func TestMessagingService_NotConfigured(t *testing.T) {
	for op, err := range messagingCalls(NewMessagingService(nil)) {
		assert.Equal(t, ErrNotConfigured{Service: ServiceMessaging}, err, op)
	}
	for op, err := range messagingCalls(NewMessagingService(func() messaging.Client { return nil })) {
		assert.Equal(t, ErrNotConfigured{Service: ServiceMessaging}, err, op)
	}
}

func TestMessagingService_EveryCallReachesTheSDK(t *testing.T) {
	client := &fakeMessagingClient{}
	for op, err := range messagingCalls(messagingServiceWith(client)) {
		assert.NoError(t, err, op)
	}
	assert.Equal(t, "events", client.name)
	assert.Equal(t, []byte("hi"), client.publishReq.Payload)
}

func TestMessagingService_EveryCallWrapsSDKErrors(t *testing.T) {
	for op, err := range messagingCalls(messagingServiceWith(&fakeMessagingClient{err: errSDK})) {
		assertCallFailed(t, err, ServiceMessaging, op)
	}
}

// The embedded transport of go-quicbaas sdk/go v0.12.0-alpha registers no
// quicbaas.Messaging handler, so every call there fails with
// UnknownMethodError: the service is not served, not a failed call.
func TestMessagingService_UnservedMethodIsNotConfigured(t *testing.T) {
	unserved := embedded.NewUnknownMethodError("quicbaas.Messaging", "Publish")
	for op, err := range messagingCalls(messagingServiceWith(&fakeMessagingClient{err: unserved})) {
		assert.Equal(t, ErrNotConfigured{Service: ServiceMessaging}, err, op)
	}
}

func TestMessagingService_CreateChannel(t *testing.T) {
	client := &fakeMessagingClient{}
	req := &messaging.CreateChannelRequest{Name: "events", Codec: messaging.CodecMsgpack, MaxHistory: 10, TTL: time.Minute}
	channel, err := messagingServiceWith(client).CreateChannel(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "events", channel.Name)
	assert.Same(t, req, client.createReq)
}

func TestMessagingService_CreateChannelRefusesInvalidRequest(t *testing.T) {
	cases := map[string]struct {
		req   *messaging.CreateChannelRequest
		field string
	}{
		"nil request":      {nil, "request"},
		"no name":          {&messaging.CreateChannelRequest{}, "name"},
		"unknown codec":    {&messaging.CreateChannelRequest{Name: "c", Codec: "xml"}, "codec"},
		"negative history": {&messaging.CreateChannelRequest{Name: "c", MaxHistory: -1}, "max_history"},
		"negative buffer":  {&messaging.CreateChannelRequest{Name: "c", BufferSize: -1}, "buffer_size"},
		"negative subs":    {&messaging.CreateChannelRequest{Name: "c", MaxSubs: -1}, "max_subscribers"},
		"negative ttl":     {&messaging.CreateChannelRequest{Name: "c", TTL: -time.Second}, "ttl"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client := &fakeMessagingClient{}
			_, err := messagingServiceWith(client).CreateChannel(context.Background(), tc.req)
			assertInvalid(t, err, tc.field)
			assert.Nil(t, client.createReq, "an invalid channel must not reach the SDK")
		})
	}
}

func TestMessagingService_NamedCallsRefuseEmptyName(t *testing.T) {
	client := &fakeMessagingClient{}
	svc := messagingServiceWith(client)
	ctx := context.Background()

	assertInvalid(t, svc.DeleteChannel(ctx, ""), "name")
	_, err := svc.GetChannel(ctx, "")
	assertInvalid(t, err, "name")
	_, err = svc.ChannelStats(ctx, "")
	assertInvalid(t, err, "channel")
	assert.Empty(t, client.name, "an empty name must not reach the SDK")
}

func TestMessagingService_PublishRefusesInvalidRequest(t *testing.T) {
	client := &fakeMessagingClient{}
	svc := messagingServiceWith(client)
	ctx := context.Background()

	assertInvalid(t, svc.Publish(ctx, nil), "request")
	assertInvalid(t, svc.Publish(ctx, &messaging.PublishRequest{}), "channel")
	assertInvalid(t, svc.Publish(ctx, &messaging.PublishRequest{Channel: "events", Codec: "yaml"}), "codec")
	assert.Nil(t, client.publishReq)
}
