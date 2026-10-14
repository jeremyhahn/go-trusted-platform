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

package messaging

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/messaging"
)

// Client is the messaging client returned by quicbaas.Client.Messaging().
type Client = upstream.Client

// Channels, subscriptions and the messages they carry.
type (
	// Channel is a notification channel as the server stores it.
	Channel = upstream.Channel
	// Subscription is a live subscription to a channel.
	Subscription = upstream.Subscription
	// SubscriptionFilter narrows the messages a subscription receives.
	SubscriptionFilter = upstream.SubscriptionFilter
	// Message is one message delivered on a channel.
	Message = upstream.Message
	// MessageType is the kind of a Message.
	MessageType = upstream.MessageType
	// EventType is the kind of key change a watch reports.
	EventType = upstream.EventType
	// Stats are the push service's statistics.
	Stats = upstream.Stats
	// ChannelStats are one channel's statistics.
	ChannelStats = upstream.ChannelStats
	// DedupStats are the deduplication statistics.
	DedupStats = upstream.DedupStats
	// DedupInfo is the deduplication state of one message.
	DedupInfo = upstream.DedupInfo
)

// Delta notifications: the changes to an entity and the helpers that build
// and apply them.
type (
	// DeltaPayload is the set of changes between two versions of an entity.
	DeltaPayload = upstream.DeltaPayload
	// FieldChange is one change within a DeltaPayload.
	FieldChange = upstream.FieldChange
	// OpType is the operation a FieldChange performs.
	OpType = upstream.OpType
	// DeltaBuilder assembles a DeltaPayload.
	DeltaBuilder = upstream.DeltaBuilder
)

// DeltaApplier applies a DeltaPayload to an entity of type E.
type DeltaApplier[E any] = upstream.DeltaApplier[E]

// Requests and responses of the Client verbs.
type (
	CreateChannelRequest = upstream.CreateChannelRequest
	DeleteChannelRequest = upstream.DeleteChannelRequest
	GetChannelRequest    = upstream.GetChannelRequest
	ListChannelsRequest  = upstream.ListChannelsRequest
	ListChannelsResponse = upstream.ListChannelsResponse
	SubscribeRequest     = upstream.SubscribeRequest
	UnsubscribeRequest   = upstream.UnsubscribeRequest
	PublishRequest       = upstream.PublishRequest
	PublishDeltaRequest  = upstream.PublishDeltaRequest
	WatchChannelRequest  = upstream.WatchChannelRequest
)

// Codec identifiers for message serialization.
const (
	CodecJSON     = upstream.CodecJSON
	CodecMsgpack  = upstream.CodecMsgpack
	CodecProtobuf = upstream.CodecProtobuf
)

// Message types.
const (
	MessageTypeSubscribe    = upstream.MessageTypeSubscribe
	MessageTypeUnsubscribe  = upstream.MessageTypeUnsubscribe
	MessageTypePublish      = upstream.MessageTypePublish
	MessageTypeNotification = upstream.MessageTypeNotification
	MessageTypePing         = upstream.MessageTypePing
	MessageTypePong         = upstream.MessageTypePong
	MessageTypeAck          = upstream.MessageTypeAck
	MessageTypeError        = upstream.MessageTypeError
	MessageTypeData         = upstream.MessageTypeData
	MessageTypeControl      = upstream.MessageTypeControl
	MessageTypeHeartbeat    = upstream.MessageTypeHeartbeat
)

// Watch event types.
const (
	EventTypePut    = upstream.EventTypePut
	EventTypeDelete = upstream.EventTypeDelete
)

// Field change operations.
const (
	OpSet       = upstream.OpSet
	OpDelete    = upstream.OpDelete
	OpAppend    = upstream.OpAppend
	OpIncrement = upstream.OpIncrement
)

// NewDeltaBuilder returns an empty upstream DeltaBuilder.
func NewDeltaBuilder() *DeltaBuilder {
	return upstream.NewDeltaBuilder()
}

// NewDeltaApplier returns the upstream DeltaApplier for entities of type E.
func NewDeltaApplier[E any]() *DeltaApplier[E] {
	return upstream.NewDeltaApplier[E]()
}
