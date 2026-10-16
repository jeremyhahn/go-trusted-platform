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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Wire contract
// =============================================================================
//
// The SDK QUIC transport adapter routes every CacheService, SchedulerService,
// MessagingService, ObjectStorageService and SwitchService method to its
// category opcode (0x53, 0x54, 0x55, 0x60, 0xCC) with the sub-opcode in
// payload[0] and the
// MessagePack-encoded platform.v1 request in payload[1:]. The handlers run the
// same gRPC service instances the other transports use, so a node without the
// service answers StatusUnavailable naming it on QUIC as it does everywhere
// else.

// appQUICHandler is one application service sub-operation handler
// (map-based dispatch for O(1) routing).
type appQUICHandler func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response

// appQUICCategory is one application service category: the service name its
// unavailable answer carries, the wired-service check and its sub-opcodes.
type appQUICCategory struct {
	service  string
	wired    func(h *QUICServiceHandler) bool
	handlers map[byte]appQUICHandler
}

func quicCacheServer(h *QUICServiceHandler) platformv1.CacheServiceServer {
	return h.cacheService
}

func quicSchedulerServer(h *QUICServiceHandler) platformv1.SchedulerServiceServer {
	return h.schedulerService
}

func quicMessagingServer(h *QUICServiceHandler) platformv1.MessagingServiceServer {
	return h.messagingService
}

func quicObjectStorageServer(h *QUICServiceHandler) platformv1.ObjectStorageServiceServer {
	return h.objectStorageService
}

// cacheQUICHandlers routes cache sub-opcodes to their handlers.
var cacheQUICHandlers = map[byte]appQUICHandler{
	quicwire.CacheSubGetStats:     appQUICCall("CacheGetStats", quicCacheServer, platformv1.CacheServiceServer.GetStats),
	quicwire.CacheSubClear:        appQUICCall("CacheClear", quicCacheServer, platformv1.CacheServiceServer.Clear),
	quicwire.CacheSubGetConfig:    appQUICCall("CacheGetConfig", quicCacheServer, platformv1.CacheServiceServer.GetConfig),
	quicwire.CacheSubUpdateConfig: appQUICCall("CacheUpdateConfig", quicCacheServer, platformv1.CacheServiceServer.UpdateConfig),
}

// schedulerQUICHandlers routes scheduler sub-opcodes to their handlers.
var schedulerQUICHandlers = map[byte]appQUICHandler{
	quicwire.SchedulerSubCreateJob:     appQUICCall("SchedulerCreateJob", quicSchedulerServer, platformv1.SchedulerServiceServer.CreateJob),
	quicwire.SchedulerSubGetJob:        appQUICCall("SchedulerGetJob", quicSchedulerServer, platformv1.SchedulerServiceServer.GetJob),
	quicwire.SchedulerSubUpdateJob:     appQUICCall("SchedulerUpdateJob", quicSchedulerServer, platformv1.SchedulerServiceServer.UpdateJob),
	quicwire.SchedulerSubDeleteJob:     appQUICCall("SchedulerDeleteJob", quicSchedulerServer, platformv1.SchedulerServiceServer.DeleteJob),
	quicwire.SchedulerSubListJobs:      appQUICCall("SchedulerListJobs", quicSchedulerServer, platformv1.SchedulerServiceServer.ListJobs),
	quicwire.SchedulerSubTriggerJob:    appQUICCall("SchedulerTriggerJob", quicSchedulerServer, platformv1.SchedulerServiceServer.TriggerJob),
	quicwire.SchedulerSubPauseJob:      appQUICCall("SchedulerPauseJob", quicSchedulerServer, platformv1.SchedulerServiceServer.PauseJob),
	quicwire.SchedulerSubResumeJob:     appQUICCall("SchedulerResumeJob", quicSchedulerServer, platformv1.SchedulerServiceServer.ResumeJob),
	quicwire.SchedulerSubCancelJob:     appQUICCall("SchedulerCancelJob", quicSchedulerServer, platformv1.SchedulerServiceServer.CancelJob),
	quicwire.SchedulerSubGetJobHistory: appQUICCall("SchedulerGetJobHistory", quicSchedulerServer, platformv1.SchedulerServiceServer.GetJobHistory),
	quicwire.SchedulerSubGetStatus:     appQUICCall("SchedulerGetStatus", quicSchedulerServer, platformv1.SchedulerServiceServer.GetStatus),
}

// messagingQUICHandlers routes messaging sub-opcodes to their handlers.
var messagingQUICHandlers = map[byte]appQUICHandler{
	quicwire.MessagingSubCreateChannel:   appQUICCall("MessagingCreateChannel", quicMessagingServer, platformv1.MessagingServiceServer.CreateChannel),
	quicwire.MessagingSubDeleteChannel:   appQUICCall("MessagingDeleteChannel", quicMessagingServer, platformv1.MessagingServiceServer.DeleteChannel),
	quicwire.MessagingSubGetChannel:      appQUICCall("MessagingGetChannel", quicMessagingServer, platformv1.MessagingServiceServer.GetChannel),
	quicwire.MessagingSubListChannels:    appQUICCall("MessagingListChannels", quicMessagingServer, platformv1.MessagingServiceServer.ListChannels),
	quicwire.MessagingSubPublish:         appQUICCall("MessagingPublish", quicMessagingServer, platformv1.MessagingServiceServer.Publish),
	quicwire.MessagingSubGetStats:        appQUICCall("MessagingGetStats", quicMessagingServer, platformv1.MessagingServiceServer.GetStats),
	quicwire.MessagingSubGetDedupStats:   appQUICCall("MessagingGetDedupStats", quicMessagingServer, platformv1.MessagingServiceServer.GetDedupStats),
	quicwire.MessagingSubGetChannelStats: appQUICCall("MessagingGetChannelStats", quicMessagingServer, platformv1.MessagingServiceServer.GetChannelStats),
}

// objectStorageQUICHandlers routes object storage sub-opcodes to their
// handlers.
var objectStorageQUICHandlers = map[byte]appQUICHandler{
	quicwire.ObjectStorageSubPutObject:         appQUICCall("ObjectStoragePutObject", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.PutObject),
	quicwire.ObjectStorageSubGetObject:         appQUICCall("ObjectStorageGetObject", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.GetObject),
	quicwire.ObjectStorageSubDeleteObject:      appQUICCall("ObjectStorageDeleteObject", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.DeleteObject),
	quicwire.ObjectStorageSubHeadObject:        appQUICCall("ObjectStorageHeadObject", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.HeadObject),
	quicwire.ObjectStorageSubListObjects:       appQUICCall("ObjectStorageListObjects", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.ListObjects),
	quicwire.ObjectStorageSubCopyObject:        appQUICCall("ObjectStorageCopyObject", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.CopyObject),
	quicwire.ObjectStorageSubListObjectsByTag:  appQUICCall("ObjectStorageListObjectsByTag", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.ListObjectsByTag),
	quicwire.ObjectStorageSubListTenantObjects: appQUICCall("ObjectStorageListTenantObjects", quicObjectStorageServer, platformv1.ObjectStorageServiceServer.ListTenantObjects),
}

// appQUICCategories routes the category opcodes whose sub-opcodes all call
// one gRPC servicer: the application services and the switch service.
var appQUICCategories = map[byte]appQUICCategory{
	quicwire.OpCacheCategory: {
		service:  appservices.ServiceCache,
		wired:    func(h *QUICServiceHandler) bool { return h.cacheService != nil },
		handlers: cacheQUICHandlers,
	},
	quicwire.OpSchedulerCategory: {
		service:  appservices.ServiceScheduler,
		wired:    func(h *QUICServiceHandler) bool { return h.schedulerService != nil },
		handlers: schedulerQUICHandlers,
	},
	quicwire.OpMessagingCategory: {
		service:  appservices.ServiceMessaging,
		wired:    func(h *QUICServiceHandler) bool { return h.messagingService != nil },
		handlers: messagingQUICHandlers,
	},
	quicwire.OpObjectStorageCategory: {
		service:  appservices.ServiceObjectStorage,
		wired:    func(h *QUICServiceHandler) bool { return h.objectStorageService != nil },
		handlers: objectStorageQUICHandlers,
	},
	quicwire.OpSwitchCategory: {
		service:  "switch",
		wired:    func(h *QUICServiceHandler) bool { return h.switchServer != nil },
		handlers: switchQUICHandlers,
	},
}

// appQUICCall builds the handler for one application service method: it
// decodes the sub-payload into the method's request message, runs the method
// on the server the handler holds and encodes the reply, or maps the gRPC
// status to a QUIC status on failure.
func appQUICCall[S any, Req any, Resp any](op string, server func(*QUICServiceHandler) S, method func(S, context.Context, *Req) (Resp, error)) appQUICHandler {
	return func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response {
		var request Req
		if err := quicwire.DecodePayload(body, &request); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}

		resp, err := method(server(h), ctx, &request)
		if err != nil {
			return h.grpcDelegateErrorToQUIC(op, err)
		}
		return h.encodeGRPCDelegateResponse(resp)
	}
}

// SetAppServices wires the cache, scheduler, messaging and object storage
// services into the QUIC handler. The same instances back REST, gRPC, MCP, and the Unix socket.
// A nil server leaves its category unavailable.
func (h *QUICServiceHandler) SetAppServices(servers appServiceServers) {
	h.cacheService = nil
	h.schedulerService = nil
	h.messagingService = nil
	h.objectStorageService = nil
	if servers.cache != nil {
		h.cacheService = servers.cache
	}
	if servers.scheduler != nil {
		h.schedulerService = servers.scheduler
	}
	if servers.messaging != nil {
		h.messagingService = servers.messaging
	}
	if servers.objectStorage != nil {
		h.objectStorageService = servers.objectStorage
	}
}

// handleAppServiceCategory dispatches an application service category opcode.
// payload[0] selects the sub-operation and payload[1:] carries the request.
func (h *QUICServiceHandler) handleAppServiceCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	category, ok := appQUICCategories[req.Opcode]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
	if !category.wired(h) {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: category.service})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	handler, ok := category.handlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx, req.Payload[1:])
}
