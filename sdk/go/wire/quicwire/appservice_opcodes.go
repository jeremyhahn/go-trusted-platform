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

package quicwire

// Application service category opcodes.
//
// CacheService, SchedulerService, MessagingService and ObjectStorageService —
// the services platformd serves over the composed go-quicbaas SDK — each
// multiplex under one category: payload[0] selects the sub-operation and
// payload[1:] carries the MessagePack-encoded platform.v1 request. The
// server-side dispatcher lives at pkg/api/daemon/quic_app_services.go, and
// the SDK QUIC adapter mapping at sdk/go/transport/quic/aac_app_services.go.
//
// Cache, Scheduler and Messaging take 0x53-0x55, the rest of the block
// reserved after OpNTPCategory. ObjectStorage takes 0x60, the first of the
// top-level bytes the VM opcodes left when they moved under
// OpVMExtendedCategory.
const (
	// OpCacheCategory multiplexes the cache sub-operations.
	OpCacheCategory byte = 0x53

	// OpSchedulerCategory multiplexes the scheduler sub-operations.
	OpSchedulerCategory byte = 0x54

	// OpMessagingCategory multiplexes the messaging sub-operations.
	OpMessagingCategory byte = 0x55

	// OpObjectStorageCategory multiplexes the object storage sub-operations.
	OpObjectStorageCategory byte = 0x60
)

// Cache sub-opcodes for the OpCacheCategory (0x53) category opcode.
const (
	// CacheSubGetStats returns the cache statistics.
	CacheSubGetStats byte = 0x01

	// CacheSubClear removes cache entries.
	CacheSubClear byte = 0x02

	// CacheSubGetConfig returns the cache configuration.
	CacheSubGetConfig byte = 0x03

	// CacheSubUpdateConfig changes the cache configuration.
	CacheSubUpdateConfig byte = 0x04
)

// Scheduler sub-opcodes for the OpSchedulerCategory (0x54) category opcode.
const (
	// SchedulerSubCreateJob schedules a job.
	SchedulerSubCreateJob byte = 0x01

	// SchedulerSubGetJob returns one job.
	SchedulerSubGetJob byte = 0x02

	// SchedulerSubUpdateJob changes a job.
	SchedulerSubUpdateJob byte = 0x03

	// SchedulerSubDeleteJob removes a job.
	SchedulerSubDeleteJob byte = 0x04

	// SchedulerSubListJobs lists jobs.
	SchedulerSubListJobs byte = 0x05

	// SchedulerSubTriggerJob runs a job now.
	SchedulerSubTriggerJob byte = 0x06

	// SchedulerSubPauseJob pauses a job.
	SchedulerSubPauseJob byte = 0x07

	// SchedulerSubResumeJob resumes a paused job.
	SchedulerSubResumeJob byte = 0x08

	// SchedulerSubCancelJob cancels a job.
	SchedulerSubCancelJob byte = 0x09

	// SchedulerSubGetJobHistory returns the executions of a job.
	SchedulerSubGetJobHistory byte = 0x0A

	// SchedulerSubGetStatus returns the scheduler status.
	SchedulerSubGetStatus byte = 0x0B
)

// Messaging sub-opcodes for the OpMessagingCategory (0x55) category opcode.
const (
	// MessagingSubCreateChannel creates a channel.
	MessagingSubCreateChannel byte = 0x01

	// MessagingSubDeleteChannel deletes a channel.
	MessagingSubDeleteChannel byte = 0x02

	// MessagingSubGetChannel returns one channel.
	MessagingSubGetChannel byte = 0x03

	// MessagingSubListChannels lists the channels.
	MessagingSubListChannels byte = 0x04

	// MessagingSubPublish publishes a message.
	MessagingSubPublish byte = 0x05

	// MessagingSubGetStats returns the push service counters.
	MessagingSubGetStats byte = 0x06

	// MessagingSubGetDedupStats returns the deduplication counters.
	MessagingSubGetDedupStats byte = 0x07

	// MessagingSubGetChannelStats returns the counters of one channel.
	MessagingSubGetChannelStats byte = 0x08
)

// Object storage sub-opcodes for the OpObjectStorageCategory (0x60) category
// opcode.
const (
	// ObjectStorageSubPutObject stores an object.
	ObjectStorageSubPutObject byte = 0x01

	// ObjectStorageSubGetObject returns an object with its data.
	ObjectStorageSubGetObject byte = 0x02

	// ObjectStorageSubDeleteObject removes an object.
	ObjectStorageSubDeleteObject byte = 0x03

	// ObjectStorageSubHeadObject returns the metadata of an object.
	ObjectStorageSubHeadObject byte = 0x04

	// ObjectStorageSubListObjects lists the objects under a key prefix.
	ObjectStorageSubListObjects byte = 0x05

	// ObjectStorageSubCopyObject copies an object to a new key.
	ObjectStorageSubCopyObject byte = 0x06

	// ObjectStorageSubListObjectsByTag lists the objects whose tag has a
	// value.
	ObjectStorageSubListObjectsByTag byte = 0x07

	// ObjectStorageSubListTenantObjects lists the objects one tenant owns.
	ObjectStorageSubListTenantObjects byte = 0x08
)
