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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Application service QUIC wire mapping.
//
// CacheService, SchedulerService, MessagingService and ObjectStorageService
// each multiplex under their category opcode (0x53, 0x54, 0x55, 0x60) with
// the sub-opcode in payload[0]
// and the MessagePack-encoded platform.v1 request in payload[1:]. The daemon
// dispatcher (pkg/api/daemon/quic_app_services.go::handleAppServiceCategory)
// decodes the same generated types, so the MessagePack keys match on both
// sides by construction.

// appServiceSubOpcode is the category and sub-opcode of one method.
type appServiceSubOpcode struct {
	category byte
	sub      byte
}

// appServiceSubOpcodes routes the application service methods to their
// category and sub-opcode bytes.
var appServiceSubOpcodes = map[string]appServiceSubOpcode{
	platformv1.CacheService_GetStats_FullMethodName:     {quicwire.OpCacheCategory, quicwire.CacheSubGetStats},
	platformv1.CacheService_Clear_FullMethodName:        {quicwire.OpCacheCategory, quicwire.CacheSubClear},
	platformv1.CacheService_GetConfig_FullMethodName:    {quicwire.OpCacheCategory, quicwire.CacheSubGetConfig},
	platformv1.CacheService_UpdateConfig_FullMethodName: {quicwire.OpCacheCategory, quicwire.CacheSubUpdateConfig},

	platformv1.SchedulerService_CreateJob_FullMethodName:     {quicwire.OpSchedulerCategory, quicwire.SchedulerSubCreateJob},
	platformv1.SchedulerService_GetJob_FullMethodName:        {quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetJob},
	platformv1.SchedulerService_UpdateJob_FullMethodName:     {quicwire.OpSchedulerCategory, quicwire.SchedulerSubUpdateJob},
	platformv1.SchedulerService_DeleteJob_FullMethodName:     {quicwire.OpSchedulerCategory, quicwire.SchedulerSubDeleteJob},
	platformv1.SchedulerService_ListJobs_FullMethodName:      {quicwire.OpSchedulerCategory, quicwire.SchedulerSubListJobs},
	platformv1.SchedulerService_TriggerJob_FullMethodName:    {quicwire.OpSchedulerCategory, quicwire.SchedulerSubTriggerJob},
	platformv1.SchedulerService_PauseJob_FullMethodName:      {quicwire.OpSchedulerCategory, quicwire.SchedulerSubPauseJob},
	platformv1.SchedulerService_ResumeJob_FullMethodName:     {quicwire.OpSchedulerCategory, quicwire.SchedulerSubResumeJob},
	platformv1.SchedulerService_CancelJob_FullMethodName:     {quicwire.OpSchedulerCategory, quicwire.SchedulerSubCancelJob},
	platformv1.SchedulerService_GetJobHistory_FullMethodName: {quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetJobHistory},
	platformv1.SchedulerService_GetStatus_FullMethodName:     {quicwire.OpSchedulerCategory, quicwire.SchedulerSubGetStatus},

	platformv1.MessagingService_CreateChannel_FullMethodName:   {quicwire.OpMessagingCategory, quicwire.MessagingSubCreateChannel},
	platformv1.MessagingService_DeleteChannel_FullMethodName:   {quicwire.OpMessagingCategory, quicwire.MessagingSubDeleteChannel},
	platformv1.MessagingService_GetChannel_FullMethodName:      {quicwire.OpMessagingCategory, quicwire.MessagingSubGetChannel},
	platformv1.MessagingService_ListChannels_FullMethodName:    {quicwire.OpMessagingCategory, quicwire.MessagingSubListChannels},
	platformv1.MessagingService_Publish_FullMethodName:         {quicwire.OpMessagingCategory, quicwire.MessagingSubPublish},
	platformv1.MessagingService_GetStats_FullMethodName:        {quicwire.OpMessagingCategory, quicwire.MessagingSubGetStats},
	platformv1.MessagingService_GetDedupStats_FullMethodName:   {quicwire.OpMessagingCategory, quicwire.MessagingSubGetDedupStats},
	platformv1.MessagingService_GetChannelStats_FullMethodName: {quicwire.OpMessagingCategory, quicwire.MessagingSubGetChannelStats},

	platformv1.ObjectStorageService_PutObject_FullMethodName:         {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubPutObject},
	platformv1.ObjectStorageService_GetObject_FullMethodName:         {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubGetObject},
	platformv1.ObjectStorageService_DeleteObject_FullMethodName:      {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubDeleteObject},
	platformv1.ObjectStorageService_HeadObject_FullMethodName:        {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubHeadObject},
	platformv1.ObjectStorageService_ListObjects_FullMethodName:       {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubListObjects},
	platformv1.ObjectStorageService_CopyObject_FullMethodName:        {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubCopyObject},
	platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName:  {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubListObjectsByTag},
	platformv1.ObjectStorageService_ListTenantObjects_FullMethodName: {quicwire.OpObjectStorageCategory, quicwire.ObjectStorageSubListTenantObjects},
}

// init merges the application service wire mapping into the shared adapter
// tables. The file name sorts before adapter.go so this init runs before the
// adapter's category-invariant assertion.
func init() {
	for method, route := range appServiceSubOpcodes {
		categoryOpcodes[route.category] = struct{}{}
		grpcMethodToOpcodeMap[method] = route.category
		categorySubOpcodeMap[method] = route.sub
	}
}
