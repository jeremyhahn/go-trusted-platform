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

package rest

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Daemon REST roots of the application services
// (pkg/api/rest/app_service_handlers.go).
const (
	cacheBasePath         = "/api/v1/cache"
	schedulerBasePath     = "/api/v1/scheduler"
	messagingBasePath     = "/api/v1/messaging"
	objectStorageBasePath = "/api/v1/object-storage"
)

// appServiceRoutes maps every CacheService, SchedulerService,
// MessagingService and ObjectStorageService method to its daemon route.
// Item routes carry the job, channel or tenant in the path; GET and DELETE
// routes carry their filters in the query, named after the proto field; the
// rest of the request is the body. Object keys hold "/" and ":", so they
// travel in the query, never in the path.
var appServiceRoutes = map[string]templatedRoute{
	platformv1.CacheService_GetStats_FullMethodName:     appQueryRoute(cacheBasePath+"/stats", http.MethodGet, "entity_type"),
	platformv1.CacheService_GetConfig_FullMethodName:    appQueryRoute(cacheBasePath+"/config", http.MethodGet),
	platformv1.CacheService_UpdateConfig_FullMethodName: appQueryRoute(cacheBasePath+"/config", http.MethodPatch),
	platformv1.CacheService_Clear_FullMethodName:        appQueryRoute(cacheBasePath+"/entries", http.MethodDelete, "entity_type", "all"),

	platformv1.SchedulerService_CreateJob_FullMethodName: appQueryRoute(schedulerBasePath+"/jobs", http.MethodPost),
	platformv1.SchedulerService_ListJobs_FullMethodName: appQueryRoute(schedulerBasePath+"/jobs", http.MethodGet,
		"owner_type", "owner_id", "status", "job_type", "tags", "limit", "offset"),
	platformv1.SchedulerService_GetJob_FullMethodName:     appItemRoute(schedulerBasePath+"/jobs/{job_id}", http.MethodGet, "job_id"),
	platformv1.SchedulerService_UpdateJob_FullMethodName:  appItemRoute(schedulerBasePath+"/jobs/{job_id}", http.MethodPatch, "job_id"),
	platformv1.SchedulerService_DeleteJob_FullMethodName:  appItemRoute(schedulerBasePath+"/jobs/{job_id}", http.MethodDelete, "job_id"),
	platformv1.SchedulerService_TriggerJob_FullMethodName: appItemRoute(schedulerBasePath+"/jobs/{job_id}/trigger", http.MethodPost, "job_id"),
	platformv1.SchedulerService_PauseJob_FullMethodName:   appItemRoute(schedulerBasePath+"/jobs/{job_id}/pause", http.MethodPost, "job_id"),
	platformv1.SchedulerService_ResumeJob_FullMethodName:  appItemRoute(schedulerBasePath+"/jobs/{job_id}/resume", http.MethodPost, "job_id"),
	platformv1.SchedulerService_CancelJob_FullMethodName:  appItemRoute(schedulerBasePath+"/jobs/{job_id}/cancel", http.MethodPost, "job_id"),
	platformv1.SchedulerService_GetJobHistory_FullMethodName: appItemRoute(schedulerBasePath+"/jobs/{job_id}/history", http.MethodGet, "job_id",
		"limit", "offset", "start_time_unix_ms", "end_time_unix_ms", "status"),
	platformv1.SchedulerService_GetStatus_FullMethodName: appQueryRoute(schedulerBasePath+"/status", http.MethodGet),

	platformv1.MessagingService_CreateChannel_FullMethodName:   appQueryRoute(messagingBasePath+"/channels", http.MethodPost),
	platformv1.MessagingService_ListChannels_FullMethodName:    appQueryRoute(messagingBasePath+"/channels", http.MethodGet),
	platformv1.MessagingService_GetChannel_FullMethodName:      appItemRoute(messagingBasePath+"/channels/{name}", http.MethodGet, "name"),
	platformv1.MessagingService_DeleteChannel_FullMethodName:   appItemRoute(messagingBasePath+"/channels/{name}", http.MethodDelete, "name"),
	platformv1.MessagingService_Publish_FullMethodName:         appItemRoute(messagingBasePath+"/channels/{channel}/messages", http.MethodPost, "channel"),
	platformv1.MessagingService_GetChannelStats_FullMethodName: appItemRoute(messagingBasePath+"/channels/{channel}/stats", http.MethodGet, "channel"),
	platformv1.MessagingService_GetStats_FullMethodName:        appQueryRoute(messagingBasePath+"/stats", http.MethodGet),
	platformv1.MessagingService_GetDedupStats_FullMethodName:   appQueryRoute(messagingBasePath+"/dedup-stats", http.MethodGet),

	platformv1.ObjectStorageService_PutObject_FullMethodName: appQueryRoute(objectStorageBasePath+"/objects", http.MethodPost),
	platformv1.ObjectStorageService_ListObjects_FullMethodName: appQueryRoute(objectStorageBasePath+"/objects", http.MethodGet,
		"prefix", "tenant_id", "limit", "cursor", "include_tags"),
	platformv1.ObjectStorageService_CopyObject_FullMethodName: appQueryRoute(objectStorageBasePath+"/objects/copy", http.MethodPost),
	platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName: appQueryRoute(objectStorageBasePath+"/objects/by-tag", http.MethodGet,
		"tag_name", "tag_value", "tenant_id", "limit", "cursor"),
	platformv1.ObjectStorageService_GetObject_FullMethodName: appQueryRoute(objectStorageBasePath+"/object", http.MethodGet,
		"key", "tenant_id", "include_metadata"),
	platformv1.ObjectStorageService_DeleteObject_FullMethodName: appQueryRoute(objectStorageBasePath+"/object", http.MethodDelete, "key", "tenant_id"),
	platformv1.ObjectStorageService_HeadObject_FullMethodName:   appQueryRoute(objectStorageBasePath+"/object/metadata", http.MethodGet, "key", "tenant_id"),
	platformv1.ObjectStorageService_ListTenantObjects_FullMethodName: appItemRoute(objectStorageBasePath+"/tenants/{tenant_id}/objects", http.MethodGet,
		"tenant_id", "limit", "cursor", "include_tags"),
}

// appQueryRoute is a route with no path parameter; each query field is sent
// under its own proto field name.
func appQueryRoute(path, method string, queryFields ...string) templatedRoute {
	route := templatedRoute{path: path, method: method}
	for _, field := range queryFields {
		route.queryParams = append(route.queryParams, queryParam{name: field, field: field})
	}
	return route
}

// appItemRoute is a route whose path names one item through pathField.
func appItemRoute(path, method, pathField string, queryFields ...string) templatedRoute {
	route := appQueryRoute(path, method, queryFields...)
	route.pathParams = []pathParam{{placeholder: "{" + pathField + "}", field: pathField}}
	return route
}

// init registers the application service routes.
func init() {
	for method, route := range appServiceRoutes {
		templatedRouteTable[method] = route
	}
}
