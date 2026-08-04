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

package registry

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// HealthStatusFromProto converts a proto HealthStatus to a domain HealthStatus.
func HealthStatusFromProto(s platformv1.HealthStatus) HealthStatus {
	switch s {
	case platformv1.HealthStatus_HEALTH_STATUS_HEALTHY:
		return HealthStatusHealthy
	case platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY:
		return HealthStatusUnhealthy
	default:
		return HealthStatusUnknown
	}
}

// IsHealthy returns true if the health status indicates healthy.
func IsHealthy(s platformv1.HealthStatus) bool {
	return s == platformv1.HealthStatus_HEALTH_STATUS_HEALTHY
}

// ArtifactTypeContainerImage returns the proto constant for container image type.
func ArtifactTypeContainerImage() platformv1.ArtifactType {
	return platformv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE
}
