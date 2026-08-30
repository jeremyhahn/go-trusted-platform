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

package grpc

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// entityRoleToProto is the single mapping between the entities.DeviceRole
// vocabulary and the platform.v1 DeviceRole enum. Every canonical role has an
// enum value so a role written over one transport reads back identically over
// gRPC, Unix and QUIC.
var entityRoleToProtoMap = map[entities.DeviceRole]platformv1.DeviceRole{
	entities.DeviceRoleUnknown:      platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN,
	entities.DeviceRoleControlPlane: platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE,
	entities.DeviceRoleGateway:      platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
	entities.DeviceRoleWorker:       platformv1.DeviceRole_DEVICE_ROLE_WORKER,
	entities.DeviceRoleServer:       platformv1.DeviceRole_DEVICE_ROLE_SERVER,
	entities.DeviceRoleClient:       platformv1.DeviceRole_DEVICE_ROLE_CLIENT,
	entities.DeviceRoleWorkstation:  platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION,
	entities.DeviceRoleEdge:         platformv1.DeviceRole_DEVICE_ROLE_EDGE,
	entities.DeviceRoleIoT:          platformv1.DeviceRole_DEVICE_ROLE_IOT,
	entities.DeviceRoleLoadBalancer: platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
}

var protoRoleToEntityMap = invertRoleMap(entityRoleToProtoMap)

func invertRoleMap(m map[entities.DeviceRole]platformv1.DeviceRole) map[platformv1.DeviceRole]entities.DeviceRole {
	inverse := make(map[platformv1.DeviceRole]entities.DeviceRole, len(m))
	for role, pb := range m {
		inverse[pb] = role
	}
	return inverse
}

// EntityRoleToProto converts a DeviceRole to its wire enum. A role outside
// the vocabulary is DEVICE_ROLE_UNKNOWN.
func EntityRoleToProto(role entities.DeviceRole) platformv1.DeviceRole {
	if pb, ok := entityRoleToProtoMap[role]; ok {
		return pb
	}
	return platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN
}

// ProtoRoleToEntity converts a wire enum to its DeviceRole. UNSPECIFIED and
// any value outside the enum are DeviceRoleUnknown.
func ProtoRoleToEntity(role platformv1.DeviceRole) entities.DeviceRole {
	if entity, ok := protoRoleToEntityMap[role]; ok {
		return entity
	}
	return entities.DeviceRoleUnknown
}
