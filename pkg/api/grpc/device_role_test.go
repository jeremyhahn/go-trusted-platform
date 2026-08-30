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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceRole_EveryCanonicalRoleHasAnEnumValue verifies the wire enum
// covers the whole entities vocabulary and round-trips each value.
func TestDeviceRole_EveryCanonicalRoleHasAnEnumValue(t *testing.T) {
	for _, role := range []entities.DeviceRole{
		entities.DeviceRoleUnknown, entities.DeviceRoleControlPlane, entities.DeviceRoleGateway,
		entities.DeviceRoleWorker, entities.DeviceRoleServer, entities.DeviceRoleClient,
		entities.DeviceRoleWorkstation, entities.DeviceRoleEdge, entities.DeviceRoleIoT,
		entities.DeviceRoleLoadBalancer,
	} {
		t.Run(string(role), func(t *testing.T) {
			pb := EntityRoleToProto(role)
			assert.NotEqual(t, platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED, pb)
			if role != entities.DeviceRoleUnknown {
				assert.NotEqual(t, platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN, pb, "role %s lost on the wire", role)
			}
			assert.Equal(t, role, ProtoRoleToEntity(pb))
		})
	}
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE, EntityRoleToProto(entities.DeviceRoleControlPlane))
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_WORKER, EntityRoleToProto(entities.DeviceRoleWorker))
}

// TestDeviceRole_OutOfVocabularyIsUnknown verifies values outside either
// side of the mapping degrade to the explicit unknown value, never panic.
func TestDeviceRole_OutOfVocabularyIsUnknown(t *testing.T) {
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN, EntityRoleToProto(entities.DeviceRole("compute")))
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN, EntityRoleToProto(entities.DeviceRole("")))
	assert.Equal(t, entities.DeviceRoleUnknown, ProtoRoleToEntity(platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED))
	assert.Equal(t, entities.DeviceRoleUnknown, ProtoRoleToEntity(platformv1.DeviceRole(999)))
}
