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

package datastore

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
)

func TestSerializers(t *testing.T) {

	org := entities.NewOrganization("test")

	serializers := []serializer.Serializer[*entities.Organization]{
		serializer.NewJSONSerializer[*entities.Organization](),
		serializer.NewYAMLSerializer[*entities.Organization](),
	}

	for _, serializer := range serializers {
		bytes, err := serializer.Serialize(org)
		assert.Nil(t, err)
		assert.NotNil(t, bytes)

		fmt.Println(string(bytes))

		org := &entities.Organization{}
		err = serializer.Deserialize(bytes, org)
		assert.Nil(t, err)
		assert.Equal(t, "test", org.Name)
	}
}
