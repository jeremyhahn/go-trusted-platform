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
