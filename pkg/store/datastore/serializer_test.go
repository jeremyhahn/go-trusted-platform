package datastore

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
)

func TestJsonSerializer(t *testing.T) {

	org := entities.NewOrganization("test")
	bytes, err := Serialize(org, SERIALIZER_JSON)
	assert.Nil(t, err)

	fmt.Println(string(bytes))

	entity, err := Deserialize[entities.Organization](bytes, SERIALIZER_JSON)
	assert.Nil(t, err)
	assert.Equal(t, "test", entity.Name)

	assert.Equal(t, ".json", SerializerExtension(SERIALIZER_JSON))
}

func TestYamlSerializer(t *testing.T) {

	org := entities.NewOrganization("test")
	bytes, err := Serialize(org, SERIALIZER_YAML)
	assert.Nil(t, err)

	fmt.Println(string(bytes))

	entity, err := Deserialize[entities.Organization](bytes, SERIALIZER_YAML)
	assert.Nil(t, err)
	assert.Equal(t, "test", entity.Name)

	assert.Equal(t, ".yaml", SerializerExtension(SERIALIZER_YAML))
}
