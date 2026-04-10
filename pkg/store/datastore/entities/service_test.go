package entities

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	t.Run("creates service with name-derived ID", func(t *testing.T) {
		svc := NewService("my-service")
		require.NotNil(t, svc)
		assert.Equal(t, "my-service", svc.Name)
		assert.Equal(t, util.NewID([]byte("my-service")), svc.ID)
		assert.Nil(t, svc.KeyAttributes)
	})

	t.Run("empty name generates valid service", func(t *testing.T) {
		svc := NewService("")
		require.NotNil(t, svc)
		assert.Equal(t, "", svc.Name)
		assert.Equal(t, util.NewID([]byte("")), svc.ID)
	})

	t.Run("same name generates same ID", func(t *testing.T) {
		svc1 := NewService("test")
		svc2 := NewService("test")
		assert.Equal(t, svc1.ID, svc2.ID)
	})

	t.Run("different names generate different IDs", func(t *testing.T) {
		svc1 := NewService("service-a")
		svc2 := NewService("service-b")
		assert.NotEqual(t, svc1.ID, svc2.ID)
	})
}

func TestService_SetEntityID(t *testing.T) {
	svc := NewService("test")
	originalID := svc.ID

	newID := uint64(54321)
	svc.SetEntityID(newID)

	assert.NotEqual(t, originalID, svc.ID)
	assert.Equal(t, newID, svc.ID)
	assert.Equal(t, newID, svc.EntityID())
}

func TestService_EntityID(t *testing.T) {
	name := "my-service"
	svc := NewService(name)
	assert.Equal(t, util.NewID([]byte(name)), svc.EntityID())
}

func TestService_KeyValueEntity(t *testing.T) {
	var entity KeyValueEntity = NewService("test")

	id := entity.EntityID()
	assert.NotZero(t, id)

	newID := uint64(99999)
	entity.SetEntityID(newID)
	assert.Equal(t, newID, entity.EntityID())
}
