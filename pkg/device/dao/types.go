package dao

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

type DeviceProfileDAO interface {
	datastore.GenericDAO[*entities.DeviceProfile]
}

type DeviceDAO interface {
	datastore.GenericDAO[*entities.Device]
}
