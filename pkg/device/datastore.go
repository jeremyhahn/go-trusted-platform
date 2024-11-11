package device

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao/afero"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

type Datastore struct {
	params    *datastore.Params[*entities.Device]
	storeType datastore.StoreType
}

func NewDatastore(
	params *datastore.Params[*entities.Device],
	storeType datastore.StoreType) *Datastore {

	return &Datastore{
		params:    params,
		storeType: storeType,
	}
}

func (ds *Datastore) DeviceDAO() (dao.DeviceDAO, error) {
	switch ds.storeType {
	case datastore.BackendAferoFS, datastore.BackendAferoMemory:
		return afero.NewDeviceDAO(ds.params)
	default:
		panic("not implemented")
	}
}
