package dns

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao/afero"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

type Datastore struct {
	params    *datastore.Params[*entities.Zone]
	storeType datastore.StoreType
}

func NewDatastore(
	params *datastore.Params[*entities.Zone],
	storeType datastore.StoreType) *Datastore {

	return &Datastore{
		params:    params,
		storeType: storeType,
	}
}

func (ds *Datastore) ZoneDAO() (dao.ZoneDAO, error) {
	switch ds.storeType {
	case datastore.BackendAferoFS, datastore.BackendAferoMemory:
		return afero.NewZoneDAO(ds.params)
	default:
		panic("not implemented")
	}
}
