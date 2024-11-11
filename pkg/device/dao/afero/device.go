package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	device_partition = "devices"
)

type Device struct {
	*kvstore.AferoDAO[*entities.Device]
}

func NewDeviceDAO(params *datastore.Params[*entities.Device]) (dao.DeviceDAO, error) {
	if params.Partition == "" {
		params.Partition = device_profile_partition
	}
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &Device{
		AferoDAO: aferoDAO,
	}, nil
}
