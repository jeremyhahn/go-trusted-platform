package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	device_profile_partition = "devices/profiles"
)

type DeviceProfile struct {
	*kvstore.AferoDAO[*entities.DeviceProfile]
}

func NewDeviceProfileDAO(params *datastore.Params[*entities.DeviceProfile]) (dao.DeviceProfileDAO, error) {
	if params.Partition == "" {
		params.Partition = device_profile_partition
	}
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &DeviceProfile{
		AferoDAO: aferoDAO,
	}, nil
}
