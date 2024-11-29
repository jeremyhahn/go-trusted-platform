package device

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	ErrInvalidDeviceID = fmt.Errorf("invalid device ID")
)

type Service struct {
	consistencyLevel datastore.ConsistencyLevel
	deviceDAO        dao.DeviceDAO
}

func NewService(config *Config) (*Service, error) {

	dsParams, err := datastore.ParamsFromConfig[*entities.Device](
		config.Datastore, DatastorePartition)
	if err != nil {
		return nil, err
	}

	storeType, err := datastore.ParseStoreType(config.Datastore.Backend)
	if err != nil {
		return nil, err
	}

	ds := NewDatastore(dsParams, storeType)

	deviceDAO, err := ds.DeviceDAO()
	if err != nil {
		return nil, fmt.Errorf("failed to get device DAO: %w", err)
	}

	return &Service{
		consistencyLevel: datastore.ParseConsistentLevel(config.Datastore.ConsistencyLevel),
		deviceDAO:        deviceDAO,
	}, nil
}

func (s *Service) Save(device *entities.Device) error {

	if device.ID == 0 {
		return ErrInvalidDeviceID
	}

	if err := s.deviceDAO.Save(device); err != nil {
		return fmt.Errorf("failed to save device: %w", err)
	}

	return nil
}
