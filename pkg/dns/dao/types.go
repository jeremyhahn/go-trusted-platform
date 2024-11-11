package dao

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

type ZoneDAO interface {
	datastore.GenericDAO[*entities.Zone]
	GetByName(name string, consistencyLevel datastore.ConsistencyLevel) (*entities.Zone, error)
}
