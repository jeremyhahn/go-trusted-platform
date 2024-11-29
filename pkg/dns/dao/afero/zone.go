package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	dns_zones_partition = "dns/zones"
)

type Zone struct {
	*kvstore.AferoDAO[*entities.Zone]
}

func NewZoneDAO(params *datastore.Params[*entities.Zone]) (dao.ZoneDAO, error) {
	if params.Partition == "" {
		params.Partition = dns_zones_partition
	}
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &Zone{
		AferoDAO: aferoDAO,
	}, nil
}

func (z *Zone) GetByName(name string, consistencyLevel datastore.ConsistencyLevel) (*entities.Zone, error) {
	zones, err := z.Page(datastore.NewPageQuery(), consistencyLevel)
	if err != nil {
		return nil, err
	}

	for _, zone := range zones.Entities {
		if zone.Name == name {
			return zone, nil
		}
	}
	return nil, err
}
