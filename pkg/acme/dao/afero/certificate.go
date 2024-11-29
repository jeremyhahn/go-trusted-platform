package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	acme_certificate_partition = "acme/certificates"
)

type ACMECertificateDAO struct {
	*kvstore.AferoDAO[*entities.ACMECertificate]
}

func NewACMECertificateDAO(params *datastore.Params[*entities.ACMECertificate]) (dao.ACMECertificateDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_certificate_partition
	}
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMECertificateDAO{
		AferoDAO: aferoDAO,
	}, nil
}
