package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	acme_certificate_partition = "acme/certificates"
)

type ACMECertificateDAO struct {
	*AferoDAO[*entities.ACMECertificate]
}

func NewACMECertificateDAO(params *Params[*entities.ACMECertificate]) (datastore.ACMECertificateDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_certificate_partition
	}
	aferoDAO, err := NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMECertificateDAO{
		AferoDAO: aferoDAO,
	}, nil
}
