package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
)

const (
	acme_challenge_partition = "acme/Challenges"
)

type ACMEChallengeDAO struct {
	*kvstore.AferoDAO[*entities.ACMEChallenge]
}

func NewACMEChallengeDAO(params *datastore.Params[*entities.ACMEChallenge], accountID uint64) (dao.ACMEChallengeDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_challenge_partition
	}
	aferoDAO, err := kvstore.NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMEChallengeDAO{
		AferoDAO: aferoDAO,
	}, nil
}
