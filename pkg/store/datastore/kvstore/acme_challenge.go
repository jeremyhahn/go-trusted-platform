package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const (
	acme_challenge_partition = "acme/Challenges"
)

type ACMEChallengeDAO struct {
	*AferoDAO[*entities.ACMEChallenge]
}

func NewACMEChallengeDAO(params *Params[*entities.ACMEChallenge], accountID uint64) (datastore.ACMEChallengeDAO, error) {
	if params.Partition == "" {
		params.Partition = acme_challenge_partition
	}
	aferoDAO, err := NewAferoDAO(params)
	if err != nil {
		return nil, err
	}
	return &ACMEChallengeDAO{
		AferoDAO: aferoDAO,
	}, nil
}
