package afero

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/spf13/afero"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	acme "github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
)

type Factory struct {
	consistencyLevel datastore.ConsistencyLevel
	fs               afero.Fs
	logger           *logging.Logger
	readBufferSize   int
	rootDir          string
	serializerType   serializer.SerializerType
	dao.Factory
}

func NewFactory(logger *logging.Logger, config *datastore.Config) (dao.Factory, error) {
	fs, err := datastore.ParseAferoBackend(config.Backend)
	if err != nil {
		return nil, err
	}
	serializerType, err := serializer.ParseSerializer(config.Serializer)
	if err != nil {
		return nil, err
	}
	consistencyLevel := datastore.ParseConsistentLevel(config.ConsistencyLevel)
	return &Factory{
		consistencyLevel: consistencyLevel,
		fs:               fs,
		logger:           logger,
		readBufferSize:   config.ReadBufferSize,
		rootDir:          config.RootDir,
		serializerType:   serializerType,
	}, nil
}

func (factory *Factory) SerializerType() serializer.SerializerType {
	return factory.serializerType
}

func (factory *Factory) ConsistencyLevel() datastore.ConsistencyLevel {
	return factory.consistencyLevel
}

func (factory *Factory) ACMEAccountDAO() (dao.ACMEAccountDAO, error) {
	serializer, err := serializer.NewSerializer[*acme.ACMEAccount](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*acme.ACMEAccount]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_account_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEAccountDAO(&params)
}

func (factory *Factory) ACMEOrderDAO(accountID uint64) (dao.ACMEOrderDAO, error) {
	serializer, err := serializer.NewSerializer[*acme.ACMEOrder](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*acme.ACMEOrder]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_order_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEOrderDAO(&params, accountID)
}

func (factory *Factory) ACMEChallengeDAO(accountID uint64) (dao.ACMEChallengeDAO, error) {
	serializer, err := serializer.NewSerializer[*acme.ACMEChallenge](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*acme.ACMEChallenge]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_challenge_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEChallengeDAO(&params, accountID)
}

func (factory *Factory) ACMEAuthorizationDAO(accountID uint64) (dao.ACMEAuthorizationDAO, error) {
	serializer, err := serializer.NewSerializer[*acme.ACMEAuthorization](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*acme.ACMEAuthorization]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_authorization_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEAuthorizationDAO(&params, accountID)
}

func (factory *Factory) ACMECertificateDAO() (dao.ACMECertificateDAO, error) {
	serializer, err := serializer.NewSerializer[*acme.ACMECertificate](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*acme.ACMECertificate]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_certificate_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMECertificateDAO(&params)
}

func (factory *Factory) ACMENonceDAO() (dao.ACMENonceDAO, error) {
	serializer, err := serializer.NewSerializer[*acme.ACMENonce](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*acme.ACMENonce]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_nonce_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMENonceDAO(&params)
}
