package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/spf13/afero"
)

type Params[E any] struct {
	Fs             afero.Fs
	Logger         *logging.Logger
	Partition      string
	ReadBufferSize int
	RootDir        string
	Serializer     serializer.Serializer[E]
}

type Factory struct {
	consistencyLevel datastore.ConsistencyLevel
	fs               afero.Fs
	logger           *logging.Logger
	readBufferSize   int
	rootDir          string
	serializerType   serializer.SerializerType
	datastore.Factory
}

func New(logger *logging.Logger, config *datastore.Config) (datastore.Factory, error) {
	fs, err := datastore.ParseBackend(config.Backend)
	if err != nil {
		return nil, err
	}
	serializerType, err := serializer.ParseSerializer(config.Serializer)
	if err != nil {
		return nil, err
	}
	consistencyLevel, err := datastore.ParseConsistentLevel(config.ConsistencyLevel)
	if err != nil {
		return nil, err
	}
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

func (factory *Factory) OrganizationDAO() (datastore.OrganizationDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.Organization](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.Organization]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      organization_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewOrganizationDAO(&params)
}

func (factory *Factory) UserDAO() (datastore.UserDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.User](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.User]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      user_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewUserDAO(&params)
}

func (factory *Factory) RegistrationDAO() (datastore.RegistrationDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.Registration](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.Registration]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      registration_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewRegistrationDAO(&params)
}

func (factory *Factory) RoleDAO() (datastore.RoleDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.Role](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.Role]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      role_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewRoleDAO(&params)
}

func (factory *Factory) WebAuthnDAO() (datastore.WebAuthnDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.Blob](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.Blob]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      webauthn_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewWebAuthnDAO(&params)
}

func (factory *Factory) ACMEAccountDAO() (datastore.ACMEAccountDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.ACMEAccount](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.ACMEAccount]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_account_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEAccountDAO(&params)
}

func (factory *Factory) ACMEOrderDAO(accountID uint64) (datastore.ACMEOrderDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.ACMEOrder](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.ACMEOrder]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_order_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEOrderDAO(&params, accountID)
}

func (factory *Factory) ACMEChallengeDAO(accountID uint64) (datastore.ACMEChallengeDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.ACMEChallenge](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.ACMEChallenge]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_challenge_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEChallengeDAO(&params, accountID)
}

func (factory *Factory) ACMEAuthorizationDAO(accountID uint64) (datastore.ACMEAuthorizationDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.ACMEAuthorization](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.ACMEAuthorization]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_authorization_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMEAuthorizationDAO(&params, accountID)
}

func (factory *Factory) ACMECertificateDAO() (datastore.ACMECertificateDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.ACMECertificate](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.ACMECertificate]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_certificate_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMECertificateDAO(&params)
}

func (factory *Factory) ACMENonceDAO() (datastore.ACMENonceDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.ACMENonce](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := Params[*entities.ACMENonce]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      acme_nonce_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewACMENonceDAO(&params)
}
