package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/spf13/afero"
)

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

func (factory *Factory) OrganizationDAO() (datastore.OrganizationDAO, error) {
	serializer, err := serializer.NewSerializer[*entities.Organization](factory.serializerType)
	if err != nil {
		return nil, err
	}
	params := datastore.Params[*entities.Organization]{
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
	params := datastore.Params[*entities.User]{
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
	params := datastore.Params[*entities.Registration]{
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
	params := datastore.Params[*entities.Role]{
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
	params := datastore.Params[*entities.Blob]{
		Fs:             factory.fs,
		Logger:         factory.logger,
		Partition:      webauthn_partition,
		ReadBufferSize: factory.readBufferSize,
		RootDir:        factory.rootDir,
		Serializer:     serializer,
	}
	return NewWebAuthnDAO(&params)
}
