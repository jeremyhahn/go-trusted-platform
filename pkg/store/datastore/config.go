package datastore

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/spf13/afero"
)

type Params[E any] struct {
	ConsistencyLevel ConsistencyLevel
	Fs               afero.Fs
	Logger           *logging.Logger
	Partition        string
	ReadBufferSize   int
	RootDir          string
	Serializer       serializer.Serializer[E]
}

type Backend string

func (b Backend) String() string {
	return string(b)
}

var (
	BackendAferoFS     StoreType = "AFERO_FS"
	BackendAferoMemory StoreType = "AFERO_MEMORY"
	BackendRaft        StoreType = "RAFT"

	ErrInvalidBackend          = errors.New("datastore: invalid backend")
	ErrInvalidConsistencyLevel = errors.New("datastore: invalid consistency level")
)

type Config struct {
	Backend          string `yaml:"backend" json:"backend" mapstructure:"backend"`
	ConsistencyLevel string `yaml:"consistency-level" json:"consistency_level" mapstructure:"consistency-level"`
	ReadBufferSize   int    `yaml:"read-buffer-size" json:"read_buffer_size" mapstructure:"read-buffer-size"`
	RootDir          string `yaml:"home" json:"home" mapstructure:"home"`
	Serializer       string `yaml:"serializer" json:"serializer" mapstructure:"serializer"`
}

func ParseAferoBackend(backend string) (afero.Fs, error) {
	switch backend {
	case BackendAferoFS.String():
		return afero.NewOsFs(), nil
	case BackendAferoMemory.String():
		return afero.NewMemMapFs(), nil
	default:
		return nil, ErrInvalidBackend
	}
}

func ParseStoreType(storeType string) (StoreType, error) {
	switch storeType {
	case BackendAferoFS.String():
		return BackendAferoFS, nil
	case BackendAferoMemory.String():
		return BackendAferoMemory, nil
	case BackendRaft.String():
		return BackendRaft, nil
	default:
		return "", ErrInvalidStoreType
	}
}

func ParseConsistentLevel(consistencyLevel string) ConsistencyLevel {
	if consistencyLevel == ConsistencyLevelQuorum.String() {
		return ConsistencyLevelQuorum
	}
	return ConsistencyLevelLocal
}

func ParamsFromConfig[E any](config *Config, partition string) (*Params[E], error) {
	fs, err := ParseAferoBackend(config.Backend)
	if err != nil {
		return nil, err
	}
	serializerType, err := serializer.ParseSerializer(config.Serializer)
	if err != nil {
		return nil, err
	}
	serializer, err := serializer.NewSerializer[E](serializerType)
	if err != nil {
		return nil, err
	}
	return &Params[E]{
		ConsistencyLevel: ParseConsistentLevel(config.ConsistencyLevel),
		Fs:               fs,
		Logger:           logging.DefaultLogger(),
		Partition:        partition,
		ReadBufferSize:   config.ReadBufferSize,
		RootDir:          config.RootDir,
		Serializer:       serializer,
	}, nil
}
