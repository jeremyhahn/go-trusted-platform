package datastore

import (
	"errors"

	"github.com/spf13/afero"
)

type Backend string

func (b Backend) String() string {
	return string(b)
}

var (
	BACKEND_AFERO_FS     Backend = "fs"
	BACKEND_AFERO_MEMORY Backend = "memory"

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

func ParseBackend(backend string) (afero.Fs, error) {
	switch backend {
	case "fs":
		return afero.NewOsFs(), nil
	case "memory":
		return afero.NewMemMapFs(), nil
	default:
		return nil, ErrInvalidBackend
	}
}

func ParseConsistentLevel(consistencyLevel string) (ConsistencyLevel, error) {
	switch consistencyLevel {
	case "local":
		return CONSISTENCY_LOCAL, nil
	case "quorum":
		return CONSISTENCY_QUORUM, nil
	default:
		return 0, ErrInvalidConsistencyLevel
	}
}
