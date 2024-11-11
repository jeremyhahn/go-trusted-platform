package device

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	DatastorePartition = "devices"

	Configuration *Config

	DefaultConfig = Config{
		Datastore: &datastore.Config{
			Backend:          "AFERO_FS",
			ConsistencyLevel: "local",
			RootDir:          "trusted-data/datastore",
			ReadBufferSize:   50,
			Serializer:       "json",
		},
	}
)

type Config struct {
	Datastore *datastore.Config `yaml:"datastore" json:"datastore" mapstructure:"datastore"`
}
