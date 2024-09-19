package datastore

import (
	"encoding/json"
	"errors"

	"gopkg.in/yaml.v2"
)

type Serializer int

const (
	SERIALIZER_JSON Serializer = iota
	SERIALIZER_YAML
)

var (
	ErrInvalidSerializer = errors.New("serializer: invalid serializer type")
)

// Serializes the provided data using the specified serializer
func Serialize(data interface{}, serializer Serializer) ([]byte, error) {
	switch serializer {
	case SERIALIZER_JSON:
		return json.Marshal(data)
	case SERIALIZER_YAML:
		return yaml.Marshal(data)
	default:
		return nil, ErrInvalidSerializer
	}
}

// Deserializes the provided data using the specified serializer
func Deserialize[E any](data []byte, serializer Serializer) (E, error) {
	var err error
	e := new(E)
	switch serializer {
	case SERIALIZER_JSON:
		if err = json.Unmarshal(data, &e); err != nil {
			return *e, err
		}
	case SERIALIZER_YAML:
		if err = yaml.Unmarshal(data, &e); err != nil {
			return *e, err
		}
	default:
		return *e, ErrInvalidSerializer
	}
	return *e, nil
}

// Returns the file extension for the provided serializer
func SerializerExtension(serializer Serializer) string {
	switch serializer {
	case SERIALIZER_JSON:
		return ".json"
	case SERIALIZER_YAML:
		return ".yaml"
	default:
		return ""
	}
}
