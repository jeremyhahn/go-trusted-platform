package datastore

// import (
// 	"errors"
// )

// const (
// 	SERIALIZER_JSON SerializerType = iota
// 	SERIALIZER_YAML
// )

// var (
// 	ErrInvalidSerializer = errors.New("serializer: invalid serializer type")
// )

// type SerializerType int

// func (s SerializerType) String() string {
// 	switch s {
// 	case SERIALIZER_JSON:
// 		return "json"
// 	case SERIALIZER_YAML:
// 		return "yaml"
// 	default:
// 		return ""
// 	}
// }

// // Responsible for entity serialization and deserialization
// type Serializer[E any] interface {
// 	Deserialize(data []byte, e any) error
// 	Extension() string
// 	Name() string
// 	Serialize(entity E) ([]byte, error)
// 	Type() SerializerType
// }

// // Serializer factory method
// func NewSerializer[T any](st SerializerType) (Serializer[T], error) {
// 	switch st {
// 	case SERIALIZER_JSON:
// 		return NewJSONSerializer[T](), nil
// 	case SERIALIZER_YAML:
// 		return NewYAMLSerializer[T](), nil
// 	default:
// 		return nil, ErrInvalidSerializer
// 	}
// }

// // Serializes the provided data using the specified serializer
// func Serialize[E any](entity E, serializer SerializerType) ([]byte, error) {
// 	s, err := NewSerializer[E](serializer)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return s.Serialize(entity)
// }

// // Deserializes the provided data using the specified serializer
// func Deserialize[E any](data []byte, e E, serializer SerializerType) error {
// 	s, err := NewSerializer[E](serializer)
// 	if err != nil {
// 		return err
// 	}
// 	return s.Deserialize(data, e)
// }

// // Returns the file extension for the provided serializer
// func SerializerExtension(serializer SerializerType) string {
// 	switch serializer {
// 	case SERIALIZER_JSON:
// 		return ".json"
// 	case SERIALIZER_YAML:
// 		return ".yaml"
// 	default:
// 		return ""
// 	}
// }

// // Parses the serializer type from the provided string
// func ParseSerializer(serializer string) (SerializerType, error) {
// 	switch serializer {
// 	case "json":
// 		return SERIALIZER_JSON, nil
// 	case "yaml":
// 		return SERIALIZER_YAML, nil
// 	default:
// 		return 0, ErrInvalidSerializer
// 	}
// }
