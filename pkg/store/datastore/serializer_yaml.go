package datastore

// import (
// 	YAML "gopkg.in/yaml.v2"
// )

// type YAMLSerializer[E any] struct {
// 	Serializer[E]
// }

// func NewYAMLSerializer[E any]() Serializer[E] {
// 	return &YAMLSerializer[E]{}
// }

// func (js YAMLSerializer[E]) Serialize(entity E) ([]byte, error) {
// 	return YAML.Marshal(entity)
// }

// func (js YAMLSerializer[E]) Deserialize(data []byte, e any) error {
// 	if err := YAML.Unmarshal(data, e); err != nil {
// 		return err
// 	}
// 	return nil
// }

// func (js YAMLSerializer[E]) Type() SerializerType {
// 	return SERIALIZER_YAML
// }

// func (js YAMLSerializer[E]) Name() string {
// 	return "yaml"
// }

// func (js YAMLSerializer[E]) Extension() string {
// 	return ".yaml"
// }
