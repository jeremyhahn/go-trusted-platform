package serializer

import "encoding/json"

type JSONSerializer[E any] struct {
	Serializer[E]
}

func NewJSONSerializer[E any]() Serializer[E] {
	return &JSONSerializer[E]{}
}

func (js JSONSerializer[E]) Serialize(entity E) ([]byte, error) {
	return json.Marshal(entity)
}

func (js JSONSerializer[E]) Deserialize(data []byte, e any) error {
	if err := json.Unmarshal(data, e); err != nil {
		return err
	}
	return nil
}

func (js JSONSerializer[E]) Type() SerializerType {
	return SERIALIZER_JSON
}

func (js JSONSerializer[E]) Name() string {
	return "json"
}

func (js JSONSerializer[E]) Extension() string {
	return ".json"
}
