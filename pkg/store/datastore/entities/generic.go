package entities

import "encoding/json"

const (
	generic_partition = "generic"
)

type Generic struct {
	ID             uint64      `yaml:"id" json:"id"`
	Entity         interface{} `yaml:"entity" json:"entity"`
	partition      string      `yaml:"-" json:"-"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewGeneric(id uint64, entity interface{}) *Generic {
	return &Generic{
		ID:        id,
		Entity:    entity,
		partition: generic_partition,
	}
}

func CreateGeneric(id uint64, entity interface{}, partition string) *Generic {
	return &Generic{
		ID:        id,
		Entity:    entity,
		partition: partition,
	}
}

func (generic *Generic) SetEntityID(id uint64) {
	generic.ID = id
}

func (generic *Generic) EntityID() uint64 {
	return generic.ID
}

func (generic *Generic) SetPartition(partition string) {
	generic.partition = partition
}

func (generic *Generic) Partition() string {
	return generic.partition
}

func (generic *Generic) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, generic.Entity)
}
