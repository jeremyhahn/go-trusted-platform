package entities

import (
	"errors"
	"strings"
)

var (
	ErrEmptyReferencesSlice = errors.New("entity/aggregate-root: empty references slice")
)

// Aggretate root used to manage key/value entity relationships
type AggregateRoot struct {
	References         []KeyValueEntity `yaml:"-" json:"-"`
	referencePartition string           `yaml:"-" json:"-"`
	Root               KeyValueEntity   `yaml:"-" json:"-"`
	rootPartition      string           `yaml:"-" json:"-"`
}

// Create a new key/value aggregate root
func NewAggregateRoot(root KeyValueEntity, references []KeyValueEntity) (*AggregateRoot, error) {
	if len(references) <= 0 {
		return nil, ErrEmptyReferencesSlice
	}
	return &AggregateRoot{
		References:         references,
		referencePartition: references[0].Partition(),
		Root:               root,
		rootPartition:      root.Partition(),
	}, nil
}

// Returns the aggregate root partition
func (aggregate *AggregateRoot) Partition() string {
	var sb strings.Builder
	sb.WriteString(aggregate.rootPartition)
	sb.WriteString("_")
	sb.WriteString(aggregate.referencePartition)
	return sb.String()
}

// Returns a list of the referenced entity ids
func (aggregate *AggregateRoot) EntityIDs() []uint64 {
	ids := make([]uint64, len(aggregate.References))
	for i, ref := range aggregate.References {
		ids[i] = ref.EntityID()
	}
	return ids
}
