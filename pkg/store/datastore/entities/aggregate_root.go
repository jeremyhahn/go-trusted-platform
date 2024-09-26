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
	ReferencePartition string           `yaml:"-" json:"-"`
	Root               KeyValueEntity   `yaml:"-" json:"-"`
	RootPartition      string           `yaml:"-" json:"-"`
}

// Create a new key/value aggregate root
func NewAggregateRoot(
	root KeyValueEntity,
	rootPartition string,
	references []KeyValueEntity,
	referencesPartition string) (*AggregateRoot, error) {

	if len(references) <= 0 {
		return nil, ErrEmptyReferencesSlice
	}
	return &AggregateRoot{
		Root:               root,
		RootPartition:      rootPartition,
		References:         references,
		ReferencePartition: referencesPartition,
	}, nil
}

// Returns the aggregate root partition
func (aggregate *AggregateRoot) Partition() string {
	var sb strings.Builder
	sb.WriteString(aggregate.RootPartition)
	sb.WriteString("_")
	sb.WriteString(aggregate.ReferencePartition)
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
