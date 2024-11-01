package entities

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type Reference struct {
	ID          uint64 `yaml:"id" json:"id"`
	ReferenceID uint64 `yaml:"ref-id" json:"ref_id"`
	name        string `yaml:"-" json:"-"`
	Index       `yaml:"-" json:"-"`
}

func NewReference(name string, referenceID uint64, referencedValue []byte) Index {
	return &Reference{
		ID:          util.NewID(referencedValue),
		ReferenceID: referenceID,
		name:        name,
	}
}

func (ref *Reference) SetEntityID(id uint64) {
	ref.ID = id
}

func (ref *Reference) EntityID() uint64 {
	return ref.ID
}

func (ref *Reference) Name() string {
	return ref.name
}

func (ref *Reference) RefID() uint64 {
	return ref.ReferenceID
}
