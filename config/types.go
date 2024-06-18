package config

type KeyValueEntity interface {
	SetID(id uint64)
	Identifier() uint64
}
