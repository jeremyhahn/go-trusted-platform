package entities

type ACMENonce struct {
	ID             uint64 `json:"id" yaml:"id"`
	Value          []byte `json:"value" yaml:"value"`
	ExpiresAt      int64  `json:"expires" yaml:"expires"`
	KeyValueEntity `json:"-" yaml:"-"`
}

func (nonce *ACMENonce) SetEntityID(id uint64) {
	nonce.ID = id
}

func (nonce *ACMENonce) EntityID() uint64 {
	return nonce.ID
}
