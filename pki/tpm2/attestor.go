package tpm2

type Attestor interface {
}

type AttestorStruct struct {
	Attestor
}

func NewAttestor() Attestor {
	return &AttestorStruct{}
}
