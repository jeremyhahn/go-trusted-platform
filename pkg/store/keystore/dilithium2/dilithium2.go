//go:build quantum_safe

package dilithium2

import (
	"errors"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

var (
	QUANTUM_ALGORITHM_DILITHIUM2 = "Dilithium2"
)

type Dilithium2 struct {
	signer *oqs.Signature
}

// Generate a new Dilithium2 key pair instance
func New() (*Dilithium2, error) {
	signer := oqs.Signature{}
	if err := signer.Init("Dilithium2", nil); err != nil {
		return nil, err
	}
	return &Dilithium2{signer: &signer}, nil
}

func (d *Dilithium2) Create(secretKey []byte) error {
	d.Clean()
	d.signer = &oqs.Signature{}
	if err := d.signer.Init("Dilithium2", secretKey); err != nil {
		return err
	}
	return nil
}

// Clean the Dilithium2 library instance
func (d *Dilithium2) Clean() {
	if d.signer != nil {
		d.signer.Clean()
		d.signer = nil
	}
}

// Generate a new Dilithium2 key pair
func (d *Dilithium2) GenerateKeyPair() ([]byte, error) {
	pubKey, err := d.signer.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// Exports the private key
func (d *Dilithium2) ExportSecretKey() []byte {
	return d.signer.ExportSecretKey()
}

// Sign a message with the secret key
func (d *Dilithium2) Sign(data []byte) ([]byte, error) {
	return d.signer.Sign(data)
}

// Verify a message with the public key
func (d *Dilithium2) Verify(data, signature, publicKey []byte) error {
	valid, err := d.signer.Verify(data, signature, publicKey)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("signature verification failed")
	}
	return nil
}
