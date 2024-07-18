package pkcs11

import (
	"github.com/ThalesIgnite/crypto11"
)

type Crypto11 struct {
	ctx *crypto11.Context
}

// Opens a new connection to the underlying PKCS #11
// device and returns the PKCS11 wrapper. Close()
// must be called when done.
func NewCrypto11(config Config) (Crypto11, error) {
	conf := &crypto11.Config{
		Path:       config.Library,
		TokenLabel: config.TokenLabel,
		SlotNumber: &config.Slot,
		Pin:        config.Pin,
	}
	ctx, err := crypto11.Configure(conf)
	if err != nil {
		return Crypto11{}, err
	}

	return Crypto11{
		ctx: ctx,
	}, nil
}

// Closes the connection
func (pkcs11 Crypto11) Close() {
	pkcs11.ctx.Close()
}
