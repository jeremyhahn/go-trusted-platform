package tpm2

import (
	"errors"
	"math"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Configuration parameters for the TPM random generator
type Random struct {
	EncryptionHandle tpm2.TPMHandle   // (optional) handle to use for transit encryption
	EncryptionPub    *tpm2.TPMTPublic // (optional) public key to use for transit encryption
	mu               sync.Mutex
	rwr              transport.TPM
}

// Returns random bytes from a Trusted Platform Module (TPM). A transport.TPM
// object is accepted so the reader can be tested with a Simulator TPM
// instead of a real TPM device and/or read from socket that's already been
// opened.
func NewRandomReader(rwr transport.TPM) *Random {
	// if conf.TPM == nil {
	// 	return &Random{}, fmt.Errorf("unable to open TPM")
	// }
	// conf.rwr = transport.FromReadWriter(conf.TPM)
	// return conf, nil
	return &Random{rwr: rwr}
}

// Reads random bytes from the TPM. Use the "Encrypt" configuration
// option to encrpt the communication between the CPU and TPM
func (r *Random) Read(data []byte) (n int, err error) {

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(data) > math.MaxUint16 {
		return 0, errors.New("tpm-rand: Number of bytes to read exceeds cannot math.MaxInt16")
	}

	var result []byte
	operation := func() (err error) {

		var resp *tpm2.GetRandomResponse
		var sess tpm2.Session

		if r.EncryptionHandle != 0 && r.EncryptionPub != nil {
			sess = tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.AESEncryption(
					128,
					tpm2.EncryptOut),
				tpm2.Salted(r.EncryptionHandle, *r.EncryptionPub))
		} else {
			sess = tpm2.HMAC(
				tpm2.TPMAlgSHA256,
				16,
				tpm2.AESEncryption(128, tpm2.EncryptOut))
		}

		resp, err = tpm2.GetRandom{
			BytesRequested: uint16(len(data)),
		}.Execute(r.rwr, sess)
		if err != nil {
			return err
		}

		result = resp.RandomBytes.Buffer
		copy(data, resp.RandomBytes.Buffer)

		return nil
	}

	// dont' know which scheme is better, probably the constant
	//err = backoff.Retry(operation, backoff.NewExponentialBackOff())
	// err = backoff.Retry(operation, r.Scheme)
	// if err != nil {
	// 	return 0, err
	// }

	// Disabling backoff because the library is in conflict
	// with the golang Time package.
	if err = operation(); err != nil {
		return 0, err
	}

	return len(result), err
}
