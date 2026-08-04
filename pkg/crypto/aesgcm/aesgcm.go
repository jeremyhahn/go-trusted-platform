// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidNonce         = errors.New("crypto/cipher: incorrect nonce length given to GCM")
	ErrMessageTooLarge      = errors.New("crypto/cipher: message too large for GCM")
	ErrInvalidBufferOverlap = errors.New("crypto/cipher: invalid buffer overlap")
)

type AESGCM struct {
	random io.Reader
}

// AES CGM encrypter / decrypter. Accepts a logger and optional source of
// entropy, such as the TPM or an HSM. A randomly generated nonce, not exceeding
// 96 bits, is automatically generated to add nonce misuse-resistance.
//
// In addition, this code wraps the panic that the Golang runtime throws
// when a nonce is incorrect, a message is too large, or a buffer overlap is
// detected, and returns a recoverable error instead of allowing it to crash
// servers.
// https://pkg.go.dev/crypto/cipher
// https://datatracker.ietf.org/doc/html/rfc8452
func NewAESGCM(random io.Reader) AESGCM {
	if random == nil {
		random = rand.Reader
	}
	return AESGCM{
		random: random,
	}
}

// Generates and returns an AES-256 32 byte key
// encoded to hexidecimal
func (a AESGCM) GenerateKey() []byte {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	return []byte(hex.EncodeToString(bytes))
}

// Seal the provided plain-test and "additional data" data
// with the specified encryption key, using AES256 in GCM mode,
// which provides authenticated encryption. Returns the ciphertext
// and a nonce, used as the Initialization Vector for the AES
// counter mode.
func (a AESGCM) Seal(key, data, additionalData []byte) ([]byte, []byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// IV's longer than 96 bits require additional calcuations
	// https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, additionalData)

	return ciphertext, nonce, nil
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and
func (a AESGCM) Open(key, ciphertext, nonce, additionalData []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Recover from panic to keep prevent servers from crashing
		if r := recover(); r != nil {
			err = &MessageError{Msg: fmt.Sprintf("%s", r)}
		}
	}()
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
