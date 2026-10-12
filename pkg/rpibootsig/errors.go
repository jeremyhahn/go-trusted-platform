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

package rpibootsig

import (
	"encoding/hex"
	"strconv"
)

// UnsupportedKeyError is a key the bootloader cannot verify with: the
// Raspberry Pi bootloader supports RSA 2048 only.
type UnsupportedKeyError struct {
	Reason string
}

func (e *UnsupportedKeyError) Error() string { return "rpibootsig: unsupported key: " + e.Reason }

// SignError is a failure to produce a boot.sig: the signer refused, or what it
// returned does not verify under its own public key.
type SignError struct {
	Step string
	Err  error
}

func (e *SignError) Error() string { return "rpibootsig: signing: " + e.Step + ": " + e.Err.Error() }
func (e *SignError) Unwrap() error { return e.Err }

// MalformedError is a boot.sig that does not parse.
type MalformedError struct {
	Reason string
}

func (e *MalformedError) Error() string { return "rpibootsig: malformed boot.sig: " + e.Reason }

// TargetSoCError is a target-soc rpi-eeprom-digest does not accept.
type TargetSoCError struct {
	SoC string
}

func (e *TargetSoCError) Error() string {
	return "rpibootsig: target-soc " + strconv.Quote(e.SoC) + " is not 2711 or 2712"
}

// KeyHashMismatchError is a public key whose hash is not the one in OTP: the
// bootloader refuses to boot anything signed by a key it was not fused for.
type KeyHashMismatchError struct {
	Want [32]byte
	Got  [32]byte
}

func (e *KeyHashMismatchError) Error() string {
	return "rpibootsig: the public key hash " + hex.EncodeToString(e.Got[:]) +
		" is not the hash in OTP " + hex.EncodeToString(e.Want[:])
}

// DigestMismatchError is an image whose SHA-256 is not the one boot.sig
// carries: boot.img was modified after it was signed.
type DigestMismatchError struct {
	Want [32]byte
	Got  [32]byte
}

func (e *DigestMismatchError) Error() string {
	return "rpibootsig: boot.img digest " + hex.EncodeToString(e.Got[:]) +
		" is not the signed digest " + hex.EncodeToString(e.Want[:])
}

// SignatureError is an RSA signature that does not verify under the public
// key: boot.sig was made by another key, or was altered.
type SignatureError struct {
	Err error
}

func (e *SignatureError) Error() string {
	return "rpibootsig: signature does not verify: " + e.Err.Error()
}
func (e *SignatureError) Unwrap() error { return e.Err }

// KeyBitsError is an RSA modulus that is not KeyBits long.
type KeyBitsError struct {
	Bits int
}

func (e *KeyBitsError) Error() string {
	return "rpibootsig: RSA key is " + strconv.Itoa(e.Bits) + " bits, the bootloader verifies " + strconv.Itoa(KeyBits)
}
