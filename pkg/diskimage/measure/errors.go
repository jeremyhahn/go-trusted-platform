package measure

import (
	"crypto"
	"fmt"
)

// UnsupportedBankError is a PCR bank whose hash is not linked into the binary.
type UnsupportedBankError struct {
	Hash crypto.Hash
}

func (e *UnsupportedBankError) Error() string {
	return fmt.Sprintf("measure: PCR bank %v is not supported", e.Hash)
}

// DigestSizeError is a digest whose length does not match its bank.
type DigestSizeError struct {
	Hash  crypto.Hash
	Index int
	Got   int
}

func (e *DigestSizeError) Error() string {
	return fmt.Sprintf("measure: digest %d is %d bytes, the %v bank needs %d", e.Index, e.Got, e.Hash, e.Hash.Size())
}

// MissingInputError is a build input a PCR's prediction needs and did not get.
type MissingInputError struct {
	PCR   int
	Input string
}

func (e *MissingInputError) Error() string {
	return fmt.Sprintf("measure: PCR %d cannot be predicted without %s", e.PCR, e.Input)
}

// MalformedImageError is a PE/COFF image, or a U-Boot binary, the
// predictors cannot read.
type MalformedImageError struct {
	Reason string
}

func (e *MalformedImageError) Error() string {
	return "measure: malformed image: " + e.Reason
}
