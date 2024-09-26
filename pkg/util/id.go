package util

import (
	"github.com/cespare/xxhash/v2"
)

func NewID(input []byte) uint64 {
	return xxhash.Sum64(input)
}
