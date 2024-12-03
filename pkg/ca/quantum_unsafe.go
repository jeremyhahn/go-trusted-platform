//go:build !quantum_safe

package ca

import (
	"crypto/x509/pkix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Returns an empty set of quantum signature extensions for installations
// that choose to opt-out of quantum-safe algorithms.
func quantumSafeExtentions(algorithm keystore.QuantumAlgorithm, data []byte) []pkix.Extension {
	return []pkix.Extension{}
}
