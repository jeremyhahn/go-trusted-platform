//go:build quantum_safe

package ca

import (
	"crypto/x509/pkix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Returns the quantum safe extensions for the certificate. Only Dilitium2 is supported,
// however, other algorithms will be added as they become officially supported by the
// crypto community.
func quantumSafeExtentions(algorithm keystore.QuantumAlgorithm, data []byte) []pkix.Extension {
	return []pkix.Extension{
		{
			Id:       common.OIDQuantumAlgorithm,
			Value:    []byte(algorithm.String()),
			Critical: false,
		},
		{
			Id:       common.OIDQuantumSignature,
			Value:    data,
			Critical: false,
		},
	}
}
