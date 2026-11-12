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

package vtpm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil/socktest"
)

// tpmHeaderSize is the size of a TPM command header: tag, size, command code.
const tpmHeaderSize = 10

// serveSimulatorOnSocket serves the in-memory TPM simulator on a unix socket,
// the way swtpm serves its TPM, and returns the socket path. The
// EKCertInjector's public methods then run end to end: they open the socket,
// send TPM2_Startup and the NV commands.
func serveSimulatorOnSocket(t *testing.T) string {
	t.Helper()

	return newSimulatorSocket(t).path
}

// simulatorSocket is the in-memory TPM simulator served on a unix socket.
type simulatorSocket struct {
	path string

	// mu serialises the simulator between connections and power cycles.
	mu  sync.Mutex
	sim *simulator.Simulator
}

// newSimulatorSocket starts the simulator and serves it on a socket in the
// test's temporary directory until the test ends.
func newSimulatorSocket(t *testing.T) *simulatorSocket {
	t.Helper()

	s := &simulatorSocket{
		path: filepath.Join(socktest.Dir(t), "swtpm.sock"),
		sim:  newSimulator(t),
	}
	tpm := transport.FromReadWriter(s.sim)
	listener, err := net.Listen("unix", s.path)
	require.NoError(t, err)

	var connections sync.WaitGroup
	connections.Add(1)
	go func() {
		defer connections.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() {
					if err := conn.Close(); err != nil {
						t.Logf("close TPM connection: %v", err)
					}
				}()
				for {
					command, err := readTPMCommand(conn)
					if err != nil {
						return
					}
					s.mu.Lock()
					response, err := tpm.Send(command)
					s.mu.Unlock()
					if err != nil {
						t.Errorf("simulator: %v", err)
						return
					}
					if _, err := conn.Write(response); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		connections.Wait()
	})
	return s
}

// powerCycle resets the simulator as a host reboot resets a TPM: NV RAM
// survives, everything volatile is lost.
func (s *simulatorSocket) powerCycle(t *testing.T) {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()
	require.NoError(t, s.sim.Reset())
}

// readTPMCommand reads one TPM command, whose header carries its total size.
func readTPMCommand(r io.Reader) ([]byte, error) {
	command := make([]byte, tpmHeaderSize)
	if _, err := io.ReadFull(r, command); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(command[2:6])
	if size < tpmHeaderSize {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, size-tpmHeaderSize)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(command, body...), nil
}

// newTestEKCertificate returns a certificate of at least minSize DER bytes.
func newTestEKCertificate(t *testing.T, minSize int) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return eKCertificateOfSize(t, &key.PublicKey, minSize)
}

// The certificate injected through the swtpm socket reads back unchanged, for
// both EK algorithms.
func TestEKCertInjector_InjectAndReadOverSocket(t *testing.T) {
	for _, algorithm := range []EKAlgorithm{EKAlgorithmRSA, EKAlgorithmECC} {
		t.Run(string(algorithm), func(t *testing.T) {
			ctx := context.Background()
			injector := NewEKCertInjector(serveSimulatorOnSocket(t), nil)
			cert := newTestEKCertificate(t, 1)

			require.NoError(t, injector.InjectCertificate(ctx, cert, algorithm))

			stored, err := injector.ReadCertificate(ctx, algorithm)
			require.NoError(t, err)
			require.True(t, cert.Equal(stored), "the stored certificate must be the injected one")
		})
	}
}

// The RSA and ECC EK certificates live in separate NV indices: writing one
// does not touch the other.
func TestEKCertInjector_BothAlgorithmsOverSocket(t *testing.T) {
	ctx := context.Background()
	injector := NewEKCertInjector(serveSimulatorOnSocket(t), nil)
	rsaCert := newTestEKCertificate(t, 1)
	eccCert := newTestEKCertificate(t, 1)

	require.NoError(t, injector.InjectCertificate(ctx, rsaCert, EKAlgorithmRSA))
	require.NoError(t, injector.InjectCertificate(ctx, eccCert, EKAlgorithmECC))

	storedRSA, err := injector.ReadCertificate(ctx, EKAlgorithmRSA)
	require.NoError(t, err)
	storedECC, err := injector.ReadCertificate(ctx, EKAlgorithmECC)
	require.NoError(t, err)
	require.True(t, rsaCert.Equal(storedRSA))
	require.True(t, eccCert.Equal(storedECC))
	require.False(t, storedRSA.Equal(storedECC))
}

// A second injection replaces the first, including when the new certificate
// is larger and the NV index has to be undefined and defined again.
func TestEKCertInjector_ReinjectOverSocket(t *testing.T) {
	ctx := context.Background()
	injector := NewEKCertInjector(serveSimulatorOnSocket(t), nil)
	first := newTestEKCertificate(t, 1)
	second := newTestEKCertificate(t, len(first.Raw)+256)

	require.NoError(t, injector.InjectCertificate(ctx, first, EKAlgorithmRSA))
	stored, err := injector.ReadCertificate(ctx, EKAlgorithmRSA)
	require.NoError(t, err)
	require.True(t, first.Equal(stored))

	require.NoError(t, injector.InjectCertificate(ctx, second, EKAlgorithmRSA))
	stored, err = injector.ReadCertificate(ctx, EKAlgorithmRSA)
	require.NoError(t, err)
	require.True(t, second.Equal(stored), "the second injection must replace the first")
}

// VerifyCertificate accepts the stored certificate and rejects any other.
func TestEKCertInjector_VerifyCertificateOverSocket(t *testing.T) {
	ctx := context.Background()
	injector := NewEKCertInjector(serveSimulatorOnSocket(t), nil)
	stored := newTestEKCertificate(t, 1)
	other := newTestEKCertificate(t, 1)
	require.NoError(t, injector.InjectCertificate(ctx, stored, EKAlgorithmRSA))

	require.NoError(t, injector.VerifyCertificate(ctx, stored, EKAlgorithmRSA))

	err := injector.VerifyCertificate(ctx, other, EKAlgorithmRSA)
	var mismatch ErrEKCertInjectionFailed
	require.True(t, errors.As(err, &mismatch), "got %v", err)
	require.ErrorContains(t, err, "does not match")
}

// A valid certificate cannot be injected when no swtpm serves the socket.
func TestEKCertInjector_InjectCertificate_NoSocket(t *testing.T) {
	injector := NewEKCertInjector(filepath.Join(t.TempDir(), "missing.sock"), nil)

	err := injector.InjectCertificate(context.Background(), newTestEKCertificate(t, 1), EKAlgorithmRSA)

	var injectFailed ErrEKCertInjectionFailed
	require.True(t, errors.As(err, &injectFailed), "got %v", err)
	require.ErrorContains(t, err, "failed to open swtpm socket")
}

// TestEKCertInjector_CheckEKCertificateExistsOverSocket is the first-boot
// safety check: a fresh TPM reports no EK certificate, so provisioning may
// write one; once one is present the check reports it and leaves it as it
// was, so provisioning never overwrites a manufacturer's certificate.
func TestEKCertInjector_CheckEKCertificateExistsOverSocket(t *testing.T) {
	for _, algorithm := range []EKAlgorithm{EKAlgorithmRSA, EKAlgorithmECC} {
		t.Run(string(algorithm), func(t *testing.T) {
			ctx := context.Background()
			injector := NewEKCertInjector(serveSimulatorOnSocket(t), nil)

			exists, existing, err := injector.CheckEKCertificateExists(ctx, algorithm)
			require.NoError(t, err)
			require.False(t, exists, "a fresh TPM holds no EK certificate")
			require.Nil(t, existing)

			cert := newTestEKCertificate(t, 1)
			require.NoError(t, injector.InjectCertificate(ctx, cert, algorithm))

			exists, existing, err = injector.CheckEKCertificateExists(ctx, algorithm)
			require.NoError(t, err)
			require.True(t, exists, "a provisioned EK certificate must be detected")
			require.True(t, cert.Equal(existing), "the detected certificate must be the provisioned one")

			stored, err := injector.ReadCertificate(ctx, algorithm)
			require.NoError(t, err)
			require.True(t, cert.Equal(stored), "the existence check must leave the certificate unchanged")
		})
	}
}

// TestEKCertInjector_EKCertificatesSurviveTPMRestart provisions both EK
// certificates, restarts the TPM and reads them back through a new
// injector, as first boot does when a provisioned vTPM bundle starts again.
func TestEKCertInjector_EKCertificatesSurviveTPMRestart(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatorSocket(t)
	certs := map[EKAlgorithm]*x509.Certificate{
		EKAlgorithmRSA: newTestEKCertificate(t, 1),
		EKAlgorithmECC: newTestEKCertificate(t, 1),
	}
	injector := NewEKCertInjector(tpm.path, nil)
	for algorithm, cert := range certs {
		require.NoError(t, injector.InjectCertificate(ctx, cert, algorithm))
		exists, stored, err := injector.CheckEKCertificateExists(ctx, algorithm)
		require.NoError(t, err)
		require.True(t, exists, "the %s EK certificate must be detected", algorithm)
		require.True(t, cert.Equal(stored), "the %s EK certificate must be the provisioned one", algorithm)
	}

	tpm.powerCycle(t)

	restarted := NewEKCertInjector(tpm.path, nil)
	for algorithm, cert := range certs {
		exists, persisted, err := restarted.CheckEKCertificateExists(ctx, algorithm)
		require.NoError(t, err)
		require.True(t, exists, "the %s EK certificate must survive a TPM restart", algorithm)
		require.True(t, cert.Equal(persisted), "the %s EK certificate must be unchanged by a TPM restart", algorithm)
	}
}

// TestEKCertInjector_CheckEKCertificateExists_TPMClosed reports a TPM that
// stops answering as a failed check, never as an absent certificate that
// provisioning could then write over.
