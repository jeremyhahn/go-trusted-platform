package vtpm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil/socktest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/stretchr/testify/require"
)

// newSocketTPMOperations opens TPMOperations against an in-memory simulator
// served on a unix socket and provisions it, as Start does for a real swtpm.
func newSocketTPMOperations(t *testing.T) (*TPMOperations, string) {
	t.Helper()

	socketPath := serveSimulatorOnSocket(t)
	ops, err := NewTPMOperations(socketPath, t.TempDir(), EKAlgorithmRSA, "vm-964", nil)
	require.NoError(t, err)
	require.NoError(t, ops.ProvisionIfNew())
	t.Cleanup(func() {
		if err := ops.Close(); err != nil {
			t.Logf("close TPM operations: %v", err)
		}
	})
	return ops, socketPath
}

// newServiceWithInstance returns a service holding one running instance
// backed by the simulator. The swtpm handle is a zero value: it reports not
// running and its Stop fails with swtpm.ErrNotRunning.
func newServiceWithInstance(t *testing.T, bundleID string) (*Service, *TPMOperations) {
	t.Helper()

	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)
	ops, socketPath := newSocketTPMOperations(t)
	service.mu.Lock()
	service.instances[bundleID] = &runningInstance{swtpm: &swtpm.SWTPM{}, socketPath: socketPath, tpmOps: ops}
	service.mu.Unlock()
	return service, ops
}

// newHangUpTPMOperations returns provisioned TPMOperations on a simulator
// socket together with a hangUp function that drops the connection, after
// which every TPM command fails. The simulator is process-wide, so a test
// using this helper must not open another one.
func newHangUpTPMOperations(t *testing.T) (*TPMOperations, string, func()) {
	t.Helper()

	tpm := transport.FromReadWriter(newSimulator(t))
	socketPath := filepath.Join(socktest.Dir(t), "swtpm.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	// The socket transport dials once per command, so serve every
	// connection until the listener closes.
	var (
		mu      sync.Mutex
		current net.Conn
		served  sync.WaitGroup
	)
	served.Add(1)
	go func() {
		defer served.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			current = conn
			mu.Unlock()
			serveTPMConnection(t, tpm, conn)
		}
	}()
	var once sync.Once
	hangUp := func() {
		once.Do(func() {
			require.NoError(t, listener.Close())
			mu.Lock()
			if current != nil {
				// The connection may already be closed by the client.
				if err := current.Close(); err != nil {
					t.Logf("close TPM connection: %v", err)
				}
			}
			mu.Unlock()
			served.Wait()
		})
	}
	t.Cleanup(hangUp)

	ops, err := NewTPMOperations(socketPath, t.TempDir(), EKAlgorithmRSA, "vm-964", nil)
	require.NoError(t, err)
	require.NoError(t, ops.ProvisionIfNew())
	return ops, socketPath, hangUp
}

// serveTPMConnection answers TPM commands on conn until the client closes it.
func serveTPMConnection(t *testing.T, tpm transport.TPM, conn net.Conn) {
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
		response, err := tpm.Send(command)
		if err != nil {
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

func TestCoverage964_ErrorMessages(t *testing.T) {
	cause := errors.New("cause")
	tests := []struct {
		name    string
		err     error
		message string
		unwraps bool
	}{
		{"nil resolved target", ErrNilResolvedTarget{}, "vtpm: resolved TPM target is nil", false},
		{"unknown target", ErrUnknownTPMTarget{Target: 9}, "vtpm: unknown TPM target 9", false},
		{"device open failed", ErrTPMDeviceOpenFailed{Device: "/dev/tpm0", Cause: cause}, "vtpm: failed to open TPM device /dev/tpm0: cause", true},
		{"nil tpm config", ErrNilTPMConfig{}, "vtpm: tpm configuration is nil", false},
		{"hardware unavailable", ErrHardwareTPMUnavailable{Device: "/dev/tpm0", Cause: cause}, "vtpm: hardware TPM device /dev/tpm0 unavailable: cause", true},
		{"socket unavailable", ErrSwtpmSocketUnavailable{Socket: "/run/s.sock", Cause: cause}, "vtpm: swtpm socket /run/s.sock unavailable: cause", true},
		{"no tpm detected", ErrNoTPMDetected{Cause: cause}, "vtpm: no TPM detected (device: auto): cause", true},
		{"not char device", ErrNotCharDevice{Path: "/tmp/x"}, "vtpm: /tmp/x exists but is not a TPM character device", false},
		{"not unix socket", ErrNotUnixSocket{Path: "/tmp/x"}, "vtpm: /tmp/x exists but is not a unix domain socket", false},
		{"attestor needs tpm", ErrVMAttestorDeviceTPMRequired{}, "vtpm: VM attestor device requires a TPM", false},
		{"unsupported quote algorithm", ErrUnsupportedQuoteAlgorithm{Algorithm: "sha1"}, `vtpm: unsupported quote hash algorithm "sha1": only sha256 is supported`, false},
		{"vm quote failed", ErrVMQuoteFailed{Cause: cause}, "vtpm: VM quote failed: cause", true},
		{"vm pcr read failed", ErrPCRReadFailedVM{PCR: 7, Cause: cause}, "vtpm: failed to read PCR 7: cause", true},
		{"pcr bank value missing", ErrPCRBankValueNotFound{PCR: 7, Algorithm: "sha256"}, "vtpm: PCR 7 not found in sha256 bank", false},
		{"aik public key", ErrAIKPublicKeyUnavailable{Cause: cause}, "vtpm: AIK public key unavailable: cause", true},
		{"aik signature algorithm", ErrAIKSignatureAlgorithmUnavailable{Cause: cause}, "vtpm: AIK signature algorithm unavailable: cause", true},
		{"ek certificate", ErrEKCertificateUnavailable{Cause: cause}, "vtpm: EK certificate unavailable: cause", true},
		{"no ek certificate", ErrVMAttestorDeviceNoEKCert{}, "vtpm: vTPM has no EK certificate", false},
		{"generation failed with cause", ErrGenerationFailed{Reason: "ek", Cause: cause}, "vtpm: generation failed: ek: cause", true},
		{"generation failed without cause", ErrGenerationFailed{Reason: "ek"}, "vtpm: generation failed: ek", false},
		{"missing hostname", ErrMissingHostname{}, "vtpm: hostname is required", false},
		{"nv buffer max", ErrNVBufferMaxUnavailable{Cause: cause}, "vtpm: TPM_PT_NV_BUFFER_MAX unavailable: cause", true},
		{"attestation key missing", ErrVTPMAttestationKeyMissing{SocketPath: "/run/s.sock", Cause: cause}, "vtpm: the provisioned vTPM at /run/s.sock has no attestation key: cause", true},
		{"wrapped error", &WrappedError{Msg: "context", Err: cause}, "context: cause", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.message, tt.err.Error())
			require.Equal(t, tt.unwraps, errors.Is(tt.err, cause))
		})
	}
}

func TestCoverage964_TPMOperationsPCRs(t *testing.T) {
	ops, _ := newSocketTPMOperations(t)
	require.NotNil(t, ops.TPM())

	before, err := ops.ReadPCR(16)
	require.NoError(t, err)
	require.Len(t, before, sha256.Size)

	digest := sha256.Sum256([]byte("measurement"))
	require.NoError(t, ops.ExtendPCR(16, digest[:]))

	after, err := ops.ReadPCR(16)
	require.NoError(t, err)
	require.NotEqual(t, before, after, "extending a PCR must change its value")

	values, err := ops.ReadPCRs([]int{0, 16})
	require.NoError(t, err)
	require.Equal(t, after, values[16])
	require.Len(t, values[0], sha256.Size)
}

func TestCoverage964_TPMOperationsQuote(t *testing.T) {
	ops, _ := newSocketTPMOperations(t)

	result, err := ops.Quote([]byte("nonce-964"), []int{0, 7})
	require.NoError(t, err)
	require.Equal(t, "SHA256", result.HashAlgorithm)
	require.NotEmpty(t, result.Quote)
	require.NotEmpty(t, result.Signature)
	require.True(t, bytes.Contains(result.Quote, []byte("nonce-964")), "the quote must carry the nonce")
}

func TestCoverage964_TPMOperationsSealUnseal(t *testing.T) {
	tests := []struct {
		name      string
		pcrs      []int
		authValue string
	}{
		{"no policy", nil, ""},
		{"password", nil, "s3cret"},
		{"pcr policy", []int{0, 7}, ""},
		{"pcr policy and password", []int{0, 7}, "s3cret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ops, _ := newSocketTPMOperations(t)

			sealed, err := ops.Seal(ctx, []byte("secret-964"), tt.pcrs, tt.authValue)
			require.NoError(t, err)

			plain, err := ops.Unseal(ctx, sealed, tt.authValue)
			require.NoError(t, err)
			require.Equal(t, []byte("secret-964"), plain)
		})
	}
}

func TestCoverage964_TPMOperationsUnsealRejectsWrongPassword(t *testing.T) {
	for _, attempt := range []struct {
		name      string
		authValue string
	}{
		{"wrong password", "not-the-secret"},
		{"missing password", ""},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			ctx := context.Background()
			ops, _ := newSocketTPMOperations(t)

			sealed, err := ops.Seal(ctx, []byte("secret-964"), nil, "s3cret")
			require.NoError(t, err)

			plain, err := ops.Unseal(ctx, sealed, attempt.authValue)
			require.Error(t, err)
			require.Nil(t, plain)
		})
	}
}

func TestCoverage964_TPMOperationsUnsealRejectsChangedPCR(t *testing.T) {
	ctx := context.Background()
	ops, _ := newSocketTPMOperations(t)

	sealed, err := ops.Seal(ctx, []byte("secret-964"), []int{0, 7}, "")
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("measured-state-change"))
	require.NoError(t, ops.ExtendPCR(7, digest[:]))

	plain, err := ops.Unseal(ctx, sealed, "")
	require.Error(t, err)
	require.Nil(t, plain)
}

func TestCoverage964_TPMOperationsPCRPasswordSealRejectsWrongPassword(t *testing.T) {
	ctx := context.Background()
	ops, _ := newSocketTPMOperations(t)

	sealed, err := ops.Seal(ctx, []byte("secret-964"), []int{0, 7}, "s3cret")
	require.NoError(t, err)

	for _, attempt := range []struct {
		name      string
		authValue string
	}{
		{"wrong password", "not-the-secret"},
		{"missing password", ""},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			plain, err := ops.Unseal(ctx, sealed, attempt.authValue)
			require.Error(t, err)
			require.Nil(t, plain)
		})
	}

	plain, err := ops.Unseal(ctx, sealed, "s3cret")
	require.NoError(t, err, "a refused unseal must not spend the sealed object")
	require.Equal(t, []byte("secret-964"), plain)
}

func TestCoverage964_TPMOperationsPCRPasswordSealRejectsChangedPCR(t *testing.T) {
	ctx := context.Background()
	ops, _ := newSocketTPMOperations(t)

	sealed, err := ops.Seal(ctx, []byte("secret-964"), []int{0, 7}, "s3cret")
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("measured-state-change"))
	require.NoError(t, ops.ExtendPCR(7, digest[:]))

	plain, err := ops.Unseal(ctx, sealed, "s3cret")
	require.Error(t, err)
	require.Nil(t, plain)
}

func TestCoverage964_TPMOperationsInjectNilCertificate(t *testing.T) {
	ops, _ := newSocketTPMOperations(t)

	err := ops.InjectEKCertificate(nil)

	var injectFailed ErrEKCertInjectionFailed
	require.True(t, errors.As(err, &injectFailed), "got %v", err)
	require.ErrorContains(t, err, "certificate cannot be nil")
}

func TestCoverage964_NewTPMOperationsErrors(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))

	tests := []struct {
		name       string
		socketPath string
		sealedDir  string
	}{
		{"missing socket", filepath.Join(t.TempDir(), "missing.sock"), t.TempDir()},
		{"sealed dir is a file", serveSimulatorOnSocket(t), filepath.Join(blocked, "sealed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := NewTPMOperations(tt.socketPath, tt.sealedDir, EKAlgorithmRSA, "vm-964", nil)

			require.Nil(t, ops)
			var connectionFailed ErrTPMConnectionFailed
			require.True(t, errors.As(err, &connectionFailed), "got %v", err)
			require.Equal(t, tt.socketPath, connectionFailed.SocketPath)
		})
	}
}

func TestCoverage964_ServiceTPMOperations(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceWithInstance(t, "bundle-964")

	quote, err := service.Quote(ctx, "bundle-964", []byte("nonce"), []int{0})
	require.NoError(t, err)
	require.Equal(t, "SHA256", quote.HashAlgorithm)

	before, err := service.ReadPCR(ctx, "bundle-964", 16)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("event"))
	require.NoError(t, service.ExtendPCR(ctx, "bundle-964", 16, digest[:]))
	after, err := service.ReadPCR(ctx, "bundle-964", 16)
	require.NoError(t, err)
	require.NotEqual(t, before, after)

	blob, err := service.Seal(ctx, "bundle-964", []byte("payload"), &SealOptions{AuthValue: "pw"})
	require.NoError(t, err)
	plain, err := service.Unseal(ctx, "bundle-964", blob, "pw")
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), plain)

	require.False(t, service.IsRunning("bundle-964"), "a zero swtpm handle is not running")
}

func TestCoverage964_ServiceTPMOperationsAfterClose(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)
	ops, socketPath, hangUp := newHangUpTPMOperations(t)
	service.instances["bundle-964"] = &runningInstance{swtpm: &swtpm.SWTPM{}, socketPath: socketPath, tpmOps: ops}
	blob, err := service.Seal(ctx, "bundle-964", []byte("payload"), nil)
	require.NoError(t, err)
	hangUp()

	_, err = service.Quote(ctx, "bundle-964", []byte("nonce"), []int{0})
	var quoteFailed ErrTPMQuoteFailed
	require.True(t, errors.As(err, &quoteFailed), "got %v", err)

	err = service.ExtendPCR(ctx, "bundle-964", 3, make([]byte, sha256.Size))
	var extendFailed ErrPCRExtendFailed
	require.True(t, errors.As(err, &extendFailed), "got %v", err)

	_, err = service.Seal(ctx, "bundle-964", []byte("payload"), nil)
	var sealFailed ErrTPMSealFailed
	require.True(t, errors.As(err, &sealFailed), "got %v", err)

	_, err = service.Unseal(ctx, "bundle-964", blob, "")
	var unsealFailed ErrTPMUnsealFailed
	require.True(t, errors.As(err, &unsealFailed), "got %v", err)
}

func TestCoverage964_ServiceStop(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceWithInstance(t, "bundle-964")

	err := service.Stop(ctx, "bundle-964")

	var stopFailed ErrVTPMStopFailed
	require.True(t, errors.As(err, &stopFailed), "got %v", err)
	require.Equal(t, "bundle-964", stopFailed.BundleID)
	require.ErrorIs(t, err, swtpm.ErrNotRunning)

	err = service.Stop(ctx, "missing")
	var notRunning ErrVTPMNotRunning
	require.True(t, errors.As(err, &notRunning), "got %v", err)
}

func TestCoverage964_ServiceClose(t *testing.T) {
	service, _ := newServiceWithInstance(t, "bundle-964")

	err := service.Close()

	require.ErrorIs(t, err, swtpm.ErrNotRunning)
	require.Empty(t, service.instances, "Close must drop every instance")
}

func TestCoverage964_InjectEKCertificate(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)
	socketPath := serveSimulatorOnSocket(t)

	info, err := service.injectEKCertificate(ctx, socketPath, t.TempDir(), &CreateBundleOptions{Hostname: "vm-964", EKAlgorithm: EKAlgorithmRSA})

	require.NoError(t, err)
	require.Equal(t, "CN=vm-964", info.Subject)
	require.Contains(t, info.Fingerprint, "sha256:")

	stored, err := NewEKCertInjector(socketPath, nil).ReadCertificate(ctx, EKAlgorithmRSA)
	require.NoError(t, err)
	require.Equal(t, "vm-964", stored.Subject.CommonName)
}

func TestCoverage964_InjectEKCertificateCAUnavailable(t *testing.T) {
	cause := errors.New("ca offline")
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), &mockCA{returnErr: cause})
	require.NoError(t, err)

	_, err = service.injectEKCertificate(context.Background(), serveSimulatorOnSocket(t), t.TempDir(), &CreateBundleOptions{Hostname: "vm-964", EKAlgorithm: EKAlgorithmRSA})

	var caUnavailable ErrCAUnavailable
	require.True(t, errors.As(err, &caUnavailable), "got %v", err)
	require.ErrorIs(t, err, cause)
}

func TestCoverage964_InjectEKCertificateForCloneWithoutCA(t *testing.T) {
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)

	info, err := service.injectEKCertificateForClone(context.Background(), t.TempDir(), "vm-964", EKAlgorithmRSA)

	require.NoError(t, err)
	require.Nil(t, info, "without a CA no EK certificate is issued")
}

// writeOVMFVarsStore writes a 4 MiB firmware volume holding an empty,
// healthy authenticated variable store, the layout the native Secure Boot
// enroller parses.
func writeOVMFVarsStore(t *testing.T, path string) {
	t.Helper()

	data := bytes.Repeat([]byte{0xFF}, 4*1024*1024)
	copy(data[0:16], make([]byte, 16))
	copy(data[16:32], uefi.FFS2GUID.Bytes())
	binary.LittleEndian.PutUint64(data[32:40], uint64(len(data)))
	copy(data[40:44], uefi.FirmwareVolumeSignature[:])
	binary.LittleEndian.PutUint32(data[44:48], 0x000F0800)
	binary.LittleEndian.PutUint16(data[48:50], 72)
	binary.LittleEndian.PutUint16(data[50:52], 0)
	binary.LittleEndian.PutUint16(data[52:54], 0)
	data[54] = 0
	data[55] = 2
	binary.LittleEndian.PutUint32(data[56:60], uint32(len(data)/0x1000))
	binary.LittleEndian.PutUint32(data[60:64], 0x1000)
	copy(data[64:72], make([]byte, 8))

	const storeOffset = 72
	copy(data[storeOffset:storeOffset+16], uefi.AuthenticatedVariableGUID.Bytes())
	binary.LittleEndian.PutUint32(data[storeOffset+16:storeOffset+20], uint32(len(data)-storeOffset))
	data[storeOffset+20] = 0x5a
	data[storeOffset+21] = 0xfe
	copy(data[storeOffset+22:storeOffset+28], make([]byte, 6))

	require.NoError(t, os.WriteFile(path, data, 0600))
}

func TestCoverage964_SetupSecureBoot(t *testing.T) {
	ctx := context.Background()
	cfg := createTestConfig(t)
	writeOVMFVarsStore(t, cfg.OVMFVars)
	service, err := NewService(cfg, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	keysDir := filepath.Join(t.TempDir(), "secure-boot-keys")
	nvramPath := filepath.Join(t.TempDir(), "ovmf", "OVMF_VARS.fd")

	info, paths, err := service.setupSecureBoot(ctx, keysDir, nvramPath, "sb-964")

	require.NoError(t, err)
	for _, fingerprint := range []string{info.PKFingerprint, info.KEKFingerprint, info.DBFingerprint} {
		require.Contains(t, fingerprint, "sha256:")
	}
	require.NotEqual(t, info.PKFingerprint, info.KEKFingerprint)
	require.Equal(t, keysDir, paths.Dir)
	for _, file := range []string{paths.PKKey, paths.PKCert, paths.KEKKey, paths.KEKCert, paths.DBKey, paths.DBCert} {
		require.FileExists(t, file)
	}
}

func TestCoverage964_SetupSecureBootEnrollmentFails(t *testing.T) {
	// createTestConfig writes an OVMF vars file holding the bytes "test",
	// which is no firmware volume, so enrollment must fail.
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)

	_, _, err = service.setupSecureBoot(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "OVMF_VARS.fd"), "sb-964")

	var enrollErr ErrSecureBootEnrollmentFailed
	require.ErrorAs(t, err, &enrollErr)
}

// writeBundleManifest writes the manifest that makes a bundle exist on disk.
func writeBundleManifest(t *testing.T, cfg *Config, id string) {
	t.Helper()
	writeBundleManifestJSON(t, cfg, id, `{"id":"`+id+`","hostname":"vm-964","ek_algorithm":"RSA"}`)
}

// writeBundleManifestJSON writes the given manifest document into the
// bundle directory of id, creating its tpm state directory.
func writeBundleManifestJSON(t *testing.T, cfg *Config, id, document string) {
	t.Helper()

	bundlePath := cfg.BundlePath(id)
	require.NoError(t, os.MkdirAll(filepath.Join(bundlePath, "tpm"), 0700))
	manifest := []byte(document)
	require.NoError(t, os.WriteFile(filepath.Join(bundlePath, "manifest.json"), manifest, 0600))
}

func TestCoverage964_ServiceStartErrors(t *testing.T) {
	// An empty PATH makes the swtpm binary lookup fail the same way on
	// every host, without starting any process.
	t.Setenv("PATH", t.TempDir())
	ctx := context.Background()
	cfg := createTestConfig(t)
	service, err := NewService(cfg, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	writeBundleManifest(t, cfg, "start-964")

	err = service.Start(ctx, "start-964")
	var startErr ErrVTPMStartFailed
	require.ErrorAs(t, err, &startErr)
	require.Equal(t, "start-964", startErr.BundleID)
	require.ErrorIs(t, err, swtpm.ErrSWTPMNotInstalled)
	require.False(t, service.IsRunning("start-964"))

	err = service.Start(ctx, "absent-964")
	require.ErrorAs(t, err, &ErrBundleNotFound{})

	service.mu.Lock()
	service.instances["start-964"] = &runningInstance{swtpm: &swtpm.SWTPM{}}
	service.mu.Unlock()
	err = service.Start(ctx, "start-964")
	require.Equal(t, ErrVTPMAlreadyRunning{BundleID: "start-964"}, err)
}

func TestCoverage964_TPMProviderSocketCache(t *testing.T) {
	socketPath := serveSimulatorOnSocket(t)
	provider := NewTPMProvider(nil)

	first, err := provider.GetTPM(socketPath)
	require.NoError(t, err)
	second, err := provider.GetTPM(socketPath)
	require.NoError(t, err)
	require.Same(t, first, second)

	viaTarget, err := provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTargetSwtpm, Device: socketPath})
	require.NoError(t, err)
	require.Same(t, first, viaTarget)

	require.NoError(t, provider.CloseTPM(socketPath))
	require.NoError(t, provider.CloseTPM(socketPath), "closing an uncached socket is a no-op")

	reopened, err := provider.GetTPM(socketPath)
	require.NoError(t, err)
	require.NotSame(t, first, reopened)
	require.NoError(t, provider.CloseAll())
	_, cached := provider.instances.Load(socketPath)
	require.False(t, cached)
}

func TestCoverage964_TPMProviderErrors(t *testing.T) {
	provider := NewTPMProvider(logging.DefaultLogger())
	regularFile := filepath.Join(t.TempDir(), "tpm0")
	require.NoError(t, os.WriteFile(regularFile, nil, 0600))
	missing := filepath.Join(t.TempDir(), "absent.sock")

	_, err := provider.GetTPMForTarget(nil)
	require.Equal(t, ErrNilResolvedTarget{}, err)

	_, err = provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTarget(99)})
	require.Equal(t, ErrUnknownTPMTarget{Target: TPMTarget(99)}, err)

	_, err = provider.GetTPMForTarget(&ResolvedTPMTarget{Target: TPMTargetHardware, Device: regularFile})
	var unavailable ErrHardwareTPMUnavailable
	require.ErrorAs(t, err, &unavailable)
	require.ErrorAs(t, err, &ErrNotCharDevice{})

	_, err = provider.GetHardwareTPM(missing)
	require.ErrorAs(t, err, &unavailable)
	require.ErrorIs(t, err, os.ErrNotExist)

	_, err = provider.GetTPM(missing)
	var connErr ErrTPMConnectionFailed
	require.ErrorAs(t, err, &connErr)
	require.Equal(t, missing, connErr.SocketPath)
}

func TestCoverage964_ReadEKCertFromRunningTPM(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)
	socketPath := serveSimulatorOnSocket(t)
	service.mu.Lock()
	service.instances["ek-964"] = &runningInstance{swtpm: &swtpm.SWTPM{}, socketPath: socketPath}
	service.mu.Unlock()
	generator := &GeneratorService{vtpmService: service, logger: logging.DefaultLogger()}
	bundle := &Bundle{ID: "ek-964", Manifest: &Manifest{EKAlgorithm: EKAlgorithmRSA}}

	_, err = generator.readEKCertFromRunningTPM(ctx, "ek-964", bundle)
	var genErr ErrEKGenerationFailed
	require.ErrorAs(t, err, &genErr, "no EK certificate has been injected yet")

	_, err = service.injectEKCertificate(ctx, socketPath, t.TempDir(), &CreateBundleOptions{Hostname: "vm-964", EKAlgorithm: EKAlgorithmRSA})
	require.NoError(t, err)

	cert, err := generator.readEKCertFromRunningTPM(ctx, "ek-964", bundle)
	require.NoError(t, err)
	require.Equal(t, "vm-964", cert.Subject.CommonName)
}

func TestCoverage964_DeleteRunningBundle(t *testing.T) {
	service, _ := newServiceWithInstance(t, "del-964")
	writeBundleManifest(t, service.config, "del-964")

	require.NoError(t, service.DeleteBundle(context.Background(), "del-964"))

	require.False(t, service.IsRunning("del-964"))
	require.NoDirExists(t, service.config.BundlePath("del-964"))
}

func TestCoverage964_ExtractEKSerial(t *testing.T) {
	cfg := createTestConfig(t)
	service, err := NewService(cfg, logging.DefaultLogger(), nil)
	require.NoError(t, err)
	writeBundleManifestJSON(t, cfg, "serial-964", `{"id":"serial-964","ek_certificate":{"serial_number":"0a1b"}}`)
	writeBundleManifest(t, cfg, "plain-964")
	generator := &GeneratorService{vtpmService: service, logger: logging.DefaultLogger()}

	tests := []struct {
		id     string
		serial string
	}{
		{"serial-964", "0a1b"},
		{"plain-964", ""},
		{"missing-964", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			require.Equal(t, tt.serial, generator.extractEKSerial(&VTPMInstance{ID: tt.id}))
		})
	}
}

// failingWriter rejects every write.
type failingWriter struct{}

var errWriteRejected = errors.New("write rejected")

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteRejected }

func TestCoverage964_ExportErrors(t *testing.T) {
	ctx := context.Background()
	cfg := createTestConfig(t)
	archiver := NewArchiver(cfg, logging.DefaultLogger())
	writeBundleManifest(t, cfg, "export-964")

	err := archiver.Export(ctx, "export-964", failingWriter{})
	require.Equal(t, ErrArchiveOperationFailed{Operation: "export", Cause: errWriteRejected}, err)

	// tar has no representation for a unix socket, so the walk must stop.
	listener, err := net.Listen("unix", filepath.Join(cfg.BundlePath("export-964"), "tpm", "s.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	err = archiver.Export(ctx, "export-964", &bytes.Buffer{})
	var archiveErr ErrArchiveOperationFailed
	require.ErrorAs(t, err, &archiveErr)
	require.Equal(t, "export", archiveErr.Operation)
}

// tarEntry is one member of a test archive.
type tarEntry struct {
	name     string
	typeflag byte
	body     string
}

// buildArchive returns the gzip-compressed tar of entries, with the raw tar
// stream cut to cut bytes when cut is positive.
func buildArchive(t *testing.T, entries []tarEntry, cut int) []byte {
	t.Helper()

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Mode: 0600, Size: int64(len(entry.body))}
		if entry.typeflag == tar.TypeDir {
			header.Mode = 0700
			header.Size = 0
		}
		require.NoError(t, tw.WriteHeader(header))
		_, err := tw.Write([]byte(entry.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	stream := raw.Bytes()
	if cut > 0 {
		stream = stream[:cut]
	}
	var compressed bytes.Buffer
	gzw := gzip.NewWriter(&compressed)
	_, err := gzw.Write(stream)
	require.NoError(t, err)
	require.NoError(t, gzw.Close())
	return compressed.Bytes()
}

func manifestEntry(id string) tarEntry {
	return tarEntry{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"` + id + `"}`}
}

func TestCoverage964_ImportFromFileRejectsBrokenArchives(t *testing.T) {
	block := string(bytes.Repeat([]byte("x"), 1024))
	tests := []struct {
		name    string
		id      string
		entries []tarEntry
		cut     int
	}{
		{"junk instead of tar", "junk", nil, 0},
		{"manifest cut short", "short", []tarEntry{manifestEntry("short")}, 520},
		{"member body cut short", "body", []tarEntry{manifestEntry("body"), {name: "p/tpm/state", typeflag: tar.TypeReg, body: block}}, 1024 + 512 + 100},
		{"member header cut short", "header", []tarEntry{manifestEntry("header"), {name: "p/tpm/state", typeflag: tar.TypeReg, body: "s"}}, 2048 + 100},
		{"directory under a file", "dirfile", []tarEntry{manifestEntry("dirfile"), {name: "p/f", typeflag: tar.TypeReg, body: "f"}, {name: "p/f/sub", typeflag: tar.TypeDir}}, 0},
		{"file under a file", "filefile", []tarEntry{manifestEntry("filefile"), {name: "p/g", typeflag: tar.TypeReg, body: "g"}, {name: "p/g/x", typeflag: tar.TypeReg, body: "x"}}, 0},
		{"file over a directory", "filedir", []tarEntry{manifestEntry("filedir"), {name: "p/d", typeflag: tar.TypeDir}, {name: "p/d", typeflag: tar.TypeReg, body: "d"}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createTestConfig(t)
			archiver := NewArchiver(cfg, logging.DefaultLogger())
			data := buildJunkArchive(t)
			if tt.entries != nil {
				data = buildArchive(t, tt.entries, tt.cut)
			}
			path := filepath.Join(t.TempDir(), "bundle.tar.gz")
			require.NoError(t, os.WriteFile(path, data, 0600))

			bundle, err := archiver.ImportFromFile(context.Background(), path)

			require.Nil(t, bundle)
			var archiveErr ErrArchiveOperationFailed
			require.ErrorAs(t, err, &archiveErr)
			require.Equal(t, "import", archiveErr.Operation)
			require.NoDirExists(t, cfg.BundlePath(tt.id), "a failed import leaves no partial bundle")
		})
	}
}

// buildJunkArchive returns a valid gzip stream whose content is no tar.
func buildJunkArchive(t *testing.T) []byte {
	t.Helper()

	var compressed bytes.Buffer
	gzw := gzip.NewWriter(&compressed)
	_, err := gzw.Write(bytes.Repeat([]byte{0x7f}, 1024))
	require.NoError(t, err)
	require.NoError(t, gzw.Close())
	return compressed.Bytes()
}

func TestCoverage964_ImportFromFileSkipsForeignMembers(t *testing.T) {
	cfg := createTestConfig(t)
	archiver := NewArchiver(cfg, logging.DefaultLogger())
	data := buildArchive(t, []tarEntry{
		manifestEntry("skip-964"),
		{name: "p/", typeflag: tar.TypeDir},
		{name: "other/x", typeflag: tar.TypeReg, body: "foreign"},
		{name: "p/../../escape", typeflag: tar.TypeReg, body: "escape"},
		{name: "p/tpm/state", typeflag: tar.TypeReg, body: "state"},
	}, 0)
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	require.NoError(t, os.WriteFile(path, data, 0600))

	bundle, err := archiver.ImportFromFile(context.Background(), path)

	require.NoError(t, err)
	require.Equal(t, "skip-964", bundle.ID)
	bundlePath := cfg.BundlePath("skip-964")
	state, err := os.ReadFile(filepath.Join(bundlePath, "tpm", "state"))
	require.NoError(t, err)
	require.Equal(t, "state", string(state))
	require.NoFileExists(t, filepath.Join(bundlePath, "x"))
	require.NoFileExists(t, filepath.Join(filepath.Dir(bundlePath), "escape"))
	require.NoFileExists(t, filepath.Join(filepath.Dir(filepath.Dir(bundlePath)), "escape"))
}

func TestCoverage964_ImportAndValidateRejectBrokenArchives(t *testing.T) {
	tests := []struct {
		name string
		data func(t *testing.T) []byte
	}{
		{"junk instead of tar", buildJunkArchive},
		{"manifest cut short", func(t *testing.T) []byte { return buildArchive(t, []tarEntry{manifestEntry("short")}, 520) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archiver := NewArchiver(createTestConfig(t), logging.DefaultLogger())

			_, err := archiver.Import(context.Background(), bytes.NewReader(tt.data(t)))
			var archiveErr ErrArchiveOperationFailed
			require.ErrorAs(t, err, &archiveErr)
			require.Equal(t, "import", archiveErr.Operation)

			_, err = archiver.ValidateArchive(context.Background(), bytes.NewReader(tt.data(t)))
			require.Error(t, err)
		})
	}
}

func TestCoverage964_ImportRejectsUnusableBundleID(t *testing.T) {
	cfg := createTestConfig(t)
	archiver := NewArchiver(cfg, logging.DefaultLogger())
	data := buildArchive(t, []tarEntry{manifestEntry(`bad\u0000id`)}, 0)

	_, err := archiver.Import(context.Background(), bytes.NewReader(data))

	var archiveErr ErrArchiveOperationFailed
	require.ErrorAs(t, err, &archiveErr)
	require.Equal(t, "import", archiveErr.Operation)
}

var errInjectedFault = errors.New("injected tpm command failure")

// faultTPM forwards commands to inner and counts them, failing the one command
// at position failAt (1-based). A failAt of 0 injects nothing.
type faultTPM struct {
	inner  transport.TPM
	sent   atomic.Int32
	failAt atomic.Int32
}

func newFaultTPM(t *testing.T) *faultTPM {
	t.Helper()
	return &faultTPM{inner: transport.FromReadWriter(newSimulator(t))}
}

func (f *faultTPM) Send(command []byte) ([]byte, error) {
	if f.sent.Add(1) == f.failAt.Load() {
		return nil, errInjectedFault
	}
	return f.inner.Send(command)
}

// arm resets the command count and fails the command at position failAt.
func (f *faultTPM) arm(failAt int32) {
	f.failAt.Store(failAt)
	f.sent.Store(0)
}

// sweepCommandFailures runs op fault-free from the state setup builds, records
// the number N of TPM commands it issues and hands its result to verify. Then,
// for every position 1..N, it rebuilds that state, fails the command at the
// position and requires op to return an error that check accepts: a nil error
// means op swallowed the failure, and fails the test naming the position.
func sweepCommandFailures(t *testing.T, tpm *faultTPM, setup func(t *testing.T), op func() error,
	verify func(t *testing.T), check func(t *testing.T, err error),
) {
	t.Helper()
	defer tpm.arm(0)

	tpm.arm(0)
	setup(t)
	tpm.arm(0)
	require.NoError(t, op(), "fault-free run")
	commands := tpm.sent.Load()
	require.Positive(t, commands, "op issued no TPM commands")
	verify(t)

	for position := int32(1); position <= commands; position++ {
		tpm.arm(0)
		setup(t)
		tpm.arm(position)
		err := op()
		if err == nil {
			t.Errorf("failure injected at command %d of %d: op returned nil", position, commands)
			continue
		}
		check(t, err)
	}
	t.Logf("swept %d command positions", commands)
}

// undefineNVIndex removes nvIndex from the TPM when it is defined.
func undefineNVIndex(t *testing.T, tpm transport.TPM, nvIndex uint32) {
	t.Helper()
	handle := tpm2.TPMHandle(nvIndex)
	public, err := tpm2.NVReadPublic{NVIndex: handle}.Execute(tpm)
	if isNVUndefinedError(err) {
		return
	}
	require.NoError(t, err)
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHPlatform,
		NVIndex:    nvNamedHandle{handle: handle, name: public.NVName},
	}.Execute(tpm)
	require.NoError(t, err)
}

// serveTPMOnSocket serves tpm on a unix socket until the test ends.
func serveTPMOnSocket(t *testing.T, tpm transport.TPM) string {
	t.Helper()

	socketPath := filepath.Join(socktest.Dir(t), "swtpm.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	var (
		mu     sync.Mutex
		conns  []net.Conn
		served sync.WaitGroup
	)
	served.Add(1)
	go func() {
		defer served.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			serveTPMConnection(t, tpm, conn)
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		mu.Lock()
		for _, conn := range conns {
			// Most connections are already closed by the client.
			if err := conn.Close(); err != nil {
				t.Logf("close TPM connection: %v", err)
			}
		}
		mu.Unlock()
		served.Wait()
	})
	return socketPath
}

func requireInjectorError(t *testing.T, err error) {
	t.Helper()
	var injectErr ErrEKCertInjectionFailed
	var writeErr ErrNVRAMWriteFailed
	require.True(t, errors.As(err, &injectErr) || errors.As(err, &writeErr), "untyped error: %v", err)
}

func TestCoverage964_EKCertInjectorCommandFailures(t *testing.T) {
	ctx := context.Background()
	tpm := newFaultTPM(t)
	socketPath := serveTPMOnSocket(t, tpm)
	injector := NewEKCertInjector(socketPath, nil)
	cert := newTestEKCertificate(t, 0)
	oldCert := newTestEKCertificate(t, 0)
	nvIndex := EKAlgorithmRSA.NVIndex()

	directFailure := func(t *testing.T, err error) {
		requireInjectorError(t, err)
		require.ErrorIs(t, err, errInjectedFault)
	}
	socketFailure := func(t *testing.T, err error) {
		var injectErr ErrEKCertInjectionFailed
		require.ErrorAs(t, err, &injectErr)
	}
	undefined := func(t *testing.T) { undefineNVIndex(t, tpm, nvIndex) }
	holding := func(c *x509.Certificate) func(t *testing.T) {
		return func(t *testing.T) {
			require.NoError(t, injector.writeCertificate(tpm, c, EKAlgorithmRSA))
		}
	}
	readsBack := func(t *testing.T) {
		stored, err := injector.readCertificate(tpm, nvIndex)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, stored.Raw)
	}
	write := func() error { return injector.writeCertificate(tpm, cert, EKAlgorithmRSA) }

	t.Run("write to an undefined index", func(t *testing.T) {
		sweepCommandFailures(t, tpm, undefined, write, readsBack, directFailure)
	})
	t.Run("write over a defined index", func(t *testing.T) {
		sweepCommandFailures(t, tpm, holding(oldCert), write, readsBack, directFailure)
	})
	t.Run("read", func(t *testing.T) {
		var stored *x509.Certificate
		sweepCommandFailures(t, tpm, holding(cert), func() error {
			var err error
			stored, err = injector.readCertificate(tpm, nvIndex)
			return err
		}, func(t *testing.T) {
			require.Equal(t, cert.Raw, stored.Raw)
		}, directFailure)
	})
	t.Run("read over the socket", func(t *testing.T) {
		var stored *x509.Certificate
		sweepCommandFailures(t, tpm, holding(cert), func() error {
			var err error
			stored, err = injector.ReadCertificate(ctx, EKAlgorithmRSA)
			return err
		}, func(t *testing.T) {
			require.Equal(t, cert.Raw, stored.Raw)
		}, socketFailure)
	})
	t.Run("exists check over the socket", func(t *testing.T) {
		var exists bool
		var stored *x509.Certificate
		sweepCommandFailures(t, tpm, holding(cert), func() error {
			var err error
			exists, stored, err = injector.CheckEKCertificateExists(ctx, EKAlgorithmRSA)
			return err
		}, func(t *testing.T) {
			require.True(t, exists)
			require.Equal(t, cert.Raw, stored.Raw)
		}, socketFailure)
	})
	t.Run("index holding no certificate", func(t *testing.T) {
		garbage := []byte("not a certificate")
		require.NoError(t, injector.defineNVSpace(tpm, nvIndex, uint16(len(garbage))))
		name, err := injector.getNVName(tpm, nvIndex)
		require.NoError(t, err)
		require.NoError(t, injector.writeNVData(tpm, nvIndex, name, garbage, 1024))

		_, err = injector.readCertificate(tpm, nvIndex)
		var injectErr ErrEKCertInjectionFailed
		require.ErrorAs(t, err, &injectErr)

		exists, stored, err := injector.CheckEKCertificateExists(ctx, EKAlgorithmRSA)
		require.NoError(t, err)
		require.True(t, exists, "a defined index with data must not be overwritten")
		require.Nil(t, stored)
	})
}

func TestCoverage964_TPMOperationsAfterHangUp(t *testing.T) {
	ops, _, hangUp := newHangUpTPMOperations(t)
	cert := newTestEKCertificate(t, 0)
	hangUp()

	var injectErr ErrEKCertInjectionFailed
	require.ErrorAs(t, ops.Provision(""), &injectErr)
	_, err := ops.GetEKPublicKey()
	require.ErrorAs(t, err, &injectErr)
	require.ErrorAs(t, ops.InjectEKCertificate(cert), &injectErr)
	require.NoError(t, (&TPMOperations{}).Close(), "closing operations without a TPM is a no-op")
}

func TestCoverage964_TPMProviderProvisionedSocket(t *testing.T) {
	ops, socketPath := newSocketTPMOperations(t)
	require.NoError(t, ops.Close())
	provider := NewTPMProvider(nil)

	tpm, err := provider.GetTPM(socketPath)

	require.NoError(t, err)
	cached, err := provider.GetTPM(socketPath)
	require.NoError(t, err)
	require.Same(t, tpm, cached)
	require.NoError(t, provider.CloseAll())
}

func TestCoverage964_SealUnsealAfterHangUp(t *testing.T) {
	ctx := context.Background()
	ops, _, hangUp := newHangUpTPMOperations(t)
	hangUp()

	// Both need the SSRK as parent, which can no longer be read.
	var wrapped *WrappedError
	sealed, err := ops.Seal(ctx, []byte("secret"), []int{7}, "pin")
	require.ErrorAs(t, err, &wrapped)
	require.Equal(t, "failed to get SSRK attributes", wrapped.Msg)
	require.Nil(t, sealed)

	plain, err := ops.Unseal(ctx, &xkmssdk.SealedData{}, "pin")
	require.ErrorAs(t, err, &wrapped)
	require.Equal(t, "failed to get SSRK attributes", wrapped.Msg)
	require.Nil(t, plain)
}

func TestCoverage964_TPMProviderCharDevice(t *testing.T) {
	provider := NewTPMProvider(nil)
	t.Cleanup(func() { require.NoError(t, provider.CloseAll()) })

	// A character device that answers no TPM command still opens as an
	// uninitialized TPM, which is cached for reuse.
	device, err := provider.GetHardwareTPM(os.DevNull)
	require.NoError(t, err)
	cached, err := provider.GetHardwareTPM(os.DevNull)
	require.NoError(t, err)
	require.Same(t, device, cached)
}

func TestCoverage964_GeneratorEKCertificateFile(t *testing.T) {
	ctx := context.Background()
	cfg := createTestConfig(t)
	service, err := NewService(cfg, logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)
	generator := &GeneratorService{vtpmService: service, logger: logging.DefaultLogger()}
	writeBundleManifest(t, cfg, "file-964")
	ekCertPath := filepath.Join(cfg.BundlePath("file-964"), "tpm", "ek.crt")

	require.NoError(t, os.WriteFile(ekCertPath, []byte("not DER"), 0600))
	_, err = generator.ExportEKCertificate(ctx, "file-964")
	var genErr ErrEKGenerationFailed
	require.ErrorAs(t, err, &genErr)

	// Without a fingerprint in the manifest it is computed from ek.crt.
	cert := newTestEKCertificate(t, 0)
	require.NoError(t, os.WriteFile(ekCertPath, cert.Raw, 0600))
	fingerprint, err := generator.GetEKFingerprint(ctx, "file-964")
	require.NoError(t, err)
	require.Equal(t, certFingerprint(cert), fingerprint)
}

func TestCoverage964_ServiceStorageErrors(t *testing.T) {
	ctx := context.Background()
	cfg := createTestConfig(t)
	service, err := NewService(cfg, logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)

	t.Run("bundle filter by device profile", func(t *testing.T) {
		writeBundleManifest(t, cfg, "profile-964")
		bundles, err := service.ListBundles(ctx, &ListOptions{DeviceProfileID: 7})
		require.NoError(t, err)
		require.Empty(t, bundles)
	})
	t.Run("unreadable bundle manifest", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(cfg.BundlePath("dir-964"), "manifest.json"), 0700))
		_, err := service.GetBundle(ctx, "dir-964")
		var manifestErr ErrInvalidManifest
		require.ErrorAs(t, err, &manifestErr)
	})
	t.Run("unreadable template manifest", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(cfg.TemplatePath("dir-964"), "manifest.json"), 0700))
		_, err := service.GetTemplate(ctx, "dir-964")
		var manifestErr ErrInvalidManifest
		require.ErrorAs(t, err, &manifestErr)
	})
	t.Run("listing directories that are files", func(t *testing.T) {
		for _, dir := range []string{cfg.BundlesDir(), cfg.TemplatesDir()} {
			require.NoError(t, os.RemoveAll(dir))
			require.NoError(t, os.WriteFile(dir, nil, 0600))
		}
		var wrapped *WrappedError

		_, err := service.ListBundles(ctx, nil)
		require.ErrorAs(t, err, &wrapped)
		require.Equal(t, "failed to list bundles", wrapped.Msg)

		_, err = service.ListTemplates(ctx)
		require.ErrorAs(t, err, &wrapped)
		require.Equal(t, "failed to list templates", wrapped.Msg)
	})
}

func TestCoverage964_FileChecksumOfDirectory(t *testing.T) {
	sum, err := fileChecksum(t.TempDir())
	require.Error(t, err)
	require.Empty(t, sum)
}

func TestCoverage964_ExtendPCRRejectsEmptyData(t *testing.T) {
	service, _ := newServiceWithInstance(t, "pcr-964")

	err := service.ExtendPCR(context.Background(), "pcr-964", 16, nil)

	var extendErr ErrPCRExtendFailed
	require.ErrorAs(t, err, &extendErr)
	require.Equal(t, 16, extendErr.PCRIndex)
}

func TestCoverage964_SetupSecureBootKeyGenFails(t *testing.T) {
	service, err := NewService(createTestConfig(t), logging.DefaultLogger(), &mockCA{})
	require.NoError(t, err)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0600))

	_, _, err = service.setupSecureBoot(context.Background(), filepath.Join(blocker, "keys"), filepath.Join(t.TempDir(), "OVMF_VARS.fd"), "sb-964")

	var keyErr ErrSecureBootKeyGenFailed
	require.ErrorAs(t, err, &keyErr)
}

func TestCoverage964_ResolveTPMTargetCharDevice(t *testing.T) {
	resolved, err := ResolveTPMTarget(&xkmssdk.TPMConfig{Device: os.DevNull}, nil)

	require.NoError(t, err)
	require.Equal(t, &ResolvedTPMTarget{Target: TPMTargetHardware, Device: os.DevNull}, resolved)
}
