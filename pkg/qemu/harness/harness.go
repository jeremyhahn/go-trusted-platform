// Package harness is the software-TPM and serial-console plumbing that
// every emulated boot of the platform shares: `platformctl iso test`,
// `platformctl diskimage test boot` and the integration suites that boot
// an installed disk or a factory image under QEMU. It starts (or resumes)
// a swtpm for a qemu.Config, waits for milestones in the guest's serial
// transcript, and drives an interactive console over the VM's console
// socket. It holds no test framework references, so it is usable from a
// CLI as much as from a test.
package harness

import (
	"context"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

// TPM is the part of *swtpm.SWTPM the harness and its callers use. It is
// an interface so the harness can be unit-tested without a swtpm binary.
type TPM interface {
	IsInitialized() bool
	Initialize(ctx context.Context) error
	Start(ctx context.Context) error
	WaitForSocket(timeout time.Duration) error
	SocketPath() string
	StateDir() string
	PID() int
	Stop() error
}

// TPMState reports whether StartTPM created fresh TPM state or resumed the
// state a previous boot left, which is what keeps PCR values and sealed
// data valid across the boots of one test sequence.
type TPMState string

const (
	// TPMStateInitialized means the state directory was empty and swtpm_setup ran.
	TPMStateInitialized TPMState = "initialized"
	// TPMStatePreserved means existing state was kept.
	TPMStatePreserved TPMState = "preserved"
)

// socketTimeout bounds the wait for swtpm's control socket after start.
const socketTimeout = 5 * time.Second

// newTPM constructs the swtpm; a variable so tests substitute a fake.
var newTPM = func(cfg *swtpm.Config, logger *logging.Logger) (TPM, error) {
	return swtpm.NewSWTPM(cfg, logger)
}

// stopExisting stops swtpm instances left in a state directory; a
// variable for the same reason.
var stopExisting = swtpm.StopExisting

// StartTPM starts the software TPM for a VM: its state lives under
// <WorkDir>/tpm, it is initialised only when that directory holds no
// state, and it is started in QEMU mode (the --ctrl socket QEMU's
// emulator tpmdev expects). On return cfg.TPMSocket names the socket the
// daemon actually opened, which swtpm may relocate for Docker volumes.
func StartTPM(ctx context.Context, logger *logging.Logger, cfg *qemu.Config) (TPM, TPMState, error) {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	tpmDir := filepath.Join(cfg.WorkDir, "tpm")

	if err := stopExisting(tpmDir); err != nil {
		logger.Warnf("Failed to stop existing TPM instances: %v", err)
	}

	tpm, err := newTPM(&swtpm.Config{
		StateDir:   tpmDir,
		SocketPath: cfg.GetTPMSocketPath(),
		PCRBanks:   []string{"sha256"},
		Debug:      cfg.Debug,
		QEMUMode:   true,
	}, logger)
	if err != nil {
		return nil, "", &TPMError{Step: "creating the software TPM", Err: err}
	}

	state := TPMStatePreserved
	if !tpm.IsInitialized() {
		if err := tpm.Initialize(ctx); err != nil {
			return nil, "", &TPMError{Step: "initializing the software TPM", Err: err}
		}
		state = TPMStateInitialized
	} else {
		logger.Info("Using existing TPM state (preserving PCR values and sealed data)")
	}

	if err := tpm.Start(ctx); err != nil {
		return nil, "", &TPMError{Step: "starting the software TPM", Err: err}
	}
	cfg.TPMSocket = tpm.SocketPath()
	logger.Debugf("TPM socket path: %s", cfg.TPMSocket)

	if err := tpm.WaitForSocket(socketTimeout); err != nil {
		StopTPM(logger, tpm)
		return nil, "", &TPMError{Step: "waiting for the TPM socket", Err: err}
	}
	return tpm, state, nil
}

// StopTPM stops a TPM StartTPM returned; nil is a no-op.
func StopTPM(logger *logging.Logger, tpm TPM) {
	if tpm == nil {
		return
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	logger.Info("Stopping software TPM...")
	if err := tpm.Stop(); err != nil {
		logger.Warnf("Failed to stop TPM: %v", err)
	}
}
