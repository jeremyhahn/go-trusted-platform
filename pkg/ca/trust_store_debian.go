package ca

import (
	"fmt"
	"os/exec"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/spf13/afero"
)

type DebianTrustStore struct {
	logger   *logging.Logger
	certDir  string
	fs       afero.Fs
	storeDir string
	OSTrustStore
}

func NewDebianTrustStore(logger *logging.Logger, fs afero.Fs, certDir string) OSTrustStore {
	return &DebianTrustStore{
		logger:   logger,
		certDir:  certDir,
		fs:       fs,
		storeDir: "/usr/local/share/ca-certificates"}
}

func (store *DebianTrustStore) Install(cn string) error {
	store.logger.Debugf(
		"installing %s.crt to operating system trusted certificate store: %s",
		cn, store.storeDir)
	certFile := fmt.Sprintf("%s/%s.crt", store.certDir, cn)
	storeFile := fmt.Sprintf("%s/%s.crt", store.storeDir, cn)
	data, err := afero.ReadFile(store.fs, certFile)
	if err != nil {
		return err
	}
	if err = afero.WriteFile(store.fs, storeFile, data, 0644); err != nil {
		return err
	}
	return store.UpdateCerts()
}

func (store *DebianTrustStore) Uninstall(cn string) error {
	store.logger.Debugf("uninstalling %s.crt from operating system trusted certificate store: %s",
		cn, store.storeDir)
	storeFile := fmt.Sprintf("%s/%s.crt", store.storeDir, cn)
	if err := store.fs.Remove(storeFile); err != nil {
		return err
	}
	return store.UpdateCerts()
}

func (store *DebianTrustStore) UpdateCerts() error {
	cmd := exec.Command("update-ca-certificates")
	stdout, err := cmd.Output()
	if err != nil {
		return err
	}
	store.logger.Infof("update-ca-certificates: %s", string(stdout))
	return nil
}
