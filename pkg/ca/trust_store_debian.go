package ca

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/op/go-logging"
)

type DebianTrustStore struct {
	logger   *logging.Logger
	certDir  string
	storeDir string
	TrustStore
}

func NewDebianTrustStore(logger *logging.Logger, certDir string) TrustStore {
	return &DebianTrustStore{
		logger:   logger,
		certDir:  certDir,
		storeDir: "/usr/local/share/ca-certificates"}
}

func (store *DebianTrustStore) Install(cn string) error {
	store.logger.Debugf("installing %s.crt to operating system trusted certificate store: %s",
		cn, store.storeDir)
	certFile := fmt.Sprintf("%s/%s.crt", store.certDir, cn)
	storeFile := fmt.Sprintf("%s/%s.crt", store.storeDir, cn)
	data, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	if err = os.WriteFile(storeFile, data, 0644); err != nil {
		return err
	}
	return store.UpdateCerts()
}

func (store *DebianTrustStore) Uninstall(cn string) error {
	store.logger.Debugf("uninstalling %s.crt from operating system trusted certificate store: %s",
		cn, store.storeDir)
	storeFile := fmt.Sprintf("%s/%s.crt", store.storeDir, cn)
	if err := os.Remove(storeFile); err != nil {
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
