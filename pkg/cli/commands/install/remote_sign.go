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

package install

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// remoteSignInstallerOptions assembles the installer options that enable
// install-time remote Secure Boot DB signing (resign-mode: remote). The DB
// private key never leaves the control plane: the installer signs the UKI digest
// via POST /api/v1/provisioning/sign using the EAB + EK identity gathered here
// (the same identity `platformctl provision fetch-config` presents).
//
// It returns no options — leaving the installer to fall through to on-node key
// generation — when remote signing is not applicable: Secure Boot is disabled,
// resign-mode is not remote, or no control-plane URL was supplied (airgap).
func remoteSignInstallerOptions(config *installer.Config, cmdFlags *systemFlags) ([]installer.InstallerOption, error) {
	if config == nil || config.SecureBoot == nil || !config.SecureBoot.Enabled {
		return nil, nil
	}
	if config.SecureBoot.ResignMode != installer.SecureBootResignModeRemote {
		return nil, nil
	}
	if cmdFlags.provisionServerURL == "" {
		// No provisioning context supplied; the installer generates the DB key
		// on-node (existing behavior).
		return nil, nil
	}

	httpClient, err := buildVerifiedHTTPClient(cmdFlags.caBundle)
	if err != nil {
		return nil, err
	}

	ekCertB64, err := readEKCertBase64(cmdFlags.ekCertPath)
	if err != nil {
		return nil, err
	}

	rsc := &installer.RemoteSignContext{
		ServerURL:  cmdFlags.provisionServerURL,
		EABKeyID:   cmdFlags.eabKID,
		EABHMAC:    cmdFlags.eabHMAC,
		EKSerial:   cmdFlags.ekSerial,
		MACAddress: cmdFlags.mac,
		EKCertB64:  ekCertB64,
		HTTPClient: httpClient,
	}
	return []installer.InstallerOption{installer.WithRemoteSignContext(rsc)}, nil
}

// buildVerifiedHTTPClient returns an *http.Client whose TLS configuration
// verifies the control plane's certificate against the CA bundle at caBundlePath
// (TLS 1.3 minimum). InsecureSkipVerify is never set. When caBundlePath is empty
// it returns nil so the installer uses a default client that trusts the system
// root store — still verified, never insecure.
func buildVerifiedHTTPClient(caBundlePath string) (*http.Client, error) {
	if caBundlePath == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, ErrCABundleRead{Path: caBundlePath, Err: err}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, ErrCABundleParse{Path: caBundlePath}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}, nil
}

// readEKCertBase64 reads the TPM EK certificate at path and returns its DER bytes
// standard-base64 encoded (the wire form the control plane expects). A PEM file
// is decoded to its DER body; a raw DER file is encoded as-is. An empty path
// yields an empty string (the EK certificate is optional — required only for
// EK-bound profiles).
func readEKCertBase64(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", ErrEKCertRead{Path: path, Err: err}
	}
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return "", ErrEKCertParse{Path: path, Err: err}
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
