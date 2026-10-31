package bootstrap

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestTypedErrorMessages pins the operator-facing text of the package's
// typed errors and, for wrapping types, that the cause stays reachable
// through errors.Is. The messages name the node, host or field an
// operator must act on; a refactor that drops one is a regression.
func TestTypedErrorMessages(t *testing.T) {
	cause := errors.New("boom")

	tests := []struct {
		name  string
		err   error
		want  string
		wraps bool
	}{
		{"ErrNilLogger", ErrNilLogger{}, "logger cannot be nil", false},
		{"ErrSecretNotFound", ErrSecretNotFound{Path: "kms://a"}, "secret not found at path: kms://a", false},
		{"ErrSecretStoreFailed with cause", ErrSecretStoreFailed{Path: "p", Cause: cause}, "failed to store secret at p: boom", true},
		{"ErrSecretStoreFailed without cause", ErrSecretStoreFailed{Path: "p"}, "failed to store secret at p", false},
		{"ErrInvalidURI with reason", ErrInvalidURI{URI: "x://", Reason: "bad scheme"}, "invalid URI x://: bad scheme", false},
		{"ErrInvalidURI without reason", ErrInvalidURI{URI: "x://"}, "invalid URI: x://", false},
		{"ErrAutoGenFailed with cause", ErrAutoGenFailed{Path: "p", Spec: "pin:8", Cause: cause}, "failed to auto-generate secret for p with spec pin:8: boom", true},
		{"ErrAutoGenFailed without cause", ErrAutoGenFailed{Path: "p", Spec: "pin:8"}, "failed to auto-generate secret for p with spec pin:8", false},
		{"ErrEnvVarNotFound", ErrEnvVarNotFound{Name: "BMC_PASS"}, "environment variable not found: BMC_PASS", false},
		{"ErrRemoteKMSUnavailable with cause", ErrRemoteKMSUnavailable{Endpoint: "kms:1", Cause: cause}, "remote KMS at kms:1 is unavailable: boom", true},
		{"ErrRemoteKMSUnavailable without cause", ErrRemoteKMSUnavailable{Endpoint: "kms:1"}, "remote KMS at kms:1 is unavailable", false},
		{"ErrDecryptionFailed with cause", ErrDecryptionFailed{Path: "p", Cause: cause}, "failed to decrypt secret at p: boom", true},
		{"ErrDecryptionFailed without cause", ErrDecryptionFailed{Path: "p"}, "failed to decrypt secret at p", false},
		{"ErrInvalidPINLength", ErrInvalidPINLength{Length: 0}, "bootstrap: invalid PIN length: 0 (must be > 0)", false},
		{"ErrPINGeneration", ErrPINGeneration{Cause: cause}, "bootstrap: failed to generate PIN: boom", true},
		{"ErrDANEPublishFailed", ErrDANEPublishFailed{Zone: "example.com", Cause: cause}, "bootstrap: TLSA record publication failed for zone example.com: boom", true},
		{"ErrTLSAComputeFailed", ErrTLSAComputeFailed{CN: "node-01", Cause: cause}, "bootstrap: TLSA data computation failed for CN node-01: boom", true},
		{"ErrCertReloadFailed", ErrCertReloadFailed{Cause: cause}, "bootstrap: certificate hot-reload failed: boom", true},
		{"ErrNoiseServerFailed", ErrNoiseServerFailed{Cause: cause}, "bootstrap: noise server error: boom", true},
		{"ErrInvalidConfig", ErrInvalidConfig{Field: "deployer", Reason: "must not be nil"}, "bootstrap: invalid config: field deployer: must not be nil", false},
		{"ErrRolloverInProgress", ErrRolloverInProgress{Hostname: "node-01"}, "bootstrap: rollover already in progress for node-01", false},
		{"ErrCABundleEmpty", ErrCABundleEmpty{}, "bootstrap: CA bundle is empty", false},
		{"ErrVirtualMediaRequiresBMC", ErrVirtualMediaRequiresBMC{Hostname: "node-01"}, "bootstrap: node node-01: boot_method=virtual-media requires bmc_address", false},
		{"ErrISOStagingFailed", ErrISOStagingFailed{LocalPath: "/iso", RemoteHost: "jump", Cause: cause}, "bootstrap: failed to stage ISO /iso on jump: boom", true},
		{"ErrBootDeviceSetFailed", ErrBootDeviceSetFailed{Hostname: "n", Device: "cd", Cause: cause}, "bootstrap: node n: failed to set boot device cd: boom", true},
		{"ErrPowerControlFailed", ErrPowerControlFailed{Hostname: "n", Operation: "on", Cause: cause}, "bootstrap: node n: BMC power on failed: boom", true},
		{"ErrPowerStateVerificationFailed", ErrPowerStateVerificationFailed{Hostname: "n", Expected: "On", Actual: "Off", Retries: 3},
			"bootstrap: node n: power state verification failed after 3 retries: expected On, got Off", false},
		{"ErrRegistrationFetch", ErrRegistrationFetch{URL: "http://c/r.json", Cause: cause}, "bootstrap: failed to fetch registration from http://c/r.json: boom", true},
		{"ErrInstallFailed", ErrInstallFailed{Hostname: "n", ExitCode: 2, LogURL: "http://c/l"}, "bootstrap: node n: installer exited with code 2; see install.log at http://c/l", false},
		{"ErrBMCReconnect", ErrBMCReconnect{Hostname: "n", Operation: "eject", Cause: cause}, "bootstrap: node n: failed to reopen BMC client for eject: boom", true},
		{"WrappedError", &WrappedError{Msg: "staging", Err: cause}, "staging: boom", true},
		{"ErrMediaStatusUnavailable with status", ErrMediaStatusUnavailable{URL: "http://c/m", StatusCode: 503}, "bootstrap: media status at http://c/m unavailable: status 503", false},
		{"ErrMediaStatusUnavailable without status", ErrMediaStatusUnavailable{URL: "http://c/m"}, "bootstrap: media status at http://c/m unavailable", false},
		{"ErrNodeConfigResolveFailed", ErrNodeConfigResolveFailed{Hostname: "n", Cause: cause}, "bootstrap: resolve the config of node n: boom", true},
		{"ErrUnknownNode", ErrUnknownNode{Hostname: "n"}, "bootstrap: no node n in the bootstrap config", false},
		{"ErrInvalidPort", ErrInvalidPort{Field: "deployer.bootstrap_http_port", Port: 0, Reason: "bad"}, "bootstrap: deployer.bootstrap_http_port = 0: bad", false},
		{"ErrSecretSchemaNotStruct", ErrSecretSchemaNotStruct{Type: "int"}, "secret field schema int is not a struct", false},
		{"ErrSecretDocumentParse", ErrSecretDocumentParse{Err: cause}, "parsing the document for secret fields: boom", true},
		{"ErrNetbootMediaRequired without node", ErrNetbootMediaRequired{Reason: "unset", Err: cause}, "bootstrap: netboot media: unset: boom", true},
		{"ErrContainerDeployFailed with cause", ErrContainerDeployFailed{Host: "h", Cause: cause}, "bootstrap: container deploy failed on host h: boom", true},
		{"ErrContainerDeployFailed without cause", ErrContainerDeployFailed{Host: "h"}, "bootstrap: container deploy failed on host h", false},
		{"ErrContainerTeardownFailed with cause", ErrContainerTeardownFailed{Host: "h", Cause: cause}, "bootstrap: container teardown failed on host h: boom", true},
		{"ErrTemplateReadFailed without cause", ErrTemplateReadFailed{Role: "gateway", Path: "/t.yaml"}, "bootstrap: failed to read template for role gateway at /t.yaml", false},
		{"ErrControlPlaneHealthGateFailed with cause", ErrControlPlaneHealthGateFailed{Timeout: time.Minute, Cause: cause}, "bootstrap: control-plane health gate failed after 1m0s: boom", true},
		{"ErrControlPlaneHealthGateFailed without cause", ErrControlPlaneHealthGateFailed{Timeout: time.Minute}, "bootstrap: control-plane health gate failed after 1m0s", false},
		{"ErrCABundleInvalid", ErrCABundleInvalid{URL: "https://cp/ca"}, "bootstrap: control-plane CA bundle from https://cp/ca contains no parseable certificates", false},
		{"ErrCABundleVerifyFailed", ErrCABundleVerifyFailed{URL: "https://cp/ca", Cause: cause},
			"bootstrap: TLS chain serving https://cp/ca does not verify against the fetched CA bundle, rejecting bundle: boom", true},
		{"ErrNoPeerCertificates", ErrNoPeerCertificates{Endpoint: "cp:8443"}, "bootstrap: TLS handshake with cp:8443 returned no peer certificates", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
			assert.Equal(t, tt.wraps, errors.Is(tt.err, cause), "errors.Is(err, cause)")
		})
	}
}

func TestErrContainerServiceNotServing_NamesListenerAndRemedy(t *testing.T) {
	cause := errors.New("connection refused")
	base := ErrContainerServiceNotServing{Host: "jump", BaseURL: "http://jump:8080", Listener: "HTTP service"}

	msg := base.Error()
	assert.Contains(t, msg, "container started on jump but its HTTP service at http://jump:8080 is not serving")
	assert.Contains(t, msg, "deployer.bootstrap_http_port")
	assert.False(t, errors.Is(base, cause))

	withCause := base
	withCause.Cause = cause
	assert.Equal(t, msg+": connection refused", withCause.Error())
	assert.ErrorIs(t, withCause, cause)
}
