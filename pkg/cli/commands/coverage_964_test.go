package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	authsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/auth"
	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// errDaemonRefused is the failure the fake daemon returns when told to fail.
var errDaemonRefused = errors.New("daemon refused the request")

// recordingDaemon is an in-process PlatformDaemon that records every
// request the CLI sends and answers with fixed data, or with err when set.
type recordingDaemon struct {
	platformv1.UnimplementedPlatformDaemonServer

	err error

	getConfig      *platformv1.GetConfigRequest
	updateConfig   *platformv1.UpdateConfigRequest
	reloaded       bool
	startService   *platformv1.StartServiceRequest
	stopService    *platformv1.StopServiceRequest
	restartService *platformv1.RestartServiceRequest
	serviceStatus  *platformv1.GetServiceStatusRequest
	health         *platformv1.GetHealthRequest
}

func (d *recordingDaemon) GetConfig(_ context.Context, req *platformv1.GetConfigRequest) (*platformv1.GetConfigResponse, error) {
	d.getConfig = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.GetConfigResponse{Sections: []*platformv1.ConfigSection{
		{Section: "tpm", Values: map[string]string{"device": "/dev/tpmrm0"}},
	}}, nil
}

func (d *recordingDaemon) UpdateConfig(_ context.Context, req *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error) {
	d.updateConfig = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.UpdateConfigResponse{}, nil
}

func (d *recordingDaemon) ReloadConfig(_ context.Context, _ *platformv1.ReloadConfigRequest) (*platformv1.ReloadConfigResponse, error) {
	d.reloaded = true
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.ReloadConfigResponse{ReloadedSections: []string{"tpm", "dns"}}, nil
}

func (d *recordingDaemon) ListServices(_ context.Context, _ *platformv1.ListServicesRequest) (*platformv1.ListServicesResponse, error) {
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.ListServicesResponse{Services: []*platformv1.ServiceInfo{testServiceInfo()}}, nil
}

func (d *recordingDaemon) StartService(_ context.Context, req *platformv1.StartServiceRequest) (*platformv1.StartServiceResponse, error) {
	d.startService = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.StartServiceResponse{Service: testServiceInfo()}, nil
}

func (d *recordingDaemon) StopService(_ context.Context, req *platformv1.StopServiceRequest) (*platformv1.StopServiceResponse, error) {
	d.stopService = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.StopServiceResponse{}, nil
}

func (d *recordingDaemon) RestartService(_ context.Context, req *platformv1.RestartServiceRequest) (*platformv1.RestartServiceResponse, error) {
	d.restartService = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.RestartServiceResponse{Service: testServiceInfo()}, nil
}

func (d *recordingDaemon) GetServiceStatus(_ context.Context, req *platformv1.GetServiceStatusRequest) (*platformv1.GetServiceStatusResponse, error) {
	d.serviceStatus = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.GetServiceStatusResponse{Service: testServiceInfo()}, nil
}

func (d *recordingDaemon) GetStatus(_ context.Context, _ *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.GetStatusResponse{Services: []*platformv1.ServiceInfo{testServiceInfo()}}, nil
}

func (d *recordingDaemon) GetHealth(_ context.Context, req *platformv1.GetHealthRequest) (*platformv1.GetHealthResponse, error) {
	d.health = req
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.GetHealthResponse{Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY}, nil
}

func (d *recordingDaemon) GetVersion(_ context.Context, _ *platformv1.GetVersionRequest) (*platformv1.GetVersionResponse, error) {
	if d.err != nil {
		return nil, d.err
	}
	return &platformv1.GetVersionResponse{Version: "9.8.7", Components: map[string]string{"qrdb": "1.2.3"}}, nil
}

func testServiceInfo() *platformv1.ServiceInfo {
	return &platformv1.ServiceInfo{
		Type:    platformv1.ServiceType_SERVICE_TYPE_TPM,
		Name:    "tpm-service",
		Version: "4.5.6",
	}
}

// recordingHost hosts the recording daemon in-process, as an embedded
// context does.
type recordingHost struct {
	services *embedded.ServiceRegistry
	stops    int
}

func (h *recordingHost) Services() *embedded.ServiceRegistry { return h.services }

func (h *recordingHost) Stop(context.Context) error {
	h.stops++
	return nil
}

// embeddedDaemonFlags returns flags whose embedded context is served by d.
func embeddedDaemonFlags(d *recordingDaemon, format cli.OutputFormat) (func() *cli.CommonFlags, *recordingHost) {
	host := &recordingHost{services: &embedded.ServiceRegistry{Daemon: d}}
	c := &cli.Context{Name: "embedded-test", Type: cli.ContextTypeEmbedded}
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext:   func() (*cli.Context, error) { return c, nil },
			StartEmbedded: func(context.Context, *cli.Context) (cli.EmbeddedHost, error) {
				return host, nil
			},
		}
	}, host
}

// captureStdout runs fn with os.Stdout redirected and returns what fn
// wrote there.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, rerr := io.ReadAll(r)
		if rerr != nil {
			b = append(b, []byte(rerr.Error())...)
		}
		done <- b
	}()
	runErr := fn()
	os.Stdout = orig
	require.NoError(t, w.Close())
	out := <-done
	require.NoError(t, r.Close())
	return string(out), runErr
}

// runCommand executes cmd with args and returns its stdout and error.
func runCommand(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return captureStdout(t, cmd.Execute)
}

type daemonCommandCase struct {
	name    string
	newCmd  func(func() *cli.CommonFlags) *cobra.Command
	args    []string
	format  cli.OutputFormat
	wantOut string
	check   func(t *testing.T, d *recordingDaemon)
}

func daemonCommandCases() []daemonCommandCase {
	return []daemonCommandCase{
		{
			name: "config get table", newCmd: NewConfigCommand, args: []string{"get", "tpm"},
			format: cli.OutputFormatTable, wantOut: "/dev/tpmrm0",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.getConfig)
				assert.Equal(t, "tpm", d.getConfig.GetSection())
			},
		},
		{
			name: "config get json", newCmd: NewConfigCommand, args: []string{"get"},
			format: cli.OutputFormatJSON, wantOut: "/dev/tpmrm0",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.getConfig)
				assert.Empty(t, d.getConfig.GetSection())
			},
		},
		{
			name: "config set persisted", newCmd: NewConfigCommand,
			args:   []string{"set", "dns", "port=53", "upstream=a=b", "--persist"},
			format: cli.OutputFormatTable, wantOut: "persisted",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.updateConfig)
				assert.True(t, d.updateConfig.GetPersist())
				assert.Equal(t, "dns", d.updateConfig.GetSection().GetSection())
				assert.Equal(t, map[string]string{"port": "53", "upstream": "a=b"},
					d.updateConfig.GetSection().GetValues())
			},
		},
		{
			name: "config set not persisted", newCmd: NewConfigCommand,
			args:   []string{"set", "dns", "port=53"},
			format: cli.OutputFormatTable, wantOut: "not persisted",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.updateConfig)
				assert.False(t, d.updateConfig.GetPersist())
			},
		},
		{
			name: "config reload", newCmd: NewConfigCommand, args: []string{"reload"},
			format: cli.OutputFormatTable, wantOut: "tpm, dns",
			check: func(t *testing.T, d *recordingDaemon) { assert.True(t, d.reloaded) },
		},
		{
			name: "service list table", newCmd: NewServiceCommand, args: []string{"list"},
			format: cli.OutputFormatTable, wantOut: "tpm-service",
		},
		{
			name: "service list json", newCmd: NewServiceCommand, args: []string{"list"},
			format: cli.OutputFormatJSON, wantOut: "tpm-service",
		},
		{
			name: "service start table", newCmd: NewServiceCommand, args: []string{"start", "tpm"},
			format: cli.OutputFormatTable, wantOut: "Service tpm started successfully",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.startService)
				assert.Equal(t, platformv1.ServiceType_SERVICE_TYPE_TPM, d.startService.GetService())
			},
		},
		{
			name: "service start json", newCmd: NewServiceCommand, args: []string{"start", "tpm"},
			format: cli.OutputFormatJSON, wantOut: `"action": "start"`,
		},
		{
			name: "service stop forwards force and timeout", newCmd: NewServiceCommand,
			args:   []string{"stop", "dns", "--force", "--timeout", "7"},
			format: cli.OutputFormatTable, wantOut: "Service dns stopped successfully",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.stopService)
				assert.Equal(t, platformv1.ServiceType_SERVICE_TYPE_DNS, d.stopService.GetService())
				assert.True(t, d.stopService.GetForce())
				assert.Equal(t, uint32(7), d.stopService.GetTimeoutSeconds())
			},
		},
		{
			name: "service restart forwards timeout", newCmd: NewServiceCommand,
			args:   []string{"restart", "sdn", "--timeout", "9"},
			format: cli.OutputFormatYAML, wantOut: "action: restart",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.restartService)
				assert.Equal(t, platformv1.ServiceType_SERVICE_TYPE_SDN, d.restartService.GetService())
				assert.Equal(t, uint32(9), d.restartService.GetTimeoutSeconds())
			},
		},
		{
			name: "service status table", newCmd: NewServiceCommand, args: []string{"status", "tpm"},
			format: cli.OutputFormatTable, wantOut: "4.5.6",
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.serviceStatus)
				assert.Equal(t, platformv1.ServiceType_SERVICE_TYPE_TPM, d.serviceStatus.GetService())
			},
		},
		{
			name: "service status json", newCmd: NewServiceCommand, args: []string{"status", "tpm"},
			format: cli.OutputFormatJSON, wantOut: "tpm-service",
		},
		{
			name: "status table", newCmd: NewStatusCommand,
			format: cli.OutputFormatTable, wantOut: "tpm-service",
		},
		{
			name: "status json", newCmd: NewStatusCommand,
			format: cli.OutputFormatJSON, wantOut: "tpm-service",
		},
		{
			name: "health detailed", newCmd: NewHealthCommand, args: []string{"--detailed"},
			format: cli.OutputFormatJSON, wantOut: `"status": "HEALTHY"`,
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.health)
				assert.True(t, d.health.GetDetailed())
			},
		},
		{
			name: "health table", newCmd: NewHealthCommand,
			format: cli.OutputFormatTable,
			check: func(t *testing.T, d *recordingDaemon) {
				require.NotNil(t, d.health)
				assert.False(t, d.health.GetDetailed())
			},
		},
		{
			name: "version table", newCmd: NewVersionCommand,
			format: cli.OutputFormatTable, wantOut: "1.2.3",
		},
		{
			name: "version json", newCmd: NewVersionCommand,
			format: cli.OutputFormatJSON, wantOut: "9.8.7",
		},
	}
}

func TestDaemonCommands_ForwardTheRequestAndRenderTheAnswer(t *testing.T) {
	for _, tc := range daemonCommandCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := &recordingDaemon{}
			getFlags, host := embeddedDaemonFlags(d, tc.format)

			out, err := runCommand(t, tc.newCmd(getFlags), tc.args...)

			require.NoError(t, err)
			assert.Contains(t, out, tc.wantOut)
			assert.Equal(t, 1, host.stops, "the embedded host is stopped when the command ends")
			if tc.check != nil {
				tc.check(t, d)
			}
		})
	}
}

func TestDaemonCommands_ReturnTheDaemonFailure(t *testing.T) {
	for _, tc := range daemonCommandCases() {
		t.Run(tc.name, func(t *testing.T) {
			d := &recordingDaemon{err: errDaemonRefused}
			getFlags, _ := embeddedDaemonFlags(d, tc.format)

			_, err := runCommand(t, tc.newCmd(getFlags), tc.args...)

			require.Error(t, err)
			assert.Contains(t, err.Error(), errDaemonRefused.Error())
		})
	}
}

func TestDaemonCommands_RejectAnUnknownOutputFormat(t *testing.T) {
	for _, tc := range daemonCommandCases() {
		if tc.format != cli.OutputFormatTable {
			continue
		}
		switch tc.name {
		case "config set persisted", "config set not persisted", "config reload":
			// set and reload print fixed messages in every format.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			getFlags, _ := embeddedDaemonFlags(&recordingDaemon{}, cli.OutputFormat("xml"))

			_, err := runCommand(t, tc.newCmd(getFlags), tc.args...)

			var formatErr cli.ErrInvalidOutputFormat
			require.ErrorAs(t, err, &formatErr)
			assert.Equal(t, "xml", formatErr.Format)
		})
	}
}

func TestDaemonCommands_RefuseWithoutAContext(t *testing.T) {
	noContext := func() *cli.CommonFlags { return &cli.CommonFlags{OutputFormat: cli.OutputFormatTable} }
	for _, tc := range daemonCommandCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runCommand(t, tc.newCmd(noContext), tc.args...)

			var noCtx cli.ErrNoContextSet
			require.ErrorAs(t, err, &noCtx)
		})
	}
}

func TestConfigSet_RejectsAPairWithoutEquals(t *testing.T) {
	d := &recordingDaemon{}
	getFlags, _ := embeddedDaemonFlags(d, cli.OutputFormatTable)

	_, err := runCommand(t, NewConfigCommand(getFlags), "set", "dns", "port")

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Msg, "port")
	assert.Nil(t, d.updateConfig, "nothing is sent when a pair is malformed")
}

func TestServiceStart_RejectsAnUnknownServiceType(t *testing.T) {
	d := &recordingDaemon{}
	getFlags, _ := embeddedDaemonFlags(d, cli.OutputFormatTable)

	_, err := runCommand(t, NewServiceCommand(getFlags), "start", "no-such-service")

	var unknown *daemonsvc.ErrUnknownServiceType
	require.ErrorAs(t, err, &unknown)
	assert.Nil(t, d.startService, "nothing is sent for an unknown service type")
}

func TestVersion_ClientOnlyNeedsNoDaemon(t *testing.T) {
	orig := app.Version
	t.Cleanup(func() { app.Version = orig })

	cases := []struct {
		name    string
		version string
		format  cli.OutputFormat
		want    string
	}{
		{name: "table with a release version", version: "3.1.4", format: cli.OutputFormatTable, want: "3.1.4"},
		{name: "json falls back to dev", version: "", format: cli.OutputFormatJSON, want: `"client_version": "dev"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app.Version = tc.version
			// No context: a daemon connection would fail.
			flags := func() *cli.CommonFlags { return &cli.CommonFlags{OutputFormat: tc.format, NoColor: true} }

			out, err := runCommand(t, NewVersionCommand(flags), "--client")

			require.NoError(t, err)
			assert.Contains(t, out, tc.want)
		})
	}
}

func TestPrintStatusTable_RendersPlatformSystemAndTPMInfo(t *testing.T) {
	var buf bytes.Buffer
	status := &daemonsvc.StatusInfo{
		Status: "running",
		Info: &daemonsvc.PlatformInfo{
			Hostname:   "node-1",
			PlatformID: "plat-42",
			FIPSMode:   true,
			SystemInfo: &daemonsvc.SystemInfo{OS: "linux", NumCPUs: 8, TotalMemoryMB: 4096, AvailableMemoryMB: 1024},
			TPMInfo:    &daemonsvc.TPMInfo{Manufacturer: "IFX", FirmwareVersion: "7.85"},
		},
	}

	_, err := captureStdout(t, func() error { return printStatusTable(healthPrinter(&buf), status) })

	require.NoError(t, err)
	out := buf.String()
	for _, want := range []string{"System Status: running", "node-1", "plat-42", "8", "4096 MB total, 1024 MB available", "IFX", "7.85"} {
		assert.Contains(t, out, want)
	}
}

func TestPrintVersionTable_ListsComponents(t *testing.T) {
	var buf bytes.Buffer
	version := &daemonsvc.VersionInfo{Version: "2.0.0", GoVersion: "go1.25", Components: map[string]string{"xkms": "1.4.0"}}

	_, err := captureStdout(t, func() error { return printVersionTable(healthPrinter(&buf), version) })

	require.NoError(t, err)
	out := buf.String()
	for _, want := range []string{"Server Version:", "2.0.0", "go1.25", "Component Versions:", "xkms", "1.4.0"} {
		assert.Contains(t, out, want)
	}
}

// factorService is an in-process auth service that records the factor
// calls the CLI makes.
type factorService struct {
	err      error
	list     *authsvc.ListResult
	enrolled *authsvc.EnrollmentResult

	listUser   string
	addReq     *authsvc.AddFactorRequest
	removedID  string
	removeAll  bool
	rotatedID  string
	relabelID  string
	relabelled string
	closed     bool
}

func (f *factorService) AddFactor(_ context.Context, req *authsvc.AddFactorRequest) (*authsvc.EnrollmentResult, error) {
	f.addReq = req
	return f.enrolled, f.err
}

func (f *factorService) ListFactors(_ context.Context, user string) (*authsvc.ListResult, error) {
	f.listUser = user
	return f.list, f.err
}

func (f *factorService) RemoveFactor(_ context.Context, factorID string, force bool) error {
	f.removedID, f.removeAll = factorID, force
	return f.err
}

func (f *factorService) RotateFactor(_ context.Context, oldID string, req *authsvc.AddFactorRequest) (*authsvc.EnrollmentResult, error) {
	f.rotatedID, f.addReq = oldID, req
	return f.enrolled, f.err
}

func (f *factorService) RelabelFactor(_ context.Context, factorID, label string) error {
	f.relabelID, f.relabelled = factorID, label
	return f.err
}

func (f *factorService) Login(context.Context, *authsvc.LoginRequest) (*authsvc.LoginResult, error) {
	return nil, f.err
}

func (f *factorService) Close() error {
	f.closed = true
	return nil
}

func useFactorService(t *testing.T, svc *factorService) {
	t.Helper()
	t.Cleanup(SetAuthClientFactory(func(context.Context, *cli.CommonFlags) (authsvc.Service, error) {
		return svc, nil
	}))
}

func noFlags() *cli.CommonFlags { return &cli.CommonFlags{} }

func testEnrollment() *authsvc.EnrollmentResult {
	return &authsvc.EnrollmentResult{
		EnrollmentID: "enr-1",
		FactorName:   "fido2",
		UserID:       "alice",
		TenantID:     "acme",
		EnrolledAt:   time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}

func TestAuthFactorList_PrintsEveryEnrollment(t *testing.T) {
	var list authsvc.ListResult
	require.NoError(t, json.Unmarshal([]byte(`{"enrollments":[
		{"enrollment_id":"enr-1","factor_name":"mtls","user_id":"alice","enrolled_at":"2026-10-01T00:00:00Z"},
		{"enrollment_id":"enr-2","factor_name":"piv","user_id":"alice","tenant_id":"acme",
		 "enrolled_at":"2026-10-02T00:00:00Z","revoked_at":"2026-10-03T00:00:00Z"}],"total":2}`), &list))
	svc := &factorService{list: &list}
	useFactorService(t, svc)

	out, err := runCommand(t, newAuthFactorCommand(noFlags), "list", "--user", "alice")

	require.NoError(t, err)
	assert.Equal(t, "alice", svc.listUser)
	assert.True(t, svc.closed)
	assert.Contains(t, out, "enr-1\tmtls\talice\t\t2026-10-01T00:00:00Z\t-")
	assert.Contains(t, out, "enr-2\tpiv\talice\tacme\t2026-10-02T00:00:00Z\t2026-10-03T00:00:00Z")
}

func TestAuthFactorList_SaysWhenNothingIsEnrolled(t *testing.T) {
	useFactorService(t, &factorService{})

	out, err := runCommand(t, newAuthFactorCommand(noFlags), "list")

	require.NoError(t, err)
	assert.Equal(t, "(no enrolled factors)\n", out)
}

func TestAuthFactorAdd_ForwardsTheFlagsAndPrintsTheEnrollment(t *testing.T) {
	svc := &factorService{enrolled: testEnrollment()}
	useFactorService(t, svc)

	out, err := runCommand(t, newAuthFactorCommand(noFlags), "add",
		"--type", "fido2", "--label", "yubikey", "--user", "alice", "--tenant", "acme", "--device", "dev-0")

	require.NoError(t, err)
	require.NotNil(t, svc.addReq)
	assert.Equal(t, authsvc.AddFactorRequest{
		Type: "fido2", Label: "yubikey", User: "alice", Tenant: "acme", FIDO2Device: "dev-0", PIVSlot: "9a",
	}, *svc.addReq)
	for _, want := range []string{"Enrollment ID: enr-1", "Tenant:        acme", "2026-10-30T12:00:00Z", "Label:         yubikey"} {
		assert.Contains(t, out, want)
	}
}

func TestAuthFactorRotate_RevokesTheOldIDAndPrintsTheNewOne(t *testing.T) {
	svc := &factorService{enrolled: testEnrollment()}
	useFactorService(t, svc)

	out, err := runCommand(t, newAuthFactorCommand(noFlags), "rotate", "enr-0", "--type", "fido2", "--label", "new")

	require.NoError(t, err)
	assert.Equal(t, "enr-0", svc.rotatedID)
	assert.Equal(t, "new", svc.addReq.Label)
	assert.Contains(t, out, "Old factor revoked: enr-0")
	assert.Contains(t, out, "New enrollment ID:  enr-1")
}

func TestAuthFactorRemoveAndRelabel_ForwardTheirArguments(t *testing.T) {
	svc := &factorService{}
	useFactorService(t, svc)

	out, err := runCommand(t, newAuthFactorCommand(noFlags), "remove", "enr-3", "--force")
	require.NoError(t, err)
	assert.Equal(t, "OK\n", out)
	assert.Equal(t, "enr-3", svc.removedID)
	assert.True(t, svc.removeAll)

	out, err = runCommand(t, newAuthFactorCommand(noFlags), "relabel", "enr-4", "--label", "backup key")
	require.NoError(t, err)
	assert.Equal(t, "OK\n", out)
	assert.Equal(t, "enr-4", svc.relabelID)
	assert.Equal(t, "backup key", svc.relabelled)
}

func TestAuthFactorCommands_RequireAFactorID(t *testing.T) {
	for _, verb := range []string{"remove", "rotate", "relabel"} {
		t.Run(verb, func(t *testing.T) {
			useFactorService(t, &factorService{})

			_, err := runCommand(t, newAuthFactorCommand(noFlags), verb)

			var missing *authsvc.ErrMissingFactorID
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, "auth factor "+verb, missing.Op)
		})
	}
}

func factorVerbs() map[string][]string {
	return map[string][]string{
		"list":    {"list"},
		"add":     {"add", "--type", "mtls", "--label", "l"},
		"remove":  {"remove", "enr-1"},
		"rotate":  {"rotate", "enr-1"},
		"relabel": {"relabel", "enr-1", "--label", "l"},
	}
}

func TestAuthFactorCommands_ReturnTheServiceFailure(t *testing.T) {
	for name, args := range factorVerbs() {
		t.Run(name, func(t *testing.T) {
			svc := &factorService{err: errDaemonRefused}
			useFactorService(t, svc)

			_, err := runCommand(t, newAuthFactorCommand(noFlags), args...)

			require.ErrorIs(t, err, errDaemonRefused)
			assert.True(t, svc.closed, "the client is closed on failure too")
		})
	}
}

func TestAuthFactorCommands_ReturnTheClientFactoryFailure(t *testing.T) {
	for name, args := range factorVerbs() {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(SetAuthClientFactory(func(context.Context, *cli.CommonFlags) (authsvc.Service, error) {
				return nil, errDaemonRefused
			}))

			_, err := runCommand(t, newAuthFactorCommand(noFlags), args...)

			require.ErrorIs(t, err, errDaemonRefused)
		})
	}
}

func TestResolveQuicBaaSAddress(t *testing.T) {
	withContext := func(c *cli.Context) *cli.CommonFlags {
		return &cli.CommonFlags{GetContext: func() (*cli.Context, error) { return c, nil }}
	}
	cases := []struct {
		name     string
		env      string
		flags    *cli.CommonFlags
		wantAddr string
		wantOpts int
		wantErr  string
	}{
		{name: "env socket", env: "/tmp/q.sock", wantAddr: "/tmp/q.sock", wantOpts: 1},
		{name: "env https selects REST", env: " https://q.example:8443 ", wantAddr: "https://q.example:8443", wantOpts: 1},
		{name: "env host:port defaults to gRPC", env: "q.example:9000", wantAddr: "q.example:9000", wantOpts: 0},
		{name: "no flags uses the local socket", wantAddr: "/run/quicbaas.sock", wantOpts: 1},
		{name: "local context", flags: withContext(&cli.Context{Type: cli.ContextTypeLocal}), wantAddr: "/run/quicbaas.sock", wantOpts: 1},
		{
			name:     "remote context",
			flags:    withContext(&cli.Context{Type: cli.ContextTypeRemote, Remote: &cli.RemoteContext{Server: "http://q:80"}}),
			wantAddr: "http://q:80", wantOpts: 1,
		},
		{name: "remote without a server", flags: withContext(&cli.Context{Name: "prod", Type: cli.ContextTypeRemote}), wantErr: `remote context "prod" has no server`},
		{name: "embedded context", flags: withContext(&cli.Context{Type: cli.ContextTypeEmbedded}), wantErr: "embedded context cannot dial quicbaas"},
		{name: "unknown context type", flags: withContext(&cli.Context{Type: "carrier-pigeon"}), wantErr: `unsupported context type "carrier-pigeon"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PLATFORMCTL_QUICBAAS_ADDR", tc.env)

			addr, opts, err := resolveQuicBaaSAddress(tc.flags)

			if tc.wantErr != "" {
				var msgErr *MessageError
				require.ErrorAs(t, err, &msgErr)
				assert.Contains(t, msgErr.Msg, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAddr, addr)
			assert.Len(t, opts, tc.wantOpts)
		})
	}
}

func TestResolveQuicBaaSAddress_ReturnsTheContextFailure(t *testing.T) {
	t.Setenv("PLATFORMCTL_QUICBAAS_ADDR", "")
	cause := errors.New("no config")
	flags := &cli.CommonFlags{GetContext: func() (*cli.Context, error) { return nil, cause }}

	_, _, err := resolveQuicBaaSAddress(flags)

	require.ErrorIs(t, err, cause)
}

func TestDefaultAuthClientFactory_RefusesAnEmbeddedContext(t *testing.T) {
	t.Setenv("PLATFORMCTL_QUICBAAS_ADDR", "")
	flags := &cli.CommonFlags{GetContext: func() (*cli.Context, error) {
		return &cli.Context{Type: cli.ContextTypeEmbedded}, nil
	}}

	svc, err := defaultAuthClientFactory(context.Background(), flags)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Nil(t, svc)
}

func TestTypedErrors_NameWhatFailed(t *testing.T) {
	cause := errors.New("disk full")
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{name: "wrapped", err: &WrappedError{Msg: "write bundle", Err: cause}, want: []string{"write bundle: disk full"}},
		{name: "pending credential backend", err: &PendingCredentialBackendError{Op: "credential list"}, want: []string{"credential list", "not yet wired"}},
		{name: "canonical redirect", err: &CanonicalRedirectError{Old: "bootstrap init", New: "init"}, want: []string{"'bootstrap init'", "Run: init"}},
		{name: "init step", err: &ErrInitStepFailed{Step: InitStepGateInit, Err: cause}, want: []string{"init: failed to " + InitStepGateInit, "disk full"}},
		{name: "missing pin", err: &ErrMissingPIN{Flag: "so-pin", EnvVar: "PLATFORMCTL_SO_PIN"}, want: []string{"--so-pin", "PLATFORMCTL_SO_PIN"}},
		{name: "loopback conflict", err: &ErrLoopbackHTTPConflict{Endpoint: "unix:///run/p.sock"}, want: []string{"--loopback-http", "unix:///run/p.sock"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				assert.True(t, strings.Contains(tc.err.Error(), want), "%q lacks %q", tc.err.Error(), want)
			}
		})
	}
	assert.ErrorIs(t, &WrappedError{Msg: "m", Err: cause}, cause)
	assert.ErrorIs(t, &ErrInitStepFailed{Step: InitStepGateInit, Err: cause}, cause)
}
