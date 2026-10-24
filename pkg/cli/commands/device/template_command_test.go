package device

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeTemplateServer stores device templates in memory and serves the
// template RPCs of the DeviceService, so the template commands run end to
// end over a real gRPC connection on a Unix socket.
type fakeTemplateServer struct {
	platformv1.UnimplementedDeviceServiceServer

	mu        sync.Mutex
	templates map[uint64]*platformv1.DeviceTemplate
	nextID    uint64
	overrides *platformv1.DeviceProfile
	fail      error
}

func (s *fakeTemplateServer) failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.fail
	s.fail = nil
	return err
}

func (s *fakeTemplateServer) CreateTemplate(_ context.Context, in *platformv1.DeviceTemplateCreateRequest) (*platformv1.DeviceTemplateCreateResponse, error) {
	if err := s.failure(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	created := in.GetTemplate()
	created.Id = s.nextID
	s.templates[created.GetId()] = created
	return &platformv1.DeviceTemplateCreateResponse{Template: created}, nil
}

func (s *fakeTemplateServer) GetTemplate(_ context.Context, in *platformv1.DeviceTemplateGetRequest) (*platformv1.DeviceTemplateGetResponse, error) {
	if err := s.failure(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	template, ok := s.templates[in.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	return &platformv1.DeviceTemplateGetResponse{Template: template}, nil
}

func (s *fakeTemplateServer) ListTemplates(_ context.Context, _ *platformv1.DeviceTemplateListRequest) (*platformv1.DeviceTemplateListResponse, error) {
	if err := s.failure(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	templates := make([]*platformv1.DeviceTemplate, 0, len(s.templates))
	for _, template := range s.templates {
		templates = append(templates, template)
	}
	total := uint64(len(templates))
	return &platformv1.DeviceTemplateListResponse{
		Templates:  templates,
		Pagination: &platformv1.PaginationResponse{Page: 1, PageSize: 20, TotalItems: total, TotalPages: 1},
	}, nil
}

func (s *fakeTemplateServer) UpdateTemplate(_ context.Context, in *platformv1.DeviceTemplateUpdateRequest) (*platformv1.DeviceTemplateUpdateResponse, error) {
	if err := s.failure(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates[in.GetTemplate().GetId()] = in.GetTemplate()
	return &platformv1.DeviceTemplateUpdateResponse{Template: in.GetTemplate()}, nil
}

func (s *fakeTemplateServer) DeleteTemplate(_ context.Context, in *platformv1.DeviceTemplateDeleteRequest) (*platformv1.DeviceTemplateDeleteResponse, error) {
	if err := s.failure(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[in.GetId()]; !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	delete(s.templates, in.GetId())
	return &platformv1.DeviceTemplateDeleteResponse{}, nil
}

func (s *fakeTemplateServer) CreateProfileFromTemplate(_ context.Context, in *platformv1.CreateProfileFromTemplateRequest) (*platformv1.CreateProfileResponse, error) {
	if err := s.failure(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	template, ok := s.templates[in.GetTemplateId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "template not found")
	}
	s.overrides = in.GetOverrides()
	return &platformv1.CreateProfileResponse{Profile: &platformv1.DeviceProfile{
		Id:       500,
		Name:     in.GetOverrides().GetName(),
		Role:     template.GetRole(),
		EkSerial: in.GetOverrides().GetEkSerial(),
	}}, nil
}

func startTemplateServer(t *testing.T) (*deviceHarness, *fakeTemplateServer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &fakeTemplateServer{
		templates: map[uint64]*platformv1.DeviceTemplate{
			5: {Id: 5, Name: "edge", Description: "kiosks", Role: platformv1.DeviceRole_DEVICE_ROLE_EDGE,
				Config: []byte(`{"a":1}`), MatchRules: &platformv1.ProfileMatchRules{SerialPrefix: "SN-"}},
		},
		nextID: 10,
	}
	gs := grpc.NewServer()
	platformv1.RegisterDeviceServiceServer(gs, srv)
	go func() {
		if serveErr := gs.Serve(lis); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", serveErr)
		}
	}()
	t.Cleanup(gs.Stop)
	return &deviceHarness{sock: sock}, srv
}

func TestDeviceTemplateCreateCommand(t *testing.T) {
	h, srv := startTemplateServer(t)

	got := h.runJSON(t, "template", "create", "--name", "rack", "--role", "server", "--match-mac-prefix", "52:54:00")
	assert.Equal(t, "11", got["id"], "the id is the one the control plane assigned")
	assert.Equal(t, "rack", got["name"])
	assert.Equal(t, "server", got["role"])
	srv.mu.Lock()
	assert.Equal(t, "52:54:00", srv.templates[11].GetMatchRules().GetMacPrefix(), "the match rule reaches the control plane")
	srv.mu.Unlock()

	table, err := h.run(t, cli.OutputFormatTable, "template", "create", "--name", "kiosk", "--description", "lobby kiosks")
	require.NoError(t, err)
	assert.Contains(t, table, "Template ID: 12")
	assert.Contains(t, table, "Name: kiosk")
	assert.Contains(t, table, "Description: lobby kiosks")
	assert.NotContains(t, table, "Role:", "an unset role is not shown")

	_, err = h.run(t, cli.OutputFormatJSON, "template", "create", "--role", "server")
	assert.Equal(t, ErrTemplateNameRequired{}, err, "refused before connecting")

	srv.fail = status.Error(codes.InvalidArgument, "name taken")
	_, err = h.run(t, cli.OutputFormatJSON, "template", "create", "--name", "rack")
	var failed ErrTemplateOperationFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "create", failed.Operation)
	assert.Contains(t, err.Error(), "name taken", "the server's reason is shown")
}

func TestDeviceTemplateGetCommand(t *testing.T) {
	h, _ := startTemplateServer(t)

	got := h.runJSON(t, "template", "get", "5")
	assert.Equal(t, "5", got["id"])
	assert.Equal(t, "kiosks", got["description"])

	table, err := h.run(t, cli.OutputFormatTable, "template", "get", "5")
	require.NoError(t, err)
	assert.Contains(t, table, "Template ID: 5")
	assert.Contains(t, table, "Role: edge")
	assert.Contains(t, table, "Config: 7 bytes")
	assert.Contains(t, table, "SN-", "the match rules are summarised")

	_, err = h.run(t, cli.OutputFormatJSON, "template", "get", "6")
	assert.Equal(t, ErrTemplateNotFound{ID: 6}, err)

	_, err = h.run(t, cli.OutputFormatJSON, "template", "get", "x6")
	assert.Equal(t, ErrInvalidTemplateID{ID: "x6"}, err)
}

func TestDeviceTemplateListCommand(t *testing.T) {
	h, srv := startTemplateServer(t)

	got := h.runJSON(t, "template", "list")
	assert.EqualValues(t, 1, got["total"])
	require.Len(t, got["templates"], 1)

	table, err := h.run(t, cli.OutputFormatTable, "template", "list")
	require.NoError(t, err)
	assert.Contains(t, table, "edge")
	assert.Contains(t, table, "kiosks")
	assert.Contains(t, table, "Page 1 of 1 (Total: 1 templates)")

	srv.mu.Lock()
	srv.templates = map[uint64]*platformv1.DeviceTemplate{}
	srv.mu.Unlock()
	table, err = h.run(t, cli.OutputFormatTable, "template", "list")
	require.NoError(t, err)
	assert.Contains(t, table, "No templates found")

	srv.fail = status.Error(codes.Unavailable, "backend down")
	_, err = h.run(t, cli.OutputFormatJSON, "template", "list")
	var failed ErrTemplateOperationFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "list", failed.Operation)
}

func TestDeviceTemplateUpdateCommand(t *testing.T) {
	h, srv := startTemplateServer(t)

	got := h.runJSON(t, "template", "update", "5", "--description", "lobby")
	assert.Equal(t, "edge", got["name"], "an unsupplied flag keeps the stored value")
	assert.Equal(t, "lobby", got["description"])
	srv.mu.Lock()
	assert.Equal(t, []byte(`{"a":1}`), srv.templates[5].GetConfig(), "the stored config is kept")
	srv.mu.Unlock()

	_, err := h.run(t, cli.OutputFormatJSON, "template", "update", "5", "--role", "mainframe")
	assert.Equal(t, ErrProfileInvalidRole{Role: "mainframe"}, err, "refused before connecting")

	_, err = h.run(t, cli.OutputFormatJSON, "template", "update", "5", "--config-file", filepath.Join(t.TempDir(), "missing.yaml"))
	var readErr ErrProfileConfigReadFailed
	assert.ErrorAs(t, err, &readErr, "an unreadable config file is refused before connecting")

	_, err = h.run(t, cli.OutputFormatJSON, "template", "update", "x5")
	assert.Equal(t, ErrInvalidTemplateID{ID: "x5"}, err)

	_, err = h.run(t, cli.OutputFormatJSON, "template", "update", "6", "--description", "lobby")
	assert.Equal(t, ErrTemplateNotFound{ID: 6}, err)
}

func TestDeviceTemplateDeleteCommand(t *testing.T) {
	h, srv := startTemplateServer(t)

	got := h.runJSON(t, "template", "delete", "5")
	assert.Equal(t, "5", got["id"])
	assert.Equal(t, true, got["deleted"])
	srv.mu.Lock()
	assert.Empty(t, srv.templates, "delete removes the template on the control plane")
	srv.mu.Unlock()

	_, err := h.run(t, cli.OutputFormatJSON, "template", "delete", "5")
	assert.Equal(t, ErrTemplateNotFound{ID: 5}, err)

	_, err = h.run(t, cli.OutputFormatJSON, "template", "delete", "x5")
	assert.Equal(t, ErrInvalidTemplateID{ID: "x5"}, err)
}

func TestDeviceTemplateCreateProfileCommand(t *testing.T) {
	h, srv := startTemplateServer(t)

	got := h.runJSON(t, "template", "create-profile", "5", "--name", "kiosk-07", "--mac", "52:54:00:12:34:56")
	assert.Equal(t, "kiosk-07", got["name"])
	assert.Equal(t, "edge", got["role"], "the profile keeps the template's role")
	srv.mu.Lock()
	assert.Equal(t, "52:54:00:12:34:56", srv.overrides.GetMacAddress(), "--mac reaches the control plane")
	srv.mu.Unlock()

	_, err := h.run(t, cli.OutputFormatJSON, "template", "create-profile", "5", "--role", "mainframe")
	assert.Equal(t, ErrProfileInvalidRole{Role: "mainframe"}, err, "refused before connecting")

	_, err = h.run(t, cli.OutputFormatJSON, "template", "create-profile", "x5")
	assert.Equal(t, ErrInvalidTemplateID{ID: "x5"}, err)

	_, err = h.run(t, cli.OutputFormatJSON, "template", "create-profile", "6", "--name", "kiosk-08")
	assert.Equal(t, ErrTemplateNotFound{ID: 6}, err)
}

func TestDeviceErrors_Messages(t *testing.T) {
	cause := errors.New("root cause")
	tests := []struct {
		err     error
		message string
	}{
		{ErrAttestEvidenceRequired{}, "device attest: --evidence-file is required"},
		{ErrAttestEvidenceReadFailed{Path: "/e.bin", Cause: cause}, "device attest: failed to read evidence file /e.bin: root cause"},
		{ErrAttestEvidenceEmpty{Path: "/e.bin"}, "device attest: evidence file /e.bin is empty"},
		{ErrProfileConfigIdentityRequired{}, "device profile: at least one of --ek-serial or --mac is required"},
		{ErrNoConfigForDevice{EKSerial: "0A", MACAddress: "m"}, `device profile: no profile for ek serial "0A", mac "m"`},
		{ErrDeviceUpdateNoChanges{ID: 4}, "device update: nothing to change on device 4: give at least one of --model, --ek-cert, --attest-pub, --attest-cert, --signing-pub, --hash-algo"},
		{ErrDeviceUpdateFailed{ID: 4, Cause: cause}, "device update: failed to update device 4: root cause"},
		{ErrInvalidTemplateID{ID: "x"}, `device template: invalid template ID "x": must be a decimal number`},
		{ErrTemplateNameRequired{}, "device template: --name is required"},
		{ErrTemplateNotFound{ID: 4}, "device template: template 4 not found"},
		{ErrTemplateOperationFailed{Operation: "list", Cause: cause}, "device template: list failed: root cause"},
		{ErrTemplateOperationFailed{Operation: "update", ID: 4, Cause: cause}, "device template: update of template 4 failed: root cause"},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			assert.Equal(t, tt.message, tt.err.Error())
		})
	}

	assert.ErrorIs(t, ErrAttestEvidenceReadFailed{Cause: cause}, cause)
	assert.ErrorIs(t, ErrDeviceUpdateFailed{Cause: cause}, cause)
	assert.ErrorIs(t, ErrTemplateOperationFailed{Cause: cause}, cause)
}
