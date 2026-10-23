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

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// templateService records the template RPCs and answers from its fields.
type templateService struct {
	platformv1.DeviceServiceClient

	stored    *platformv1.DeviceTemplate
	updated   *platformv1.DeviceTemplate
	overrides *platformv1.DeviceProfile
	deletedID uint64
	err       error
}

func (s *templateService) CreateTemplate(_ context.Context, in *platformv1.DeviceTemplateCreateRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateCreateResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	created := in.GetTemplate()
	created.Id = 77
	return &platformv1.DeviceTemplateCreateResponse{Template: created}, nil
}

func (s *templateService) GetTemplate(_ context.Context, _ *platformv1.DeviceTemplateGetRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateGetResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.DeviceTemplateGetResponse{Template: s.stored}, nil
}

func (s *templateService) ListTemplates(_ context.Context, _ *platformv1.DeviceTemplateListRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateListResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.DeviceTemplateListResponse{
		Templates:  []*platformv1.DeviceTemplate{s.stored},
		Pagination: &platformv1.PaginationResponse{Page: 1, PageSize: 20, TotalItems: 1, TotalPages: 1},
	}, nil
}

func (s *templateService) UpdateTemplate(_ context.Context, in *platformv1.DeviceTemplateUpdateRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateUpdateResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.updated = in.GetTemplate()
	return &platformv1.DeviceTemplateUpdateResponse{Template: s.updated}, nil
}

func (s *templateService) DeleteTemplate(_ context.Context, in *platformv1.DeviceTemplateDeleteRequest, _ ...grpc.CallOption) (*platformv1.DeviceTemplateDeleteResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.deletedID = in.GetId()
	return &platformv1.DeviceTemplateDeleteResponse{}, nil
}

func (s *templateService) CreateProfileFromTemplate(_ context.Context, in *platformv1.CreateProfileFromTemplateRequest, _ ...grpc.CallOption) (*platformv1.CreateProfileResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.overrides = in.GetOverrides()
	return &platformv1.CreateProfileResponse{Profile: &platformv1.DeviceProfile{
		Id:       88,
		Name:     in.GetOverrides().GetName(),
		Role:     s.stored.GetRole(),
		EkSerial: in.GetOverrides().GetEkSerial(),
	}}, nil
}

func jsonPrinter() (*cli.Printer, *bytes.Buffer) {
	var out bytes.Buffer
	return cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out), &out
}

func decodePrinted(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	var printed map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &printed), out.String())
	return printed
}

func TestNewTemplateCommand_Subcommands(t *testing.T) {
	cmd := newTemplateCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"create", "get", "list", "update", "delete", "create-profile"} {
		assert.True(t, names[want], "template %s must exist", want)
	}
}

func TestParseTemplateID(t *testing.T) {
	id, err := parseTemplateID("42")
	require.NoError(t, err)
	assert.EqualValues(t, 42, id)

	_, err = parseTemplateID("x42")
	assert.Equal(t, ErrInvalidTemplateID{ID: "x42"}, err)
}

func TestBuildTemplate(t *testing.T) {
	template, err := buildTemplate(&templateFlags{
		name: "rack", description: "R650", role: "server",
		match: matchRuleFlags{serialPrefix: "SN-"},
	})
	require.NoError(t, err)
	assert.Equal(t, "rack", template.GetName())
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_SERVER, template.GetRole())
	assert.Equal(t, "SN-", template.GetMatchRules().GetSerialPrefix())
}

func TestBuildTemplate_RejectsBadFlags(t *testing.T) {
	_, err := buildTemplate(&templateFlags{})
	assert.Equal(t, ErrTemplateNameRequired{}, err)

	_, err = buildTemplate(&templateFlags{name: "rack", role: "mainframe"})
	assert.Error(t, err)
}

func TestCreateTemplateAndPrint(t *testing.T) {
	stub := &templateService{}
	printer, out := jsonPrinter()
	err := createTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON,
		&platformv1.DeviceTemplate{Name: "rack", Role: platformv1.DeviceRole_DEVICE_ROLE_SERVER})
	require.NoError(t, err)

	printed := decodePrinted(t, out)
	assert.Equal(t, "77", printed["id"])
	assert.Equal(t, "rack", printed["name"])
	assert.Equal(t, "server", printed["role"])
}

func TestCreateTemplateAndPrint_ServerRejects(t *testing.T) {
	stub := &templateService{err: status.Error(codes.InvalidArgument, "bad")}
	printer, _ := jsonPrinter()
	err := createTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON,
		&platformv1.DeviceTemplate{Name: "rack"})
	var failed ErrTemplateOperationFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "create", failed.Operation)
}

func TestGetTemplateAndPrint(t *testing.T) {
	stub := &templateService{stored: &platformv1.DeviceTemplate{Id: 5, Name: "edge", Description: "kiosks"}}
	printer, out := jsonPrinter()
	require.NoError(t, getTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 5))

	printed := decodePrinted(t, out)
	assert.Equal(t, "5", printed["id"])
	assert.Equal(t, "kiosks", printed["description"])
}

func TestGetTemplateAndPrint_NotFound(t *testing.T) {
	stub := &templateService{err: status.Error(codes.NotFound, "no template")}
	printer, _ := jsonPrinter()
	err := getTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 5)
	assert.Equal(t, ErrTemplateNotFound{ID: 5}, err)
	assert.True(t, errors.Is(err, common.ErrNotFound))

	err = getTemplateAndPrint(context.Background(), device.NewClientFromGRPC(&templateService{}), printer, cli.OutputFormatJSON, 6)
	assert.Equal(t, ErrTemplateNotFound{ID: 6}, err, "an empty reply is not a template")
}

func TestListTemplatesAndPrint(t *testing.T) {
	stub := &templateService{stored: &platformv1.DeviceTemplate{Id: 5, Name: "edge"}}
	printer, out := jsonPrinter()
	require.NoError(t, listTemplatesAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 1, 20))

	printed := decodePrinted(t, out)
	assert.EqualValues(t, 1, printed["total"])
	assert.EqualValues(t, 1, printed["total_pages"])
	require.Len(t, printed["templates"], 1)
}

func TestListTemplatesAndPrint_ServerFails(t *testing.T) {
	stub := &templateService{err: status.Error(codes.Unavailable, "down")}
	printer, _ := jsonPrinter()
	err := listTemplatesAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 1, 20)
	var failed ErrTemplateOperationFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "list", failed.Operation)
}

func TestUpdateTemplateAndPrint_KeepsUnnamedFields(t *testing.T) {
	stub := &templateService{stored: &platformv1.DeviceTemplate{
		Id: 5, Name: "edge", Description: "old", Role: platformv1.DeviceRole_DEVICE_ROLE_SERVER,
		Config: []byte(`{"a":1}`), MatchRules: &platformv1.ProfileMatchRules{SerialPrefix: "SN-"},
	}}
	printer, out := jsonPrinter()
	tf := &templateFlags{description: "new", role: "edge", match: matchRuleFlags{macPrefix: "52:54:00"}}
	require.NoError(t, updateTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 5, tf, nil))

	require.NotNil(t, stub.updated)
	assert.Equal(t, "edge", stub.updated.GetName())
	assert.Equal(t, "new", stub.updated.GetDescription())
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_EDGE, stub.updated.GetRole())
	assert.Equal(t, []byte(`{"a":1}`), stub.updated.GetConfig())
	assert.Equal(t, "SN-", stub.updated.GetMatchRules().GetSerialPrefix())
	assert.Equal(t, "52:54:00", stub.updated.GetMatchRules().GetMacPrefix())
	assert.Equal(t, "edge", decodePrinted(t, out)["role"])
}

func TestUpdateTemplateAndPrint_NotFound(t *testing.T) {
	stub := &templateService{err: status.Error(codes.NotFound, "no template")}
	printer, _ := jsonPrinter()
	err := updateTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 5, &templateFlags{description: "x"}, nil)
	assert.Equal(t, ErrTemplateNotFound{ID: 5}, err)
	assert.Nil(t, stub.updated, "a missing template is never stored")
}

func TestApplyTemplateUpdateFlags_BadRole(t *testing.T) {
	template := &platformv1.DeviceTemplate{Role: platformv1.DeviceRole_DEVICE_ROLE_SERVER}
	err := applyTemplateUpdateFlags(template, &templateFlags{role: "mainframe"}, nil)
	assert.Error(t, err)
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_SERVER, template.GetRole())
}

func TestDeleteTemplateAndPrint(t *testing.T) {
	stub := &templateService{}
	printer, out := jsonPrinter()
	require.NoError(t, deleteTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 9))

	assert.EqualValues(t, 9, stub.deletedID)
	printed := decodePrinted(t, out)
	assert.Equal(t, "9", printed["id"])
	assert.Equal(t, true, printed["deleted"])
}

func TestDeleteTemplateAndPrint_NotFound(t *testing.T) {
	stub := &templateService{err: status.Error(codes.NotFound, "no template")}
	printer, _ := jsonPrinter()
	err := deleteTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 9)
	assert.Equal(t, ErrTemplateNotFound{ID: 9}, err)
}

func TestCreateProfileFromTemplateAndPrint(t *testing.T) {
	stub := &templateService{stored: &platformv1.DeviceTemplate{Role: platformv1.DeviceRole_DEVICE_ROLE_SERVER}}
	overrides, err := buildProfileOverrides(&profileFlags{name: "r650-01", ekSerial: "0A1B"})
	require.NoError(t, err)
	printer, out := jsonPrinter()
	require.NoError(t, createProfileFromTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 5, overrides))

	assert.Equal(t, "r650-01", stub.overrides.GetName())
	assert.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED, stub.overrides.GetRole(), "an unset role keeps the template's")
	assert.Nil(t, stub.overrides.GetMatchRules(), "unset match flags keep the template's rules")
	printed := decodePrinted(t, out)
	assert.Equal(t, "r650-01", printed["name"])
	assert.Equal(t, "0A1B", printed["ek_serial"])
}

func TestBuildProfileOverrides_BadRole(t *testing.T) {
	_, err := buildProfileOverrides(&profileFlags{role: "mainframe"})
	assert.Error(t, err)
}

func TestCreateProfileFromTemplateAndPrint_NotFound(t *testing.T) {
	stub := &templateService{err: status.Error(codes.NotFound, "no template")}
	printer, _ := jsonPrinter()
	err := createProfileFromTemplateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 5, &platformv1.DeviceProfile{})
	assert.Equal(t, ErrTemplateNotFound{ID: 5}, err)
}
