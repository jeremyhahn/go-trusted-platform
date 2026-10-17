package mcp

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// errIAMUpdateRefused is the service error the update tools must pass through.
type errIAMUpdateRefused struct{}

func (errIAMUpdateRefused) Error() string { return "update refused" }

// TestIAMUpdateTools checks that iam_update_user, iam_update_role and
// iam_update_group hand every argument to the service, return its answer,
// and pass its error through (docs/iam/api.md §3-§5). Their iam:write scope
// is checked by TestIAMToolClassification.
func TestIAMUpdateTools(t *testing.T) {
	ctx := context.Background()
	answer := map[string]interface{}{"name": "updated"}

	tests := map[string]struct {
		args  map[string]interface{}
		want  interface{}
		mount func(svc *mockServiceProvider, got *interface{}, err error)
	}{
		"iam_update_user": {
			args: map[string]interface{}{
				"tenant_id": "tenant-1", "user_id": "user-1", "email": "a@acme.test",
				"name": "Alice", "roles": []interface{}{"viewer"}, "groups": []interface{}{"ops"},
				"attributes": map[string]interface{}{"dept": "eng"},
			},
			want: &IAMUpdateUserRequest{
				TenantID: "tenant-1", UserID: "user-1", Email: "a@acme.test",
				Name: "Alice", Roles: []string{"viewer"}, Groups: []string{"ops"},
				Attributes: map[string]string{"dept": "eng"},
			},
			mount: func(svc *mockServiceProvider, got *interface{}, err error) {
				svc.iamUpdateUserFunc = func(_ context.Context, req *IAMUpdateUserRequest) (interface{}, error) {
					*got = req
					return answer, err
				}
			},
		},
		"iam_update_role": {
			args: map[string]interface{}{
				"tenant_id": "tenant-1", "role_id": "role-1", "name": "Reader",
				"description": "reads users", "permissions": []interface{}{"users:read"},
			},
			want: &IAMUpdateRoleRequest{
				TenantID: "tenant-1", RoleID: "role-1", Name: "Reader",
				Description: "reads users", Permissions: []string{"users:read"},
			},
			mount: func(svc *mockServiceProvider, got *interface{}, err error) {
				svc.iamUpdateRoleFunc = func(_ context.Context, req *IAMUpdateRoleRequest) (interface{}, error) {
					*got = req
					return answer, err
				}
			},
		},
		"iam_update_group": {
			args: map[string]interface{}{
				"tenant_id": "tenant-1", "group_id": "group-1", "name": "Ops", "description": "operators",
			},
			want: &IAMUpdateGroupRequest{
				TenantID: "tenant-1", GroupID: "group-1", Name: "Ops", Description: "operators",
			},
			mount: func(svc *mockServiceProvider, got *interface{}, err error) {
				svc.iamUpdateGroupFunc = func(_ context.Context, req *IAMUpdateGroupRequest) (interface{}, error) {
					*got = req
					return answer, err
				}
			},
		},
	}

	for tool, tc := range tests {
		t.Run(tool+" forwards the request", func(t *testing.T) {
			svc := newMockServiceProvider()
			var got interface{}
			tc.mount(svc, &got, nil)

			result, err := NewToolRegistry(svc, newTestLogger()).ExecuteTool(ctx, tool, tc.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("request = %+v, want %+v", got, tc.want)
			}
			if !reflect.DeepEqual(result, answer) {
				t.Errorf("result = %v, want %v", result, answer)
			}
		})

		t.Run(tool+" passes the service error through", func(t *testing.T) {
			svc := newMockServiceProvider()
			var got interface{}
			tc.mount(svc, &got, errIAMUpdateRefused{})

			_, err := NewToolRegistry(svc, newTestLogger()).ExecuteTool(ctx, tool, tc.args)
			if !errors.As(err, new(errIAMUpdateRefused)) {
				t.Fatalf("error = %v, want errIAMUpdateRefused", err)
			}
		})
	}
}
