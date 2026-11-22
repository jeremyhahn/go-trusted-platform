package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bmcUsersCall records the one API request a BMC user test expects.
type bmcUsersCall struct {
	hits   int
	method string
	path   string
	body   map[string]interface{}
}

// bmcUsersServer answers every API request with status and reply and
// records it in call; the /health/live probe Connect sends is not counted.
func bmcUsersServer(t *testing.T, call *bmcUsersCall, code int, reply string) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		call.hits++
		call.method = r.Method
		call.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		call.body = nil
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &call.body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(reply))
	})
	return a
}

func TestBMCListUsers_PathAndBareArrayReply(t *testing.T) {
	var call bmcUsersCall
	a := bmcUsersServer(t, &call, http.StatusOK,
		`{"success":true,"payload":[{"slot":2,"username":"admin","enabled":true,"privilege":4,"channel":1}]}`)

	resp := &platformv1.BMCListUsersResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.BMCService_ListUsers_FullMethodName,
		&platformv1.BMCListUsersRequest{ProfileId: 42}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if call.method != http.MethodGet || call.path != "/api/v1/bmc/42/users" {
		t.Errorf("request = %s %s, want GET /api/v1/bmc/42/users", call.method, call.path)
	}
	users := resp.GetUsers()
	if len(users) != 1 {
		t.Fatalf("users = %v, want one", users)
	}
	u := users[0]
	if u.GetSlot() != 2 || u.GetUsername() != "admin" || !u.GetEnabled() ||
		u.GetPrivilege() != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR || u.GetChannel() != 1 {
		t.Errorf("user = %v, want slot 2 admin enabled administrator channel 1", u)
	}
}

func TestBMCCreateUser_FlatBodyAndCreatedSlot(t *testing.T) {
	var call bmcUsersCall
	a := bmcUsersServer(t, &call, http.StatusCreated,
		`{"success":true,"payload":{"slot":3,"username":"ops","enabled":true,"privilege":3,"channel":1}}`)

	resp := &platformv1.BMCCreateUserResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.BMCService_CreateUser_FullMethodName,
		&platformv1.BMCCreateUserRequest{
			ProfileId: 42,
			User: &platformv1.BMCUser{
				Slot: 3, Username: "ops", Enabled: true,
				Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR, Channel: 1,
			},
			Password: "x",
		}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if call.method != http.MethodPost || call.path != "/api/v1/bmc/42/users" {
		t.Errorf("request = %s %s, want POST /api/v1/bmc/42/users", call.method, call.path)
	}
	want := map[string]interface{}{
		"slot": float64(3), "username": "ops", "enabled": true,
		"privilege": "operator", "channel": float64(1), "password": "x",
	}
	if !reflect.DeepEqual(call.body, want) {
		t.Errorf("body = %v, want %v", call.body, want)
	}
	if resp.GetSlot() != 3 {
		t.Errorf("slot = %d, want 3", resp.GetSlot())
	}
}

func TestBMCCreateUser_UnspecifiedPrivilegeRejectedBeforeTheWire(t *testing.T) {
	var call bmcUsersCall
	a := bmcUsersServer(t, &call, http.StatusCreated, `{"success":true,"payload":{}}`)

	err := a.Connection().Invoke(context.Background(), platformv1.BMCService_CreateUser_FullMethodName,
		&platformv1.BMCCreateUserRequest{
			ProfileId: 42,
			User:      &platformv1.BMCUser{Slot: 3, Username: "ops", Channel: 1},
			Password:  "x",
		}, &platformv1.BMCCreateUserResponse{})
	assertBMCUsersInvalidArgument(t, err, call)
}

func TestBMCSetUserPrivilege_PathAndBody(t *testing.T) {
	var call bmcUsersCall
	a := bmcUsersServer(t, &call, http.StatusOK, `{"success":true,"payload":{}}`)

	err := a.Connection().Invoke(context.Background(), platformv1.BMCService_SetUserPrivilege_FullMethodName,
		&platformv1.BMCSetUserPrivilegeRequest{
			ProfileId: 42, Slot: 3, Channel: 1,
			Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER,
		}, &platformv1.BMCSetUserPrivilegeResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if call.method != http.MethodPut || call.path != "/api/v1/bmc/42/users/3/privilege" {
		t.Errorf("request = %s %s, want PUT /api/v1/bmc/42/users/3/privilege", call.method, call.path)
	}
	want := map[string]interface{}{"privilege": "user", "channel": float64(1)}
	if !reflect.DeepEqual(call.body, want) {
		t.Errorf("body = %v, want %v", call.body, want)
	}
}

func TestBMCSetUserPrivilege_ZeroSlotRejectedBeforeTheWire(t *testing.T) {
	var call bmcUsersCall
	a := bmcUsersServer(t, &call, http.StatusOK, `{"success":true,"payload":{}}`)

	err := a.Connection().Invoke(context.Background(), platformv1.BMCService_SetUserPrivilege_FullMethodName,
		&platformv1.BMCSetUserPrivilegeRequest{
			ProfileId: 42, Slot: 0, Channel: 1,
			Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER,
		}, &platformv1.BMCSetUserPrivilegeResponse{})
	assertBMCUsersInvalidArgument(t, err, call)
}

func TestBMCPrivilegeName_MatchesTheServerNames(t *testing.T) {
	want := map[platformv1.BMCUserPrivilege]string{
		platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK:      "callback",
		platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER:          "user",
		platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR:      "operator",
		platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR: "administrator",
		platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS:     "no-access",
	}
	for p, name := range want {
		got, err := bmcPrivilegeName(p)
		if err != nil || got != name {
			t.Errorf("bmcPrivilegeName(%v) = %q, %v; want %q", p, got, err, name)
		}
	}
	for _, p := range []platformv1.BMCUserPrivilege{
		platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED, platformv1.BMCUserPrivilege(7),
	} {
		if _, err := bmcPrivilegeName(p); err == nil {
			t.Errorf("bmcPrivilegeName(%v) = nil error, want refusal", p)
		}
	}
}

func assertBMCUsersInvalidArgument(t *testing.T, err error, call bmcUsersCall) {
	t.Helper()
	if err == nil {
		t.Fatal("Invoke succeeded, want InvalidArgument")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("err = %v, want InvalidArgument", err)
	}
	if call.hits != 0 {
		t.Errorf("server saw %d API requests, want 0", call.hits)
	}
}
