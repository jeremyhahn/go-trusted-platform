package rest

import (
	"encoding/json"
	"fmt"
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bmcPrivilegeNames spells each BMC user privilege the way the daemon's
// user handlers parse it (privilegeByName in pkg/webservice/v1/bmc).
var bmcPrivilegeNames = map[platformv1.BMCUserPrivilege]string{
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK:      "callback",
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER:          "user",
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR:      "operator",
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR: "administrator",
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS:     "no-access",
}

// bmcPrivilegeName returns the server's name for p; UNSPECIFIED and values
// outside the enum are refused.
func bmcPrivilegeName(p platformv1.BMCUserPrivilege) (string, error) {
	name, ok := bmcPrivilegeNames[p]
	if !ok {
		return "", fmt.Errorf("bmc user privilege %v has no REST name", p)
	}
	return name, nil
}

// bmcWireUser is the daemon's bmc.User record: the privilege travels as
// its numeric value, which matches the proto enum.
type bmcWireUser struct {
	Slot      uint32 `json:"slot"`
	Username  string `json:"username"`
	Enabled   bool   `json:"enabled"`
	Privilege int32  `json:"privilege"`
	Channel   uint32 `json:"channel"`
}

func (u bmcWireUser) proto() *platformv1.BMCUser {
	return &platformv1.BMCUser{
		Slot:      u.Slot,
		Username:  u.Username,
		Enabled:   u.Enabled,
		Privilege: platformv1.BMCUserPrivilege(u.Privilege),
		Channel:   u.Channel,
	}
}

// decodeBMCListUsers wraps the bare user array the daemon answers into
// BMCListUsersResponse.
func decodeBMCListUsers(raw []byte) (*platformv1.BMCListUsersResponse, error) {
	var users []bmcWireUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, err
	}
	out := &platformv1.BMCListUsersResponse{Users: make([]*platformv1.BMCUser, 0, len(users))}
	for _, u := range users {
		out.Users = append(out.Users, u.proto())
	}
	return out, nil
}

// decodeBMCCreateUser reads the slot from the created user the daemon
// answers.
func decodeBMCCreateUser(raw []byte) (*platformv1.BMCCreateUserResponse, error) {
	var u bmcWireUser
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, err
	}
	return &platformv1.BMCCreateUserResponse{Slot: u.Slot}, nil
}

func init() {
	templatedRouteTable[platformv1.BMCService_ListUsers_FullMethodName] =
		bmcRoute("/api/v1/bmc/{profileID}/users", http.MethodGet)
	templatedRouteTable[platformv1.BMCService_CreateUser_FullMethodName] =
		bmcRoute("/api/v1/bmc/{profileID}/users", http.MethodPost)
	templatedRouteTable[platformv1.BMCService_SetUserPrivilege_FullMethodName] = templatedRoute{
		path:   "/api/v1/bmc/{profileID}/users/{slot}/privilege",
		method: http.MethodPut,
		pathParams: []pathParam{
			{placeholder: "{profileID}", field: "profile_id"},
			{placeholder: "{slot}", field: "slot"},
		},
	}

	restRequestEncoders[platformv1.BMCService_CreateUser_FullMethodName] = requestEncoder(
		platformv1.BMCService_CreateUser_FullMethodName,
		func(r *platformv1.BMCCreateUserRequest) (map[string]interface{}, error) {
			u := r.GetUser()
			privilege, err := bmcPrivilegeName(u.GetPrivilege())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"slot":      u.GetSlot(),
				"username":  u.GetUsername(),
				"enabled":   u.GetEnabled(),
				"privilege": privilege,
				"channel":   u.GetChannel(),
				"password":  r.GetPassword(),
			}, nil
		})
	restRequestEncoders[platformv1.BMCService_SetUserPrivilege_FullMethodName] = requestEncoder(
		platformv1.BMCService_SetUserPrivilege_FullMethodName,
		func(r *platformv1.BMCSetUserPrivilegeRequest) (map[string]interface{}, error) {
			privilege, err := bmcPrivilegeName(r.GetPrivilege())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"privilege": privilege, "channel": r.GetChannel()}, nil
		})

	restResponseDecoders[platformv1.BMCService_ListUsers_FullMethodName] =
		wireDecoder(platformv1.BMCService_ListUsers_FullMethodName, decodeBMCListUsers)
	restResponseDecoders[platformv1.BMCService_CreateUser_FullMethodName] =
		wireDecoder(platformv1.BMCService_CreateUser_FullMethodName, decodeBMCCreateUser)
}
