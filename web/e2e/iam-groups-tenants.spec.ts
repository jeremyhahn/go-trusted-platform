import { test } from "@playwright/test";

// Slice 16 of #1665 (#1744): IAM groups, group members, permission check and tenants.
test.describe("IAM groups, members, permission check and tenants", () => {
  test.fixme("CreateGroup: POST /groups from the new group page", async () => {});
  test.fixme("GetGroup: GET /groups/{id} on the group detail page", async () => {});
  test.fixme("UpdateGroup: PUT /groups/{id} from the group detail page", async () => {});
  test.fixme("AddGroupMember: POST /groups/{id}/members/{user}", async () => {});
  test.fixme("RemoveGroupMember: DELETE /groups/{id}/members/{user} behind a confirm", async () => {});
  test.fixme("CheckPermission: POST /permissions/check", async () => {});
  test.fixme("ListTenants: GET /tenants", async () => {});
  test.fixme("CreateTenant: POST /tenants", async () => {});
  test.fixme("GetTenant: GET /tenants/{tenant}", async () => {});
  test.fixme("UpdateTenant: PUT /tenants/{tenant}", async () => {});
  test.fixme("DeleteTenant: DELETE /tenants/{tenant} behind a confirm", async () => {});
});
