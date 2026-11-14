/**
 * Unit tests for IAMService (#1771).
 *
 * Each public method is driven against a mocked ApiClient: the wire test
 * asserts the HTTP verb, the path, the query string and the body; the
 * error test asserts that a failed transport response reaches the caller
 * unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMService } from './iam-service.js';
import type { ApiClient } from '../client/api-client.js';
import type { ApiResponse } from '../types/api.js';

type Verb = 'get' | 'post' | 'put' | 'delete';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'mock',
  } as unknown as ApiClient;
}

interface WireCase {
  /** Public method under test */
  method: string;
  /** Test name */
  name: string;
  /** Calls the method */
  call: (service: IAMService) => Promise<ApiResponse<unknown>>;
  /** Expected HTTP verb */
  verb: Verb;
  /** Expected path with query string */
  url: string;
  /** Expected body; omitted for verbs that send none */
  body?: unknown;
}

const failure = {
  success: false,
  error: { code: 'NOT_FOUND', message: 'not found' },
} as unknown as ApiResponse<unknown>;

const cases: WireCase[] = [
  // Users
  {
    method: 'createUser',
    name: 'posts the request to the tenant users path',
    call: (s) => s.createUser({ tenantId: 'acme', email: 'ada+1', name: 'Ada', roles: ['admin'] }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/users',
    body: { tenantId: 'acme', email: 'ada+1', name: 'Ada', roles: ['admin'] },
  },
  {
    method: 'getUser',
    name: 'gets the user and encodes both path segments',
    call: (s) => s.getUser('acme corp', 'user/1'),
    verb: 'get',
    url: '/v1/iam/tenants/acme%20corp/users/user%2F1',
  },
  {
    method: 'listUsers',
    name: 'maps page, pageSize and the filters to the query',
    call: (s) =>
      s.listUsers({
        tenantId: 'acme',
        page: 2,
        pageSize: 25,
        emailFilter: 'ada+1',
        roleFilter: 'admin',
        groupFilter: 'ops',
      }),
    verb: 'get',
    url: '/v1/iam/tenants/acme/users?page=2&limit=25&email=ada%2B1&role=admin&group=ops',
  },
  {
    method: 'listUsers',
    name: 'sends no query when no option is set',
    call: (s) => s.listUsers({ tenantId: 'acme' }),
    verb: 'get',
    url: '/v1/iam/tenants/acme/users',
  },
  {
    method: 'updateUser',
    name: 'puts the request to the user path',
    call: (s) => s.updateUser({ tenantId: 'acme', userId: 'u1', name: 'Ada L' }),
    verb: 'put',
    url: '/v1/iam/tenants/acme/users/u1',
    body: { tenantId: 'acme', userId: 'u1', name: 'Ada L' },
  },
  {
    method: 'deleteUser',
    name: 'deletes the user path',
    call: (s) => s.deleteUser('acme', 'u1'),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/users/u1',
  },
  // Roles
  {
    method: 'createRole',
    name: 'posts the request to the tenant roles path',
    call: (s) => s.createRole({ tenantId: 'acme', name: 'reader', permissions: ['read'] }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/roles',
    body: { tenantId: 'acme', name: 'reader', permissions: ['read'] },
  },
  {
    method: 'getRole',
    name: 'gets the role path',
    call: (s) => s.getRole('acme', 'r/1'),
    verb: 'get',
    url: '/v1/iam/tenants/acme/roles/r%2F1',
  },
  {
    method: 'listRoles',
    name: 'maps page and pageSize to the query',
    call: (s) => s.listRoles({ tenantId: 'acme', page: 1, pageSize: 10 }),
    verb: 'get',
    url: '/v1/iam/tenants/acme/roles?page=1&limit=10',
  },
  {
    method: 'updateRole',
    name: 'puts the request to the role path',
    call: (s) => s.updateRole({ tenantId: 'acme', roleId: 'r1', permissions: ['read', 'write'] }),
    verb: 'put',
    url: '/v1/iam/tenants/acme/roles/r1',
    body: { tenantId: 'acme', roleId: 'r1', permissions: ['read', 'write'] },
  },
  {
    method: 'deleteRole',
    name: 'deletes the role path',
    call: (s) => s.deleteRole('acme', 'r1'),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/roles/r1',
  },
  {
    method: 'assignRole',
    name: 'posts only the role id to the user roles path',
    call: (s) => s.assignRole({ tenantId: 'acme', userId: 'u1', roleId: 'r1' }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/users/u1/roles',
    body: { roleId: 'r1' },
  },
  {
    method: 'revokeRole',
    name: 'deletes the user role path',
    call: (s) => s.revokeRole({ tenantId: 'acme', userId: 'u1', roleId: 'r 1' }),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/users/u1/roles/r%201',
  },
  // Groups
  {
    method: 'createGroup',
    name: 'posts the request to the tenant groups path',
    call: (s) => s.createGroup({ tenantId: 'acme', name: 'ops', description: 'operators' }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/groups',
    body: { tenantId: 'acme', name: 'ops', description: 'operators' },
  },
  {
    method: 'getGroup',
    name: 'gets the group path',
    call: (s) => s.getGroup('acme', 'g1'),
    verb: 'get',
    url: '/v1/iam/tenants/acme/groups/g1',
  },
  {
    method: 'listGroups',
    name: 'maps page and pageSize to the query',
    call: (s) => s.listGroups({ tenantId: 'acme', page: 3, pageSize: 5 }),
    verb: 'get',
    url: '/v1/iam/tenants/acme/groups?page=3&limit=5',
  },
  {
    method: 'updateGroup',
    name: 'puts the request to the group path',
    call: (s) => s.updateGroup({ tenantId: 'acme', groupId: 'g1', name: 'ops2' }),
    verb: 'put',
    url: '/v1/iam/tenants/acme/groups/g1',
    body: { tenantId: 'acme', groupId: 'g1', name: 'ops2' },
  },
  {
    method: 'deleteGroup',
    name: 'deletes the group path',
    call: (s) => s.deleteGroup('acme', 'g1'),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/groups/g1',
  },
  {
    method: 'addGroupMember',
    name: 'posts only the user id to the group members path',
    call: (s) => s.addGroupMember({ tenantId: 'acme', groupId: 'g1', userId: 'u1' }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/groups/g1/members',
    body: { userId: 'u1' },
  },
  {
    method: 'removeGroupMember',
    name: 'deletes the group member path',
    call: (s) => s.removeGroupMember({ tenantId: 'acme', groupId: 'g1', userId: 'u/1' }),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/groups/g1/members/u%2F1',
  },
  // Authentication
  {
    method: 'authenticate',
    name: 'posts the credentials to the auth path',
    call: (s) => s.authenticate({ tenantId: 'acme', username: 'ada', password: 'pw', mfaCode: '123456' }),
    verb: 'post',
    url: '/v1/iam/auth',
    body: { tenantId: 'acme', username: 'ada', password: 'pw', mfaCode: '123456' },
  },
  {
    method: 'checkPermission',
    name: 'posts the request to the auth check path',
    call: (s) =>
      s.checkPermission({ tenantId: 'acme', subjectId: 'u1', action: 'read', resource: 'devices/d1' }),
    verb: 'post',
    url: '/v1/iam/auth/check',
    body: { tenantId: 'acme', subjectId: 'u1', action: 'read', resource: 'devices/d1' },
  },
  {
    method: 'createToken',
    name: 'posts the request to the auth token path',
    call: (s) => s.createToken({ tenantId: 'acme', userId: 'u1', scopes: ['read'], expiresIn: 3600 }),
    verb: 'post',
    url: '/v1/iam/auth/token',
    body: { tenantId: 'acme', userId: 'u1', scopes: ['read'], expiresIn: 3600 },
  },
  {
    method: 'revokeToken',
    name: 'posts the request to the token revoke path',
    call: (s) => s.revokeToken({ tokenId: 't1' }),
    verb: 'post',
    url: '/v1/iam/auth/token/revoke',
    body: { tokenId: 't1' },
  },
  {
    method: 'verifyToken',
    name: 'posts the token to the token verify path',
    call: (s) => s.verifyToken({ token: 'tok' }),
    verb: 'post',
    url: '/v1/iam/auth/token/verify',
    body: { token: 'tok' },
  },
  // Tenants
  {
    method: 'createTenant',
    name: 'posts the request to the tenants path',
    call: (s) => s.createTenant({ id: 'acme', name: 'Acme' }),
    verb: 'post',
    url: '/v1/iam/tenants',
    body: { id: 'acme', name: 'Acme' },
  },
  {
    method: 'getTenant',
    name: 'gets the encoded tenant path',
    call: (s) => s.getTenant('acme/eu'),
    verb: 'get',
    url: '/v1/iam/tenants/acme%2Feu',
  },
  {
    method: 'listTenants',
    name: 'maps page and pageSize to the query',
    call: (s) => s.listTenants({ page: 2, pageSize: 50 }),
    verb: 'get',
    url: '/v1/iam/tenants?page=2&limit=50',
  },
  {
    method: 'listTenants',
    name: 'sends no query without a request',
    call: (s) => s.listTenants(),
    verb: 'get',
    url: '/v1/iam/tenants',
  },
  {
    method: 'updateTenant',
    name: 'puts the request to the tenant path',
    call: (s) => s.updateTenant({ tenantId: 'acme', name: 'Acme Ltd' }),
    verb: 'put',
    url: '/v1/iam/tenants/acme',
    body: { tenantId: 'acme', name: 'Acme Ltd' },
  },
  {
    method: 'deleteTenant',
    name: 'deletes the tenant path',
    call: (s) => s.deleteTenant('acme'),
    verb: 'delete',
    url: '/v1/iam/tenants/acme',
  },
  // Policies
  {
    method: 'createPolicy',
    name: 'posts the request to the tenant policies path',
    call: (s) => s.createPolicy({ tenantId: 'acme', name: 'p1', specYaml: 'c3BlYw==', priority: 10 }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/policies',
    body: { tenantId: 'acme', name: 'p1', specYaml: 'c3BlYw==', priority: 10 },
  },
  {
    method: 'getPolicy',
    name: 'gets the encoded policy path',
    call: (s) => s.getPolicy('acme', 'allow all'),
    verb: 'get',
    url: '/v1/iam/tenants/acme/policies/allow%20all',
  },
  {
    method: 'listPolicies',
    name: 'maps page and pageSize to the query',
    call: (s) => s.listPolicies({ tenantId: 'acme', page: 1, pageSize: 20 }),
    verb: 'get',
    url: '/v1/iam/tenants/acme/policies?page=1&limit=20',
  },
  {
    method: 'updatePolicy',
    name: 'puts the request to the policy path',
    call: (s) => s.updatePolicy({ tenantId: 'acme', policyName: 'p1', priority: 5 }),
    verb: 'put',
    url: '/v1/iam/tenants/acme/policies/p1',
    body: { tenantId: 'acme', policyName: 'p1', priority: 5 },
  },
  {
    method: 'deletePolicy',
    name: 'deletes the policy path',
    call: (s) => s.deletePolicy('acme', 'p1'),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/policies/p1',
  },
  {
    method: 'validatePolicy',
    name: 'posts the request to the policies validate path',
    call: (s) => s.validatePolicy({ tenantId: 'acme', specYaml: 'c3BlYw==' }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/policies/validate',
    body: { tenantId: 'acme', specYaml: 'c3BlYw==' },
  },
  {
    method: 'testPolicy',
    name: 'posts the request to the policies test path',
    call: (s) =>
      s.testPolicy({ tenantId: 'acme', subjectId: 'u1', roles: ['admin'], action: 'write', resource: 'r1' }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/policies/test',
    body: { tenantId: 'acme', subjectId: 'u1', roles: ['admin'], action: 'write', resource: 'r1' },
  },
  // Applications
  {
    method: 'registerApp',
    name: 'posts the request to the tenant apps path',
    call: (s) => s.registerApp({ tenantId: 'acme', name: 'portal', grantTypes: ['client_credentials'] }),
    verb: 'post',
    url: '/v1/iam/tenants/acme/apps',
    body: { tenantId: 'acme', name: 'portal', grantTypes: ['client_credentials'] },
  },
  {
    method: 'getApp',
    name: 'gets the encoded app path',
    call: (s) => s.getApp('acme', 'client/1'),
    verb: 'get',
    url: '/v1/iam/tenants/acme/apps/client%2F1',
  },
  {
    method: 'listApps',
    name: 'maps page and pageSize to the query',
    call: (s) => s.listApps({ tenantId: 'acme', page: 4, pageSize: 15 }),
    verb: 'get',
    url: '/v1/iam/tenants/acme/apps?page=4&limit=15',
  },
  {
    method: 'updateApp',
    name: 'puts the request to the app path',
    call: (s) => s.updateApp({ tenantId: 'acme', clientId: 'c1', name: 'portal2' }),
    verb: 'put',
    url: '/v1/iam/tenants/acme/apps/c1',
    body: { tenantId: 'acme', clientId: 'c1', name: 'portal2' },
  },
  {
    method: 'deleteApp',
    name: 'deletes the app path',
    call: (s) => s.deleteApp('acme', 'c1'),
    verb: 'delete',
    url: '/v1/iam/tenants/acme/apps/c1',
  },
  {
    method: 'rotateAppSecret',
    name: 'posts an empty body to the rotate-secret path',
    call: (s) => s.rotateAppSecret('acme', 'c1'),
    verb: 'post',
    url: '/v1/iam/tenants/acme/apps/c1/rotate-secret',
    body: {},
  },
];

const verbs: Verb[] = ['get', 'post', 'put', 'delete'];

describe('IAMService', () => {
  let client: ApiClient;
  let service: IAMService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new IAMService(client);
  });

  it('covers every public method', () => {
    const publicMethods = Object.getOwnPropertyNames(IAMService.prototype).filter(
      (name) => name !== 'constructor'
    );
    const tested = new Set(cases.map((c) => c.method));
    expect(publicMethods.filter((name) => !tested.has(name))).toEqual([]);
  });

  for (const c of cases) {
    describe(c.method, () => {
      it(c.name, async () => {
        const response = { success: true, data: { ok: c.method } };
        vi.mocked(client[c.verb]).mockResolvedValue(response);

        const result = await c.call(service);

        expect(result).toBe(response);
        expect(client[c.verb]).toHaveBeenCalledTimes(1);
        if (c.verb === 'post' || c.verb === 'put') {
          expect(client[c.verb]).toHaveBeenCalledWith(c.url, c.body);
        } else {
          expect(client[c.verb]).toHaveBeenCalledWith(c.url);
        }
        for (const other of verbs.filter((v) => v !== c.verb)) {
          expect(client[other]).not.toHaveBeenCalled();
        }
      });
    });
  }

  for (const method of [...new Set(cases.map((c) => c.method))]) {
    const c = cases.find((x) => x.method === method) as WireCase;
    describe(method, () => {
      it('returns the failed transport response unchanged', async () => {
        vi.mocked(client[c.verb]).mockResolvedValue(failure);

        const result = await c.call(service);

        expect(result).toBe(failure);
        expect(result.success).toBe(false);
        expect(result.data).toBeUndefined();
      });

      it('propagates a transport rejection', async () => {
        vi.mocked(client[c.verb]).mockRejectedValue(new Error('network down'));

        await expect(c.call(service)).rejects.toThrow('network down');
      });
    });
  }
});
