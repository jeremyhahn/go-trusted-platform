# API Feature Parity Roadmap

This document tracks the work required to achieve 100% feature parity across all API protocols (REST, gRPC, QUIC, MCP, Unix Socket).

## Status Legend
- ⬜ Not Started
- 🟡 In Progress
- ✅ Complete

---

## Phase 1: REST API Implementation (Critical Priority)

REST currently has only 5 daemon management endpoints. Need to implement full service coverage.

### 1.1 CA Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/ca/info` | GET | ⬜ |
| `/api/v1/ca/certificates` | POST | ⬜ |
| `/api/v1/ca/certificates` | GET | ⬜ |
| `/api/v1/ca/certificates/{serial}` | GET | ⬜ |
| `/api/v1/ca/certificates/{serial}/revoke` | POST | ⬜ |
| `/api/v1/ca/certificates/{serial}/renew` | POST | ⬜ |
| `/api/v1/ca/certificates/verify` | POST | ⬜ |
| `/api/v1/ca/crl` | GET | ⬜ |
| `/api/v1/ca/bundle` | GET | ⬜ |

### 1.2 KMS Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/kms/keys` | POST | ⬜ |
| `/api/v1/kms/keys` | GET | ⬜ |
| `/api/v1/kms/keys/{id}` | GET | ⬜ |
| `/api/v1/kms/keys/{id}` | DELETE | ⬜ |
| `/api/v1/kms/keys/{id}/rotate` | POST | ⬜ |
| `/api/v1/kms/keys/{id}/export` | GET | ⬜ |
| `/api/v1/kms/keys/{id}/versions` | GET | ⬜ |
| `/api/v1/kms/keys/import` | POST | ⬜ |
| `/api/v1/kms/encrypt` | POST | ⬜ |
| `/api/v1/kms/decrypt` | POST | ⬜ |
| `/api/v1/kms/sign` | POST | ⬜ |
| `/api/v1/kms/verify` | POST | ⬜ |
| `/api/v1/kms/hash` | POST | ⬜ |
| `/api/v1/kms/hmac` | POST | ⬜ |
| `/api/v1/kms/random` | POST | ⬜ |
| `/api/v1/kms/status` | GET | ⬜ |

### 1.3 vTPM Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/vtpm/bundles` | POST | ⬜ |
| `/api/v1/vtpm/bundles` | GET | ⬜ |
| `/api/v1/vtpm/bundles/{id}` | GET | ⬜ |
| `/api/v1/vtpm/bundles/{id}` | DELETE | ⬜ |
| `/api/v1/vtpm/bundles/{id}/start` | POST | ⬜ |
| `/api/v1/vtpm/bundles/{id}/stop` | POST | ⬜ |
| `/api/v1/vtpm/bundles/{id}/state` | GET | ⬜ |
| `/api/v1/vtpm/bundles/{id}/quote` | POST | ⬜ |
| `/api/v1/vtpm/bundles/{id}/pcr/{index}` | GET | ⬜ |
| `/api/v1/vtpm/bundles/{id}/pcr/{index}/extend` | POST | ⬜ |
| `/api/v1/vtpm/bundles/{id}/seal` | POST | ⬜ |
| `/api/v1/vtpm/bundles/{id}/unseal` | POST | ⬜ |
| `/api/v1/vtpm/bundles/{id}/export` | GET | ⬜ |
| `/api/v1/vtpm/bundles/import` | POST | ⬜ |
| `/api/v1/vtpm/templates` | POST | ⬜ |
| `/api/v1/vtpm/templates/{id}/clone` | POST | ⬜ |

### 1.4 Device Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/devices` | POST | ⬜ |
| `/api/v1/devices` | GET | ⬜ |
| `/api/v1/devices/{id}` | GET | ⬜ |
| `/api/v1/devices/{id}` | PUT | ⬜ |
| `/api/v1/devices/{id}` | DELETE | ⬜ |
| `/api/v1/devices/{id}/activate` | POST | ⬜ |
| `/api/v1/devices/{id}/attest` | POST | ⬜ |
| `/api/v1/devices/{id}/state` | GET | ⬜ |
| `/api/v1/devices/serial/{serial}` | GET | ⬜ |
| `/api/v1/devices/profiles` | POST | ⬜ |
| `/api/v1/devices/profiles` | GET | ⬜ |
| `/api/v1/devices/profiles/{id}` | GET | ⬜ |
| `/api/v1/devices/profiles/{id}` | PUT | ⬜ |
| `/api/v1/devices/profiles/{id}` | DELETE | ⬜ |

### 1.5 IAM Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/iam/users` | POST | ⬜ |
| `/api/v1/iam/users` | GET | ⬜ |
| `/api/v1/iam/users/{id}` | GET | ⬜ |
| `/api/v1/iam/users/{id}` | PUT | ⬜ |
| `/api/v1/iam/users/{id}` | DELETE | ⬜ |
| `/api/v1/iam/roles` | POST | ⬜ |
| `/api/v1/iam/roles` | GET | ⬜ |
| `/api/v1/iam/roles/{id}` | GET | ⬜ |
| `/api/v1/iam/roles/{id}` | PUT | ⬜ |
| `/api/v1/iam/roles/{id}` | DELETE | ⬜ |
| `/api/v1/iam/groups` | POST | ⬜ |
| `/api/v1/iam/groups` | GET | ⬜ |
| `/api/v1/iam/groups/{id}` | GET | ⬜ |
| `/api/v1/iam/groups/{id}` | PUT | ⬜ |
| `/api/v1/iam/groups/{id}` | DELETE | ⬜ |
| `/api/v1/iam/policies` | POST | ⬜ |
| `/api/v1/iam/policies` | GET | ⬜ |
| `/api/v1/iam/policies/{id}` | GET | ⬜ |
| `/api/v1/iam/policies/{id}` | PUT | ⬜ |
| `/api/v1/iam/policies/{id}` | DELETE | ⬜ |
| `/api/v1/iam/tokens` | POST | ⬜ |
| `/api/v1/iam/tokens/validate` | POST | ⬜ |
| `/api/v1/iam/tokens/refresh` | POST | ⬜ |
| `/api/v1/iam/tokens/revoke` | POST | ⬜ |

### 1.6 DNS Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/dns/zones` | POST | ⬜ |
| `/api/v1/dns/zones` | GET | ⬜ |
| `/api/v1/dns/zones/{name}` | GET | ⬜ |
| `/api/v1/dns/zones/{name}` | DELETE | ⬜ |
| `/api/v1/dns/zones/{name}/sign` | POST | ⬜ |
| `/api/v1/dns/zones/{name}/records` | POST | ⬜ |
| `/api/v1/dns/zones/{name}/records` | GET | ⬜ |
| `/api/v1/dns/zones/{name}/records/{id}` | PUT | ⬜ |
| `/api/v1/dns/zones/{name}/records/{id}` | DELETE | ⬜ |
| `/api/v1/dns/resolve` | POST | ⬜ |
| `/api/v1/dns/register` | POST | ⬜ |
| `/api/v1/dns/transfer` | POST | ⬜ |

### 1.7 SDN Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/sdn/bridges` | POST | ⬜ |
| `/api/v1/sdn/bridges` | GET | ⬜ |
| `/api/v1/sdn/bridges/{id}` | GET | ⬜ |
| `/api/v1/sdn/bridges/{id}` | DELETE | ⬜ |
| `/api/v1/sdn/bridges/{id}/ports` | POST | ⬜ |
| `/api/v1/sdn/bridges/{id}/ports` | GET | ⬜ |
| `/api/v1/sdn/bridges/{id}/ports/{port}` | DELETE | ⬜ |
| `/api/v1/sdn/flows` | POST | ⬜ |
| `/api/v1/sdn/flows` | GET | ⬜ |
| `/api/v1/sdn/flows/{id}` | DELETE | ⬜ |
| `/api/v1/sdn/policies` | POST | ⬜ |
| `/api/v1/sdn/policies` | GET | ⬜ |
| `/api/v1/sdn/policies/{id}` | GET | ⬜ |
| `/api/v1/sdn/policies/{id}` | DELETE | ⬜ |
| `/api/v1/sdn/topology` | GET | ⬜ |

### 1.8 Compute Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/compute/vms` | POST | ⬜ |
| `/api/v1/compute/vms` | GET | ⬜ |
| `/api/v1/compute/vms/{id}` | GET | ⬜ |
| `/api/v1/compute/vms/{id}` | DELETE | ⬜ |
| `/api/v1/compute/vms/{id}/start` | POST | ⬜ |
| `/api/v1/compute/vms/{id}/stop` | POST | ⬜ |
| `/api/v1/compute/vms/{id}/restart` | POST | ⬜ |
| `/api/v1/compute/vms/{id}/suspend` | POST | ⬜ |
| `/api/v1/compute/vms/{id}/resume` | POST | ⬜ |
| `/api/v1/compute/vms/{id}/attest` | POST | ⬜ |
| `/api/v1/compute/vms/{id}/console` | GET | ⬜ |
| `/api/v1/compute/containers` | POST | ⬜ |
| `/api/v1/compute/containers` | GET | ⬜ |
| `/api/v1/compute/containers/{id}` | GET | ⬜ |
| `/api/v1/compute/containers/{id}` | DELETE | ⬜ |
| `/api/v1/compute/containers/{id}/start` | POST | ⬜ |
| `/api/v1/compute/containers/{id}/stop` | POST | ⬜ |
| `/api/v1/compute/containers/{id}/logs` | GET | ⬜ |
| `/api/v1/compute/containers/{id}/exec` | POST | ⬜ |
| `/api/v1/compute/containers/{id}/attest` | POST | ⬜ |

### 1.9 Attestation Service REST Endpoints
| Endpoint | Method | Status |
|----------|--------|--------|
| `/api/v1/attestation/manifest` | GET | ⬜ |
| `/api/v1/attestation/manifest` | POST | ⬜ |
| `/api/v1/attestation/manifest/verify` | POST | ⬜ |
| `/api/v1/attestation/host` | POST | ⬜ |
| `/api/v1/attestation/vm/{id}` | POST | ⬜ |
| `/api/v1/attestation/container/{id}` | POST | ⬜ |
| `/api/v1/attestation/device/{id}` | POST | ⬜ |
| `/api/v1/attestation/reports` | GET | ⬜ |
| `/api/v1/attestation/reports/{id}` | GET | ⬜ |
| `/api/v1/attestation/policies` | POST | ⬜ |
| `/api/v1/attestation/policies` | GET | ⬜ |

---

## Phase 2: Unix Socket Handler Expansion

Unix Socket currently has 7 handlers (CA, KMS, vTPM, Device, Container, Health, IAM partial). Need to add missing services and expand existing ones.

### 2.1 IAM Handler (New)
| Operation | Opcode | Status |
|-----------|--------|--------|
| CreateUser | OpIAMCreateUser | ⬜ |
| GetUser | OpIAMGetUser | ⬜ |
| UpdateUser | OpIAMUpdateUser | ⬜ |
| DeleteUser | OpIAMDeleteUser | ⬜ |
| ListUsers | OpIAMListUsers | ⬜ |
| CreateRole | OpIAMCreateRole | ⬜ |
| GetRole | OpIAMGetRole | ⬜ |
| UpdateRole | OpIAMUpdateRole | ⬜ |
| DeleteRole | OpIAMDeleteRole | ⬜ |
| ListRoles | OpIAMListRoles | ⬜ |
| CreateGroup | OpIAMCreateGroup | ⬜ |
| GetGroup | OpIAMGetGroup | ⬜ |
| UpdateGroup | OpIAMUpdateGroup | ⬜ |
| DeleteGroup | OpIAMDeleteGroup | ⬜ |
| ListGroups | OpIAMListGroups | ⬜ |
| CreatePolicy | OpIAMCreatePolicy | ⬜ |
| GetPolicy | OpIAMGetPolicy | ⬜ |
| UpdatePolicy | OpIAMUpdatePolicy | ⬜ |
| DeletePolicy | OpIAMDeletePolicy | ⬜ |
| ListPolicies | OpIAMListPolicies | ⬜ |
| IssueToken | OpIAMIssueToken | ⬜ |
| ValidateToken | OpIAMValidateToken | ⬜ |
| RefreshToken | OpIAMRefreshToken | ⬜ |
| RevokeToken | OpIAMRevokeToken | ⬜ |

### 2.2 DNS Handler (New)
| Operation | Opcode | Status |
|-----------|--------|--------|
| CreateZone | OpDNSCreateZone | ⬜ |
| GetZone | OpDNSGetZone | ⬜ |
| DeleteZone | OpDNSDeleteZone | ⬜ |
| ListZones | OpDNSListZones | ⬜ |
| SignZone | OpDNSSignZone | ⬜ |
| AddRecord | OpDNSAddRecord | ⬜ |
| UpdateRecord | OpDNSUpdateRecord | ⬜ |
| DeleteRecord | OpDNSDeleteRecord | ⬜ |
| ListRecords | OpDNSListRecords | ⬜ |
| Resolve | OpDNSResolve | ⬜ |
| Register | OpDNSRegister | ⬜ |
| Transfer | OpDNSTransfer | ⬜ |

### 2.3 SDN Handler (New)
| Operation | Opcode | Status |
|-----------|--------|--------|
| CreateBridge | OpSDNCreateBridge | ⬜ |
| GetBridge | OpSDNGetBridge | ⬜ |
| DeleteBridge | OpSDNDeleteBridge | ⬜ |
| ListBridges | OpSDNListBridges | ⬜ |
| AddPort | OpSDNAddPort | ⬜ |
| RemovePort | OpSDNRemovePort | ⬜ |
| ListPorts | OpSDNListPorts | ⬜ |
| AddFlow | OpSDNAddFlow | ⬜ |
| DeleteFlow | OpSDNDeleteFlow | ⬜ |
| ListFlows | OpSDNListFlows | ⬜ |
| ApplyPolicy | OpSDNApplyPolicy | ⬜ |
| GetPolicy | OpSDNGetPolicy | ⬜ |
| ListPolicies | OpSDNListPolicies | ⬜ |
| GetTopology | OpSDNGetTopology | ⬜ |

### 2.4 VM Handler (New)
| Operation | Opcode | Status |
|-----------|--------|--------|
| CreateVM | OpVMCreate | ⬜ |
| GetVM | OpVMGet | ⬜ |
| DeleteVM | OpVMDelete | ⬜ |
| ListVMs | OpVMList | ⬜ |
| StartVM | OpVMStart | ⬜ |
| StopVM | OpVMStop | ⬜ |
| RestartVM | OpVMRestart | ⬜ |
| SuspendVM | OpVMSuspend | ⬜ |
| ResumeVM | OpVMResume | ⬜ |
| AttestVM | OpVMAttest | ✅ (via OpVMExtendedCategory sub-opcode) |
| GetConsole | OpVMConsole | ⬜ |

### 2.5 Attestation Handler (New)
| Operation | Opcode | Status |
|-----------|--------|--------|
| GetManifest | OpAttestGetManifest | ⬜ |
| BuildManifest | OpAttestBuildManifest | ⬜ |
| VerifyManifest | OpAttestVerifyManifest | ⬜ |
| CollectHost | OpAttestHost | ⬜ |
| CollectVM | OpAttestVM | ⬜ |
| CollectContainer | OpAttestContainer | ⬜ |
| CollectDevice | OpAttestDevice | ⬜ |
| ListReports | OpAttestListReports | ⬜ |
| GetReport | OpAttestGetReport | ⬜ |

### 2.6 Extended Device Handler Operations
| Operation | Opcode | Status |
|-----------|--------|--------|
| CreateDevice | OpDeviceCreate | ⬜ |
| UpdateDevice | OpDeviceUpdate | ⬜ |
| DeleteDevice | OpDeviceDelete | ⬜ |
| FindBySerial | OpDeviceFindBySerial | ⬜ |
| ActivateDevice | OpDeviceActivate | ⬜ |
| CreateProfile | OpDeviceCreateProfile | ⬜ |
| UpdateProfile | OpDeviceUpdateProfile | ⬜ |
| DeleteProfile | OpDeviceDeleteProfile | ⬜ |

### 2.7 Extended vTPM Handler Operations
| Operation | Opcode | Status |
|-----------|--------|--------|
| CreateBundle | OpVTPMCreateBundle | ⬜ |
| GetBundle | OpVTPMGetBundle | ⬜ |
| DeleteBundle | OpVTPMDeleteBundle | ⬜ |
| ListBundles | OpVTPMListBundles | ⬜ |
| CreateTemplate | OpVTPMCreateTemplate | ⬜ |
| CloneTemplate | OpVTPMCloneTemplate | ⬜ |
| ExportBundle | OpVTPMExportBundle | ⬜ |
| ImportBundle | OpVTPMImportBundle | ⬜ |
| ExtendPCR | OpVTPMExtendPCR | ⬜ |
| Seal | OpVTPMSeal | ⬜ |
| Unseal | OpVTPMUnseal | ⬜ |

### 2.8 Extended KMS Handler Operations
| Operation | Opcode | Status |
|-----------|--------|--------|
| GenerateDataKey | OpKMSGenerateDataKey | ⬜ |
| GenerateWrappedDataKey | OpKMSGenerateWrappedDataKey | ⬜ |

### 2.9 CA Handler - Add CRL Operation
| Operation | Opcode | Status |
|-----------|--------|--------|
| GetCRL | OpCACRL | ⬜ |

---

## Phase 3: gRPC Service Completion

### 3.1 KMS gRPC Service (New)
| RPC | Status |
|-----|--------|
| GenerateKey | ⬜ |
| ImportKey | ⬜ |
| GetKey | ⬜ |
| ListKeys | ⬜ |
| DeleteKey | ⬜ |
| RotateKey | ⬜ |
| UpdateKeyStatus | ⬜ |
| ExportKey | ⬜ |
| GetKeyVersions | ⬜ |
| Encrypt | ⬜ |
| Decrypt | ⬜ |
| Sign | ⬜ |
| Verify | ⬜ |
| Hash | ⬜ |
| HMAC | ⬜ |
| VerifyHMAC | ⬜ |
| GenerateRandom | ⬜ |
| GenerateDataKey | ⬜ |
| GenerateWrappedDataKey | ⬜ |
| BackendStatus | ⬜ |

### 3.2 Health gRPC Service (New)
| RPC | Status |
|-----|--------|
| Health | ⬜ |
| Liveness | ⬜ |
| Readiness | ⬜ |

---

## Phase 4: QUIC/MCP Gaps

### 4.1 VM Operations for QUIC
| Operation | Status |
|-----------|--------|
| CreateVM | ⬜ |
| GetVM | ⬜ |
| DeleteVM | ⬜ |
| ListVMs | ⬜ |
| StartVM | ⬜ |
| StopVM | ⬜ |
| RestartVM | ⬜ |
| SuspendVM | ⬜ |
| ResumeVM | ⬜ |
| AttestVM | ⬜ |

### 4.2 VM Operations for MCP
| Tool | Status |
|------|--------|
| vm_create | ⬜ |
| vm_get | ⬜ |
| vm_delete | ⬜ |
| vm_list | ⬜ |
| vm_start | ⬜ |
| vm_stop | ⬜ |
| vm_restart | ⬜ |
| vm_suspend | ⬜ |
| vm_resume | ⬜ |
| vm_attest | ✅ |

### 4.3 Attestation for QUIC
| Operation | Status |
|-----------|--------|
| GetManifest | ⬜ |
| BuildManifest | ⬜ |
| VerifyManifest | ⬜ |
| CollectHost | ⬜ |
| CollectVM | ⬜ |
| CollectContainer | ⬜ |
| CollectDevice | ⬜ |

### 4.4 Attestation for MCP
| Tool | Status |
|------|--------|
| attestation_get_manifest | ⬜ |
| attestation_build_manifest | ⬜ |
| attestation_verify_manifest | ⬜ |
| attestation_collect_host | ⬜ |
| attestation_collect_vm | ⬜ |
| attestation_collect_container | ⬜ |
| attestation_collect_device | ⬜ |

---

## Phase 5: Testing & Documentation

### 5.1 Integration Tests
| Protocol | Test Suite | Status |
|----------|------------|--------|
| REST | test/integration/rest/ | ⬜ |
| Unix | test/integration/unix/ | ⬜ |
| gRPC | test/integration/grpc/ | ⬜ |
| QUIC | test/integration/quic/ | ⬜ |
| MCP | test/integration/mcp/ | ⬜ |

### 5.2 Multi-Protocol Tests
| Service | Multi-Protocol Test | Status |
|---------|---------------------|--------|
| CA | All protocols | ⬜ |
| KMS | All protocols | ⬜ |
| vTPM | All protocols | ⬜ |
| Device | All protocols | ⬜ |
| IAM | All protocols | ⬜ |
| DNS | All protocols | ⬜ |
| SDN | All protocols | ⬜ |
| Compute | All protocols | ⬜ |
| Attestation | All protocols | ⬜ |

### 5.3 Documentation
| Document | Status |
|----------|--------|
| docs/api/rest-api-reference.md | ⬜ |
| docs/api/unix-api-reference.md | ⬜ |
| docs/api/grpc-api-reference.md | ⬜ |
| docs/api/quic-api-reference.md | ⬜ |
| docs/api/mcp-api-reference.md | ⬜ |

---

## Summary Statistics

| Phase | Total Items | Completed | Remaining |
|-------|-------------|-----------|-----------|
| Phase 1: REST API | 127 endpoints | 0 | 127 |
| Phase 2: Unix Socket | 76 operations | 0 | 76 |
| Phase 3: gRPC | 23 RPCs | 0 | 23 |
| Phase 4: QUIC/MCP | 34 operations | 0 | 34 |
| Phase 5: Testing | 19 items | 0 | 19 |
| **Total** | **279 items** | **0** | **279** |

---

## Execution Order

1. **Phase 1.1-1.2**: REST CA + KMS (highest value, most requested)
2. **Phase 2.1**: Unix IAM Handler (security critical)
3. **Phase 3.1**: gRPC KMS Service (fills major gap)
4. **Phase 1.3-1.4**: REST vTPM + Device
5. **Phase 2.2-2.4**: Unix DNS, SDN, VM handlers
6. **Phase 1.5-1.9**: REST IAM, DNS, SDN, Compute, Attestation
7. **Phase 2.5-2.9**: Unix Attestation and extended operations
8. **Phase 3.2**: gRPC Health
9. **Phase 4**: QUIC/MCP gaps
10. **Phase 5**: Testing and documentation

---

*Last Updated: 2026-01-12*
