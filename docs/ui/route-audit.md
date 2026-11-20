# UI route audit: every call the web UI makes, checked against the server

Issue #2032, epic #1665 (ruling 972 wave 1). `docs/ui/coverage-matrix.md` maps backend operations to pages; this file goes the other way: every REST path or SDK method that `web/src` calls, and whether the daemon serves it.

**Draft (slice 1).** The `not-configured` pass is not done yet: every area below is registered only when its backend server is non-nil (for example `gatewayRoutes`, `pkg/webservice/v1/router.go:723`), and slice 2 must check each one against `configs/platform/templates/single-node/default.yaml`. Until then, rows whose route exists are marked `implemented`.

## How to read this file

- **Caller**: the file under `web/src` and its line. Paths are relative to `web/src`; `(d)` stands for `app/(dashboard)`.
- **SDK**: the method's line in `sdk/javascript/src/services/<area>-service.ts` (quicBaaS: `services/quicbaas/`). The SDK base URL is `/api` plus the service's base path (for example `/v1/ca`).
- **Server**: the line in `pkg/webservice/v1/testdata/routes.golden` (`g:N`). The golden file lists every route the v1 router registers when all backends are wired (`TestRegisterRoutes_EveryRouteStillExists`). `router.go:N` is `pkg/webservice/v1/router.go`. `-` means no route matches the method and path, so the call gets a 404 or 405.
- **Status**: `implemented`, `unimplemented` (no route), `stubbed` (the handler returns fixed or empty data), `not-configured` (see the draft note above).

## Counts (grep)

Counted with Serena `search_for_pattern` over `web/src`, excluding `__tests__/`, `test/` and `*.test.tsx`:

- `\bfetch\(`: 38 matches. One is a comment (`(d)/tpm/nvram/page.tsx:112`), so there are **37 fetch call sites**, all listed in table B. Two of them are wrappers that send several paths (`app/auth/webauthn/page.tsx:98`, `utils/auth-factors-api.ts:75`). B lists each of those paths on its own row.
- `apiClient\.`: **0 matches**.
- SDK service calls: the web code takes a service from `useAttestation/useCA/useCompute/useDevice/useDNS/useGateway/useIAM/useIDevID/useKMS/useOverlay/usePlatform/usePXE/useSDN/useTenant/useTPM/useVPN/useVTPM` (`sdk/javascript/src/react/hooks/use-services.ts`) or from `usePlatformClient()`, and calls `<var>.<method>(`. That gives **178 distinct SDK methods** (table A, plus 3 NTP paths: 181 rows). Each appears once, and the caller column lists every call site. `hooks/use-ntp.ts` calls the NTP paths through `client.getApiClient()`.

## A. SDK service methods

| Method | Callers | SDK | Route | Server | Status |
|---|---|---|---|---|---|
| attestation.getManifest | (d)/attestation/[id]/attestation-detail-client.tsx:38 | attestation:109 | GET /api/v1/attestation/manifests/{id} | g:95 | implemented |
| attestation.listManifests | (d)/attestation/page.tsx:73, eventlogs:180, manifests:154, quotes:171, verify:171 | attestation:141 | GET /attestation/manifests | g:94 | implemented |
| attestation.buildManifest | (d)/attestation/page.tsx:109 | attestation:121 | POST /attestation/manifests/build | g:363 | implemented |
| attestation.listDeviceReports | (d)/attestation/page.tsx:58, (d)/devices/page.tsx:157 | attestation:213 | GET /attestation/reports | g:96 | implemented |
| attestation.getDeviceReport | components/features/attestation/device-report-card.tsx:42 | attestation:224 | GET /attestation/reports/{device_id} | g:97 | implemented |
| attestation.refreshDeviceReport | device-report-card.tsx:56, components/features/devices/device-table.tsx:71 | attestation:237 | POST /attestation/reports/{id}/refresh | g:367 | implemented |
| ca.listCertificates | (d)/ca/certificates/page.tsx:91, (d)/dashboard/page.tsx:141 | ca:113 | GET /ca/certificates | g:102 | implemented |
| ca.getCertificate | (d)/ca/certificates/[id]/cert-detail-client.tsx:80 | ca:123 | GET /ca/certificates/{serial} | g:103 | implemented |
| ca.issueCertificate | (d)/ca/certificates/page.tsx:202 | ca:135 | POST /ca/certificates | g:369 | implemented |
| ca.revokeCertificate | certificates/page.tsx:224, cert-detail-client.tsx:141 | ca:149 | DELETE /ca/certificates/{serial} | g:2 | implemented |
| ca.renewCertificate | certificates/page.tsx:238 | ca:163 | POST /ca/certificates/{serial}/renew | g:371 | implemented |
| ca.downloadCertificatePEM | certificates/page.tsx:256 | ca:226 | GET /ca/certificates/{serial}/download | - | **unimplemented** |
| ca.getCRL | (d)/ca/crl/page.tsx:71 | ca:185 | GET /ca/crl | g:104 | implemented |
| ca.getBundle | (d)/ca/bundle/page.tsx:48 | ca:205 | GET /ca/bundle | g:101 | implemented |
| compute.listVMs | (d)/compute/vms/page.tsx:40, snapshots:51 | compute:215 | GET /compute/vms | g:119 | implemented |
| compute.getVM | (d)/compute/vms/[id]/vm-detail-client.tsx:58 | compute:203 | GET /compute/vms/{id} | g:120 | implemented |
| compute.createVM | components/features/compute/vm-form.tsx:84 | compute:140 | POST /compute/vms | g:382 | implemented |
| compute.startVM | vm-detail-client.tsx:86, vm-table.tsx:45 | compute:150 | POST /compute/vms/{id}/start | g:391 | implemented |
| compute.stopVM | vm-detail-client.tsx:108, vm-table.tsx:67 | compute:163 | POST /compute/vms/{id}/stop | g:392 | implemented |
| compute.rebootVM | vm-detail-client.tsx:130, vm-table.tsx:89 | compute:176 | POST /compute/vms/{id}/reboot | g:387 | implemented |
| compute.deleteVM | vm-detail-client.tsx:187, vm-table.tsx:111 | compute:189 | DELETE /compute/vms/{id} | g:6 | implemented |
| compute.listSnapshots | (d)/compute/snapshots/page.tsx:86 | compute:323 | GET /compute/vms/{id}/snapshots | g:122 | implemented |
| compute.deleteSnapshot | snapshots/page.tsx:134 | compute:311 | DELETE /compute/vms/{id}/snapshots/{sid} | g:8 | implemented |
| compute.restoreSnapshot | snapshots/page.tsx:158 | compute:298 | POST /compute/vms/{id}/snapshots/{sid}/restore | g:390 | implemented |
| compute.listContainers | (d)/compute/containers/page.tsx:40 | compute:459 | GET /compute/containers | g:112 | implemented |
| compute.createContainer | components/features/compute/container-form.tsx:96 | compute:394 | POST /compute/containers | g:373 | implemented |
| compute.startContainer | container-table.tsx:51 | compute:404 | POST /compute/containers/{id}/start | g:376 | implemented |
| compute.stopContainer | container-table.tsx:73 | compute:417 | POST /compute/containers/{id}/stop | g:377 | implemented |
| compute.deleteContainer | container-table.tsx:95 | compute:430 | DELETE /compute/containers/{id} | g:4 | implemented |
| device.listDevices | (d)/devices/page.tsx:57, dashboard:130, features/devices/idevid-form.tsx:71 | device:269 | GET /devices | g:135 | implemented |
| device.getDevice | (d)/devices/[id]/device-detail-client.tsx:71 | device:167 | GET /devices/{id} | g:138 | implemented |
| device.createDevice | features/devices/device-form.tsx:50 | device:157 | POST /devices | g:405 | implemented |
| device.deleteDevice | device-detail-client.tsx:190, device-table.tsx:117 | device:259 | DELETE /devices/{id} | g:11 | implemented |
| device.enableDevice | hooks/use-device-toggle.ts:31 | device:227 | POST /devices/{id}/enable | g:410 | implemented |
| device.disableDevice | hooks/use-device-toggle.ts:31 | device:215 | POST /devices/{id}/disable | g:409 | implemented |
| device.recordAttestCert | features/attestation/attest-cert-card.tsx:64 | device:247 | POST /devices/{id}/attest-cert/record | g:408 | implemented |
| device.listProfiles | (d)/devices/profiles/page.tsx:206 | device:365 | GET /device/profiles | g:126 | implemented |
| device.createProfile | profiles/page.tsx:278, (d)/provisioning/sessions/[sessionId]/session-detail-client.tsx:195 | device:322 | POST /device/profiles | g:399 | implemented |
| device.deleteProfile | profiles/page.tsx:254 | device:355 | DELETE /device/profiles/{id} | g:9 | implemented |
| device.getTemplate | (d)/devices/templates/[id]/template-detail-client.tsx:79, create-profile-client.tsx:60 | device:442 | GET /device/templates/{id} | g:134 | implemented |
| device.deleteTemplate | template-detail-client.tsx:94 | device:465 | DELETE /device/templates/{id} | g:10 | implemented |
| device.createProfileFromTemplate | create-profile-client.tsx:75, session-detail-client.tsx:161 | device:490 | POST /device/templates/{id}/create-profile | g:404 | implemented |
| device.getProvisioningSession | session-detail-client.tsx:134 | device:591 | GET /provisioning/sessions/{id} | g:256 | implemented |
| device.fulfillProvisioningSession | session-detail-client.tsx:164, 198 | device:607 | POST /provisioning/sessions/{id}/fulfill | g:496 | implemented (path at device:607 not yet read) |
| dns.listZones | (d)/networking/dns/page.tsx:42 | dns:112 | GET /dns/zones | g:141 | implemented |
| dns.createZone | dns/page.tsx:132 | dns:90 | POST /dns/zones | g:413 | implemented |
| dns.getZone | (d)/networking/dns/[zone]/dns-zone-detail-client.tsx:32 | dns:100 | GET /dns/zones/{zone} | g:142 | implemented |
| dns.deleteZone | features/networking/dns-zone-table.tsx:52 | dns:142 | DELETE /dns/zones/{zone} | g:12 | implemented |
| dns.addRecord | features/networking/dns-record-form.tsx:83 | dns:158 | POST /dns/zones/{zone}/records | g:414 | implemented |
| dns.updateRecord | dns-record-form.tsx:144 | dns:185 | PUT /dns/zones/{zone}/records | g:574 | implemented |
| dns.deleteRecord | dns-record-table.tsx:55 | dns:198 | DELETE /dns/zones/{zone}/records/{type}/{name} | g:13 | implemented |
| gateway.getStatus | (d)/networking/gateway/page.tsx:57 | gateway:76 | GET /gateway/status | g:162 | implemented (gated on GatewayServiceServer, router.go:723) |
| gateway.getBGPStatus | gateway/page.tsx:83 | gateway:168 | GET /gateway/bgp/status | g:156 | implemented (same gate) |
| gateway.listAnnouncedPrefixes | gateway/page.tsx:109 | gateway:210 | GET /gateway/bgp/prefixes | g:155 | implemented (same gate) |
| gateway.listIPAMPools | gateway/page.tsx:135 | gateway:223 | GET /gateway/ipam/pools | g:159 | implemented (same gate) |
| iam.listUsers | (d)/iam/users/page.tsx:42, dashboard:119, (d)/tenant/members/page.tsx:33, (d)/tenant/page.tsx:126 | iam:145 | GET /iam/tenants/{t}/users | g:182 | implemented |
| iam.getUser | (d)/iam/users/[id]/user-detail-client.tsx:68 | iam:136 | GET /iam/tenants/{t}/users/{id} | g:183 | implemented |
| iam.createUser | users/page.tsx:112 | iam:126 | POST /iam/tenants/{t}/users | g:444 | implemented |
| iam.updateUser | users/page.tsx:172, user-detail-client.tsx:137 | iam:162 | PUT /iam/tenants/{t}/users/{id} | g:585 | implemented |
| iam.deleteUser | users/page.tsx:145, 232, tenant/members/page.tsx:81 | iam:172 | DELETE /iam/tenants/{t}/users/{id} | g:30 | implemented |
| iam.assignRole | tenant/members/page.tsx:59 | iam:235 | POST /iam/tenants/{t}/users/{id}/roles (role in body) | - (server: `.../roles/{role}`, g:445) | **unimplemented** |
| iam.revokeRole | user-detail-client.tsx:171 | iam:245 | DELETE /iam/tenants/{t}/users/{id}/roles/{role} | g:31 | implemented |
| iam.listRoles | (d)/iam/roles/page.tsx:39, permissions:56, users/page.tsx:59, user-detail-client.tsx:80 | iam:204 | GET /iam/tenants/{t}/roles | g:180 | implemented |
| iam.getRole | (d)/iam/roles/[id]/role-detail-client.tsx:66 | iam:195 | GET /iam/tenants/{t}/roles/{id} | g:181 | implemented |
| iam.createRole | (d)/iam/roles/new/page.tsx:34 | iam:185 | POST /iam/tenants/{t}/roles | g:443 | implemented |
| iam.updateRole | role-detail-client.tsx:107 | iam:216 | PUT /iam/tenants/{t}/roles/{id} | g:584 | implemented |
| iam.deleteRole | roles/page.tsx:78, 130 | iam:226 | DELETE /iam/tenants/{t}/roles/{id} | g:29 | implemented |
| iam.listGroups | (d)/iam/groups/page.tsx:50, permissions:38 | iam:277 | GET /iam/tenants/{t}/groups | g:176 | implemented |
| iam.getGroup | (d)/iam/groups/[id]/group-detail-client.tsx:42 | iam:268 | GET /iam/tenants/{t}/groups/{id} | g:177 | implemented |
| iam.createGroup | (d)/iam/groups/new/page.tsx:30 | iam:258 | POST /iam/tenants/{t}/groups | g:437 | implemented |
| iam.deleteGroup | groups/page.tsx:82, 134, group-detail-client.tsx:50 | iam:299 | DELETE /iam/tenants/{t}/groups/{id} | g:26 | implemented |
| iam.listPolicies | (d)/iam/policies/page.tsx:61, permissions:47 | iam:438 | GET /iam/tenants/{t}/policies | g:178 | implemented |
| iam.getPolicy | (d)/iam/policies/[name]/policy-detail-client.tsx:49 | iam:429 | GET /iam/tenants/{t}/policies/{id} | g:179 | implemented |
| iam.createPolicy | (d)/iam/policies/new/page.tsx:72 | iam:419 | POST /iam/tenants/{t}/policies | g:440 | implemented |
| iam.deletePolicy | policies/page.tsx:93, 145, policy-detail-client.tsx:57 | iam:460 | DELETE /iam/tenants/{t}/policies/{id} | g:28 | implemented |
| iam.listApps | (d)/iam/apps/page.tsx:52, (d)/iam/tokens/page.tsx:66 | iam:512 | GET /iam/tenants/{t}/apps | g:174 | implemented |
| iam.getApp | (d)/iam/apps/[clientId]/app-detail-client.tsx:41 | iam:503 | GET /iam/tenants/{t}/apps/{id} | g:175 | implemented |
| iam.registerApp | (d)/iam/apps/new/page.tsx:37, tokens/page.tsx:96 | iam:493 | POST /iam/tenants/{t}/apps | g:435 | implemented |
| iam.deleteApp | apps/page.tsx:89, 141, app-detail-client.tsx:49, tokens/page.tsx:140, 227 | iam:534 | DELETE /iam/tenants/{t}/apps/{id} | g:25 | implemented |
| iam.rotateAppSecret | tokens/page.tsx:167 | iam:543 | POST /iam/tenants/{t}/apps/{id}/rotate-secret | - (server: `/rotate`, g:436) | **unimplemented** |
| idevid.getIDevIDInfo | (d)/devices/idevid/[id]/idevid-detail-client.tsx:58, (d)/tpm/keys/page.tsx:224, (d)/tpm/status/page.tsx:139 | idevid:126 | GET /idevid/info | g:194 | implemented |
| idevid.generateIDevID | idevid-detail-client.tsx:92, features/devices/idevid-form.tsx:92, idevid-table.tsx:57 | idevid:117 | POST /idevid/generate | g:452 | implemented |
| idevid.deleteIDevID | idevid-detail-client.tsx:88, idevid-table.tsx:53 | idevid:144 | DELETE /idevid | g:34 | implemented |
| idevid.createIDevIDCSR | idevid-form.tsx:100 | idevid:154 | POST /idevid/csr | g:450 | implemented |
| idevid.getIDevIDCertificate | idevid-detail-client.tsx:153, idevid-table.tsx:132, tpm/keys/page.tsx:140 | idevid:173 | GET /idevid/certificate | g:188 | implemented |
| idevid.deleteIDevIDCertificate | idevid-detail-client.tsx:114, idevid-table.tsx:83 | idevid:182 | DELETE /idevid/certificate | g:35 | implemented |
| idevid.getIAKInfo | tpm/keys/page.tsx:210, tpm/status/page.tsx:134 | idevid:212 | GET /idevid/iak | g:191 | implemented |
| idevid.getIAKCertificate | tpm/keys/page.tsx:137 | idevid:259 | GET /idevid/iak/certificate | g:192 | implemented |
| kms.listKeys | (d)/kms/page.tsx:60 | kms:133 | GET /kms/keys | g:204 | implemented |
| kms.getKey | (d)/kms/[id]/key-detail-client.tsx:61 | kms:123 | GET /kms/keys/{name} | g:205 | implemented (URL built above kms:123, not yet read) |
| kms.generateKey | kms/page.tsx:134 | kms:99 | POST /kms/keys | g:469 | implemented |
| kms.deleteKey | kms/page.tsx:189, key-detail-client.tsx:108 | kms:152 | DELETE /kms/keys/{name} | g:40 | implemented (URL not yet read) |
| kms.rotateKey | kms/page.tsx:165 | kms:162 | POST /kms/keys/{id}/rotate | g:472 | implemented |
| kms.exportKey | kms/page.tsx:213 | kms:188 | POST /kms/keys/{id}/export | - | **unimplemented** |
| kms.encrypt | key-detail-client.tsx:148 | kms:224 | POST /kms/encrypt (key in body) | - (server: `/kms/encrypt/{name}`, g:465) | **unimplemented** |
| kms.decrypt | key-detail-client.tsx:158 | kms:234 | POST /kms/decrypt | - (g:462 needs `{name}`) | **unimplemented** |
| kms.sign | key-detail-client.tsx:168 | kms:244 | POST /kms/sign | - (g:477 needs `{name}`) | **unimplemented** |
| kms.verify | key-detail-client.tsx:178 | kms:254 | POST /kms/verify | - (g:478 needs `{name}`) | **unimplemented** |
| overlay.listVNIs | (d)/networking/overlays/page.tsx:41, hooks/use-overlay-vteps.ts:26 | overlay:118 | GET /overlay/vnis | g:234 | implemented |
| overlay.createVNI | overlays/page.tsx:129 | overlay:109 | POST /overlay/vnis | g:484 | implemented |
| overlay.deleteVNI | use-overlay-vteps.ts:55 | overlay:128 | DELETE /overlay/vnis/{vni} | g:45 | implemented |
| overlay.listVTEPs | use-overlay-vteps.ts:25 | overlay:83 | GET /overlay/vteps | g:235 | implemented |
| overlay.getVTEP | use-overlay-vteps.ts:32 | overlay:93 | GET /overlay/vteps/{nodeId} | g:236 | implemented |
| overlay.listTunnels | use-overlay-vteps.ts:27 | overlay:142 | GET /overlay/tunnels | g:232 | implemented |
| overlay.getTunnelStats | use-overlay-vteps.ts:41 | overlay:154 | GET /overlay/tunnels/stats | g:233 | implemented |
| overlay.listRemoteMACs | use-overlay-vteps.ts:28 | overlay:172 | GET /overlay/macs | g:230 | implemented |
| overlay.forgetMAC | use-overlay-vteps.ts:66 | overlay:184 | DELETE /overlay/macs | g:44 | implemented |
| platform.getHealth | dashboard:152, (d)/platform/events:182, health:76, metrics:230, services:152 | platform:100 | GET /platform/health | g:241 | implemented |
| platform.getMetrics | dashboard:163, health:95, metrics:202 | platform:141 | GET /platform/metrics | g:245 | implemented |
| platform.getSystemInfo | health:99, metrics:222 | platform:77 | GET /platform/system | g:251 | implemented |
| pxe.listDevices | (d)/networking/pxe/page.tsx:46 | pxe:124 | GET /pxe/devices | g:260 | implemented |
| pxe.getStatus | pxe/page.tsx:72 | pxe:240 | GET /pxe/status | g:264 | implemented |
| pxe.registerDevice | pxe/page.tsx:302 | pxe:78 | POST /pxe/devices | g:498 | implemented |
| sdn.listBridges | (d)/networking/sdn:66, flows:118, ports:78, vlans:60 | sdn:135 | GET /sdn/bridges | g:278 | implemented |
| sdn.createBridge | sdn/page.tsx:221 | sdn:113 | POST /sdn/bridges | g:518 | implemented |
| sdn.listPorts | ports/page.tsx:103 | sdn:192 | GET /sdn/bridges/{name}/ports | g:282 | implemented |
| sdn.addPort | ports/page.tsx:443 | sdn:166 | POST /sdn/bridges/{name}/ports | g:521 | implemented |
| sdn.deletePort | ports/page.tsx:173, 330 | sdn:207 | DELETE /sdn/bridges/{name}/ports/{port} | g:53 | implemented |
| sdn.listFlows | sdn/page.tsx:87, flows/page.tsx:143 | sdn:279 | GET /sdn/bridges/{name}/flows | g:281 | implemented |
| sdn.addFlow | flows/page.tsx:509 | sdn:266 | POST /sdn/bridges/{name}/flows | g:520 | implemented |
| sdn.deleteFlow | flows/page.tsx:219, 391 | sdn:297 | DELETE /sdn/bridges/{b}/flows/{flow} | - (server: `DELETE /sdn/flows`, g:55) | **unimplemented** |
| sdn.listVLANs | vlans/page.tsx:85 | sdn:352 | GET /sdn/bridges/{id}/vlans | g:279 | implemented |
| sdn.createVLAN | vlans/page.tsx:506 | sdn:339 | POST /sdn/bridges/{id}/vlans | g:519 | implemented |
| sdn.deleteVLAN | vlans/page.tsx:168, 383 | sdn:367 | DELETE /sdn/bridges/{b}/vlans/{vlan} | - | **unimplemented** |
| tenant.getTenant | dashboard:172, (d)/tenant/page.tsx:108 | tenant:87 | GET /tenants/{id} | g:300 | implemented |
| tenant.getQuotas | (d)/tenant/quotas/page.tsx:85 | tenant:192 | GET /tenants/{id}/quotas | g:303 | implemented |
| tenant.getUsage | quotas/page.tsx:97 | tenant:221 | GET /tenants/{id}/usage | g:304 | implemented |
| tpm.getInfo | (d)/tpm/lockout:63, nvram:125, status:102 | tpm:161 | GET /tpm/info | g:311 | implemented |
| tpm.getEK | tpm/keys:162, status:124 | tpm:211 | GET /tpm/ek | g:308 | implemented |
| tpm.getSRK | tpm/keys:173, status:129 | tpm:269 | GET /tpm/srk | g:315 | implemented |
| tpm.getEKCertificate | tpm/keys:134 | tpm:223 | GET /tpm/ek/certificate | g:309 | implemented |
| tpm.getEventLog | (d)/tpm/eventlog/page.tsx:76 | tpm:379 | GET /tpm/eventlog | g:310 | implemented |
| tpm.getPCRs | (d)/tpm/pcrs/page.tsx:106 | tpm:410 | POST /tpm/pcrs | g:549 | implemented |
| tpm.readNVRAM | nvram:180 | tpm:448 | GET /tpm/nvram/{index} | g:312 | implemented |
| tpm.defineNVRAM | nvram:213 | tpm:424 | POST /tpm/nvram | g:548 | implemented |
| tpm.writeNVRAM | nvram:261 | tpm:434 | PUT /tpm/nvram/{index} | g:598 | implemented |
| tpm.undefineNVRAM | nvram:288 | tpm:463 | DELETE /tpm/nvram/{index} | g:64 | implemented |
| tpm.quote | (d)/tpm/quote/page.tsx:155 | tpm:355 | POST /tpm/quote | g:552 | implemented |
| tpm.verifyQuote | quote/page.tsx:205 | tpm:365 | POST /tpm/quote/verify | g:553 | implemented |
| tpm.seal | (d)/tpm/seal/page.tsx:73 | tpm:331 | POST /tpm/seal | g:555 | implemented |
| tpm.unseal | seal/page.tsx:105 | tpm:341 | POST /tpm/unseal | g:557 | implemented |
| tpm.extendPCR | hooks/use-tpm-ops.ts:16 | tpm:491 | POST /tpm/pcrs/extend | g:550 | implemented (path at tpm:492 not yet read) |
| tpm.makeCredential | use-tpm-ops.ts:18 | tpm:509 | POST /tpm/make-credential | g:547 | implemented |
| tpm.activateCredential | use-tpm-ops.ts:21 | tpm:519 | POST /tpm/activate-credential | g:541 | implemented |
| tpm.getRandom | use-tpm-ops.ts:23 | tpm:477 | POST /tpm/random | g:554 | implemented |
| vpn.getStatus | (d)/networking/vpn/page.tsx:99 | vpn:105 | GET /vpn/status | g:321 | implemented |
| vpn.listPeers | vpn/page.tsx:106 | vpn:75 | GET /vpn/peers | g:318 | implemented |
| vpn.enrolPeer | vpn/page.tsx:162 | vpn:61 | POST /vpn/peers | g:558 | implemented |
| vpn.revokePeer | vpn/page.tsx:140 | vpn:89 | DELETE /vpn/peers/{device_id} | g:66 | implemented |
| vpn.listPosturePolicies | vpn/page.tsx:114 | vpn:168 | GET /vpn/posture-policies | g:319 | implemented |
| vpn.getPosturePolicy | vpn/page.tsx:202 | vpn:125 | GET /vpn/posture-policies/{name} | g:320 | implemented |
| vpn.setPosturePolicy | vpn/page.tsx:219 | vpn:138 | PUT /vpn/posture-policies/{name} | g:599 | implemented |
| vpn.deletePosturePolicy | vpn/page.tsx:185 | vpn:154 | DELETE /vpn/posture-policies/{name} | g:67 | implemented |
| vtpm.listBundles | (d)/devices/vtpm/page.tsx:45 | vtpm:250 | GET /vtpm/bundles | g:323 | implemented |
| vtpm.getBundle | (d)/devices/vtpm/[id]/vtpm-detail-client.tsx:72 | vtpm:212 | GET /vtpm/bundles/{id} | g:324 | implemented |
| vtpm.createBundle | features/devices/vtpm-form.tsx:57 | vtpm:202 | POST /vtpm/bundles | g:559 | implemented |
| vtpm.deleteBundle | vtpm-detail-client.tsx:107, vtpm-table.tsx:53 | vtpm:224 | DELETE /vtpm/bundles/{id} | g:68 | implemented |
| vtpm.startBundle | hooks/use-vtpm-runtime.ts:26 | vtpm:322 | POST /vtpm/bundles/{id}/start | g:564 | implemented |
| vtpm.stopBundle | use-vtpm-runtime.ts:29 | vtpm:362 | POST /vtpm/bundles/{id}/stop | g:565 | implemented |
| vtpm.quoteBundle | use-vtpm-runtime.ts:34 | vtpm:377 | POST /vtpm/bundles/{id}/quote | g:562 | implemented |
| vtpm.sealBundle | use-vtpm-runtime.ts:35 | vtpm:387 | POST /vtpm/bundles/{id}/seal | g:563 | implemented |
| vtpm.unsealBundle | use-vtpm-runtime.ts:36 | vtpm:397 | POST /vtpm/bundles/{id}/unseal | g:566 | implemented |
| vtpm.extendBundlePCR | use-vtpm-runtime.ts:38 | vtpm:419 | POST /vtpm/bundles/{id}/pcrs/extend | g:561 | implemented |
| vtpm.readBundlePCR | use-vtpm-runtime.ts:40 | vtpm:459 | GET /vtpm/bundles/{id}/pcrs?pcr_index= | g:328 | implemented (fallback `/pcr/{i}` at vtpm:465 has no route) |
| quicBaaSBackup.list | (d)/storage/backup/page.tsx:149 | quicbaas/backup:161 | GET /quicbaas/backups | router.go:329 | **stubbed** (fixed empty list) |
| quicBaaSBackup.create | backup/page.tsx:184 | quicbaas/backup:90 | POST /quicbaas/backups | router.go:331 | **stubbed** (mutationStub) |
| quicBaaSBackup.delete | backup/page.tsx:210 | quicbaas/backup:182 | DELETE /quicbaas/backups/{id} | - | **unimplemented** |
| quicBaaSBackup.restore | backup/page.tsx:234 | quicbaas/backup:115 | POST /quicbaas/backups/{id}/restore | - | **unimplemented** |
| quicBaaSObjectStorageAdmin.listBuckets | (d)/storage/objects/page.tsx:156 | quicbaas/object-storage-admin:115 | GET /quicbaas/storage/buckets | router.go:293 | **stubbed** |
| quicBaaSObjectStorageAdmin.createBucket | objects/page.tsx:236 | quicbaas/object-storage-admin:81 | POST /quicbaas/storage/buckets | router.go:295 | **stubbed** |
| quicBaaSObjectStorageAdmin.deleteBucket | objects/page.tsx:272 | quicbaas/object-storage-admin:99 | DELETE /quicbaas/storage/buckets/{name} | router.go:297 | **stubbed** |
| quicBaaSObjectStorage.listObjects | objects/page.tsx:206 | quicbaas/object-storage:165 | GET /quicbaas/storage/buckets/{b}/objects | router.go:299 | **stubbed** |
| quicBaaSObjectStorage.putObject | objects/page.tsx:305 | quicbaas/object-storage:75 | POST /quicbaas/storage/buckets/{b}/objects | - | **unimplemented** |
| quicBaaSObjectStorage.getObject | objects/page.tsx:432 | quicbaas/object-storage:111 | GET /quicbaas/storage/buckets/{b}/objects/{key} | - (DELETE only, router.go:301) | **unimplemented** |
| quicBaaSObjectStorage.deleteObject | objects/page.tsx:337 | quicbaas/object-storage:132 | DELETE /quicbaas/storage/buckets/{b}/objects/{key} | router.go:301 | **stubbed** |
| quicBaaSTimeSeries.query | (d)/storage/timeseries/page.tsx:202 | quicbaas/timeseries:109 | POST /quicbaas/timeseries/query | - | **unimplemented** |
| quicBaaSTimeSeries.aggregate | timeseries/page.tsx:168 | quicbaas/timeseries:133 | POST /quicbaas/timeseries/aggregate | - | **unimplemented** |
| quicBaaSTimeSeries.deleteRange | timeseries/page.tsx:234 | quicbaas/timeseries:159 | POST /quicbaas/timeseries/delete | - | **unimplemented** |
| ntp status (api client) | hooks/use-ntp.ts:59 | - | GET /ntp/status | g:223 | implemented |
| ntp sources (api client) | use-ntp.ts:60 | - | GET /ntp/sources | g:222 | implemented |
| ntp step (api client) | use-ntp.ts:61 | - | POST /ntp/step | g:481 | implemented |

## B. Raw `fetch(` calls

| Caller | Route | Server | Status |
|---|---|---|---|
| (d)/compute/images/page.tsx:74 | GET /api/v1/compute/images | g:115 | implemented |
| (d)/compute/images/page.tsx:100 | DELETE /api/v1/compute/images/{ref} | g:5 | implemented |
| (d)/devices/idevid/page.tsx:45 | GET /api/v1/idevid | g:186 | implemented |
| (d)/devices/idevid/page.tsx:65 | GET /api/v1/idevid/expiring | g:190 | implemented |
| (d)/networking/ipam/page.tsx:153 | GET /api/v1/sdn/gateway/ipam/pools | g:288 | implemented |
| (d)/networking/ipam/page.tsx:184 | GET /api/v1/sdn/gateway/ipam/allocations?pool_id= | g:287 | implemented |
| (d)/networking/ipam/page.tsx:245 | PUT /api/v1/sdn/gateway/ipam/pools/{id} | g:594 | implemented |
| (d)/networking/ipam/page.tsx:271 | POST /api/v1/sdn/gateway/ipam/pools | g:525 | implemented |
| (d)/networking/ipam/page.tsx:307 | DELETE /api/v1/sdn/gateway/ipam/pools/{id} | g:57 | implemented |
| (d)/networking/zones/page.tsx:256 | GET /api/v1/sdn/zones | g:293 | implemented |
| (d)/networking/zones/page.tsx:323 | PUT /api/v1/sdn/zones/{name} | g:595 | implemented |
| (d)/networking/zones/page.tsx:338 | POST /api/v1/sdn/zones | g:528 | implemented |
| (d)/networking/zones/page.tsx:374 | DELETE /api/v1/sdn/zones/{name} | g:58 | implemented |
| (d)/platform/config/page.tsx:88 | GET /api/v1/platform/config | g:238 | implemented |
| (d)/platform/config/page.tsx:108 | GET /api/v1/platform/config/snapshots | g:239 | implemented |
| (d)/platform/config/page.tsx:129 | POST /api/v1/platform/config/snapshots | g:486 | implemented |
| (d)/platform/config/page.tsx:161 | POST /api/v1/platform/config/snapshots/{id}/rollback | g:487 | implemented |
| (d)/platform/config/page.tsx:188 | DELETE /api/v1/platform/config/snapshots/{id} | g:46 | implemented |
| (d)/platform/config/page.tsx:209 | POST /api/v1/platform/config/reload | g:485 | implemented |
| (d)/platform/logs/page.tsx:107 | GET /api/v1/platform/logs/services | g:243 | implemented |
| (d)/platform/logs/page.tsx:121 | GET /api/v1/platform/logs?… | g:242 | implemented |
| app/admin/invitations/page.tsx:66 | GET /api/v1/invitations | g:195 | implemented |
| app/admin/invitations/page.tsx:102 | POST /api/v1/invitations | g:457 | implemented |
| app/admin/invitations/page.tsx:140 | DELETE /api/v1/invitations/{id} | g:38 | implemented |
| app/admin/tenant/page.tsx:45 | GET /api/v1/tenant | - (only `/tenants`, g:298) | **unimplemented** |
| app/auth/login/page.tsx:81 | POST /api/v1/login | g:214, router/authentication.go:51 (any method) | implemented |
| app/auth/login/page.tsx:109 | POST /api/v1/webauthn/login/begin | g:334, router/webauthn.go:101 | implemented |
| app/auth/login/page.tsx:125 | POST /api/v1/webauthn/login/finish | g:335, router/webauthn.go:115 | implemented |
| app/auth/webauthn/page.tsx:98 (via :306) | POST /api/v1/webauthn/registration/begin | g:336 | implemented |
| app/auth/webauthn/page.tsx:98 (via :343) | POST /api/v1/webauthn/registration/finish | g:337 | implemented |
| app/auth/webauthn/page.tsx:98 (via :396) | POST /api/v1/webauthn/login/begin | g:334 | implemented |
| app/auth/webauthn/page.tsx:98 (via :423) | POST /api/v1/webauthn/login/finish | g:335 | implemented |
| components/security/add-factor-wizard.tsx:255 | POST /api/v1/users/{id}/factors/mtls/issue-cert | - | **unimplemented** |
| components/security/add-factor-wizard.tsx:394 | POST /api/v1/webauthn/register/begin | - (server: `/webauthn/registration/begin`, g:336) | **unimplemented** |
| hooks/use-registry.ts:58 | GET /api/v1/compute/images/status | g:117 | implemented |
| hooks/use-registry.ts:98 | GET /v2/{name}/tags/list | rest/registry/ocidist.go:257 (`/v2` subrouter) | implemented (handler not yet read) |
| hooks/use-registry.ts:114 | DELETE /v2/{name}/manifests/{ref} | rest/registry/ocidist.go:257 | implemented (handler not yet read) |
| hooks/use-reported-gateways.ts:90 | GET /api/v1/gateway/state | g:160 | implemented |
| utils/auth-factors-api.ts:75 (via :106) | GET /api/v1/users/{id}/factors | router.go:290 | **stubbed** (fixed empty list) |
| utils/auth-factors-api.ts:75 (via :115) | POST /api/v1/users/{id}/factors | - | **unimplemented** |
| utils/auth-factors-api.ts:75 (via :122) | DELETE /api/v1/users/{id}/factors/{fid} | - | **unimplemented** |
| utils/auth-factors-api.ts:75 (via :132) | PUT /api/v1/users/{id}/factors/{fid}/rotate | - | **unimplemented** |
| utils/auth-factors-api.ts:75 (via :142) | PATCH /api/v1/users/{id}/factors/{fid}/label | - | **unimplemented** |
| utils/auth-factors-api.ts:75 (via :149) | PUT /api/v1/tenants/{t}/security/mfa-policy | - | **unimplemented** |
| utils/auth-factors-api.ts:201 | HEAD /api/v1/auth/mtls/probe | - | **unimplemented** |

## Counts per status (draft, before the not-configured pass)

- Table A (181 rows: 178 SDK methods, 3 NTP paths): implemented 157, unimplemented 17, stubbed 7, not-configured 0 (pending).
- Table B (45 rows covering 37 fetch sites): implemented 35, unimplemented 9, stubbed 1, not-configured 0 (pending).

## Every row that is not `implemented`

1. `ca.downloadCertificatePEM`: GET /ca/certificates/{serial}/download has no route.
2. `iam.assignRole`: the SDK posts the role in the body; the server serves only `.../users/{id}/roles/{role}`.
3. `iam.rotateAppSecret`: the SDK calls `/rotate-secret`; the server serves `/rotate`.
4. `kms.exportKey`: /kms/keys/{id}/export has no route.
5. `kms.encrypt`: the server needs `/kms/encrypt/{name}`.
6. `kms.decrypt`: the server needs `/kms/decrypt/{name}`.
7. `kms.sign`: the server needs `/kms/sign/{name}`.
8. `kms.verify`: the server needs `/kms/verify/{name}`.
9. `sdn.deleteFlow`: the SDK calls a per-bridge flow path; the server serves only DELETE /sdn/flows.
10. `sdn.deleteVLAN`: no DELETE route for VLANs.
11. `quicBaaSBackup.list`: stubbed.
12. `quicBaaSBackup.create`: stubbed.
13. `quicBaaSBackup.delete`: unimplemented.
14. `quicBaaSBackup.restore`: unimplemented.
15. `quicBaaSObjectStorageAdmin.listBuckets`: stubbed.
16. `quicBaaSObjectStorageAdmin.createBucket`: stubbed.
17. `quicBaaSObjectStorageAdmin.deleteBucket`: stubbed.
18. `quicBaaSObjectStorage.listObjects`: stubbed.
19. `quicBaaSObjectStorage.putObject`: unimplemented.
20. `quicBaaSObjectStorage.getObject`: unimplemented.
21. `quicBaaSObjectStorage.deleteObject`: stubbed.
22. `quicBaaSTimeSeries.query`: unimplemented.
23. `quicBaaSTimeSeries.aggregate`: unimplemented.
24. `quicBaaSTimeSeries.deleteRange`: unimplemented.
25. `app/admin/tenant/page.tsx:45` GET /api/v1/tenant: unimplemented.
26. `add-factor-wizard.tsx:255` mTLS issue-cert: unimplemented.
27. `add-factor-wizard.tsx:394` /webauthn/register/begin: wrong path, unimplemented.
28. `auth-factors-api` GET /users/{id}/factors: stubbed.
29. `auth-factors-api` POST /users/{id}/factors: unimplemented.
30. `auth-factors-api` DELETE /users/{id}/factors/{fid}: unimplemented.
31. `auth-factors-api` PUT /users/{id}/factors/{fid}/rotate: unimplemented.
32. `auth-factors-api` PATCH /users/{id}/factors/{fid}/label: unimplemented.
33. `auth-factors-api` PUT /tenants/{t}/security/mfa-policy: unimplemented.
34. `auth-factors-api` HEAD /auth/mtls/probe: unimplemented.

## Remaining for slice 2

- The not-configured pass: for each area whose `*Routes()` in `router.go` registers only on a non-nil server (gateway, vpn, overlay, sdn, pxe, compute, dns, ntp, vtpm and others), check the backend against `configs/platform/templates/single-node/default.yaml` and re-mark the rows.
- Read the paths not yet verified: `device:607`, `kms:123/152`, `tpm:492`, and the `/v2` handlers.
- Look for stubs inside handlers that the golden file lists as registered (Unimplemented, TODO, fixed data).
