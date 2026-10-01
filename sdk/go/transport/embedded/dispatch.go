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

package embedded

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// buildHandlerMap constructs the O(1) dispatch map from gRPC full method
// names to in-process service handler functions. Only services that are
// registered (non-nil) in the ServiceRegistry are added to the map.
func buildHandlerMap(reg *ServiceRegistry) map[string]handlerFunc {
	m := make(map[string]handlerFunc, 300)

	registerDaemonHandlers(m, reg)
	registerCAHandlers(m, reg)
	registerTPMHandlers(m, reg)
	registerVTPMHandlers(m, reg)
	registerDeviceHandlers(m, reg)
	registerIAMHandlers(m, reg)
	registerKMSHandlers(m, reg)
	registerSDNHandlers(m, reg)
	registerComputeHandlers(m, reg)
	registerIDevIDHandlers(m, reg)
	registerAttestationHandlers(m, reg)
	registerTenantHandlers(m, reg)
	registerPXEHandlers(m, reg)
	registerDNSHandlers(m, reg)
	registerGatewayHandlers(m, reg)
	registerOverlayHandlers(m, reg)
	registerRegistryHandlers(m, reg)
	registerClusterHandlers(m, reg)
	registerEABHandlers(m, reg)
	registerInvitationHandlers(m, reg)
	registerConfigDeliveryHandlers(m, reg)
	registerProxyHandlers(m, reg)

	return m
}

// registerConfigDeliveryHandlers registers ConfigDeliveryService handlers.
func registerConfigDeliveryHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.ConfigDelivery == nil {
		return
	}
	svc := reg.ConfigDelivery

	m[platformv1.ConfigDeliveryService_GetNonce_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetNonce(ctx, req.(*platformv1.GetNonceRequest))
	}
	m[platformv1.ConfigDeliveryService_FetchConfig_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FetchConfig(ctx, req.(*platformv1.FetchConfigRequest))
	}
	m[platformv1.ConfigDeliveryService_SignDigest_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SignDigest(ctx, req.(*platformv1.SignDigestRequest))
	}
	m[platformv1.ConfigDeliveryService_PollSession_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.PollSession(ctx, req.(*platformv1.PollSessionRequest))
	}
	m[platformv1.ConfigDeliveryService_FulfillSession_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FulfillSession(ctx, req.(*platformv1.FulfillSessionRequest))
	}
	m[platformv1.ConfigDeliveryService_ListSessions_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListSessions(ctx, req.(*platformv1.ListSessionsRequest))
	}
	m[platformv1.ConfigDeliveryService_GetSession_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetSession(ctx, req.(*platformv1.GetSessionRequest))
	}
}

// registerDaemonHandlers registers PlatformDaemon service handlers.
func registerDaemonHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Daemon == nil {
		return
	}
	svc := reg.Daemon

	m[platformv1.PlatformDaemon_GetStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetStatus(ctx, req.(*platformv1.GetStatusRequest))
	}
	m[platformv1.PlatformDaemon_GetHealth_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetHealth(ctx, req.(*platformv1.GetHealthRequest))
	}
	m[platformv1.PlatformDaemon_Shutdown_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Shutdown(ctx, req.(*platformv1.ShutdownRequest))
	}
	m[platformv1.PlatformDaemon_GetVersion_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetVersion(ctx, req.(*platformv1.GetVersionRequest))
	}
	m[platformv1.PlatformDaemon_GetConfig_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetConfig(ctx, req.(*platformv1.GetConfigRequest))
	}
	m[platformv1.PlatformDaemon_UpdateConfig_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateConfig(ctx, req.(*platformv1.UpdateConfigRequest))
	}
	m[platformv1.PlatformDaemon_ReloadConfig_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ReloadConfig(ctx, req.(*platformv1.ReloadConfigRequest))
	}
	m[platformv1.PlatformDaemon_StartService_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StartService(ctx, req.(*platformv1.StartServiceRequest))
	}
	m[platformv1.PlatformDaemon_StopService_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StopService(ctx, req.(*platformv1.StopServiceRequest))
	}
	m[platformv1.PlatformDaemon_RestartService_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RestartService(ctx, req.(*platformv1.RestartServiceRequest))
	}
	m[platformv1.PlatformDaemon_GetServiceStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetServiceStatus(ctx, req.(*platformv1.GetServiceStatusRequest))
	}
	m[platformv1.PlatformDaemon_ListServices_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListServices(ctx, req.(*platformv1.ListServicesRequest))
	}
	m[platformv1.PlatformDaemon_ListEntityTypes_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListEntityTypes(ctx, req.(*platformv1.ListEntityTypesRequest))
	}
	// Note: StreamEvents, StreamLogs, StreamMetrics, DumpEntityType are server-streaming
	// and not supported by the embedded transport's Invoke method.
}

// registerCAHandlers registers CAService handlers.
func registerCAHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.CA == nil {
		return
	}
	svc := reg.CA

	m[platformv1.CAService_GetCAInfo_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCAInfo(ctx, req.(*platformv1.GetCAInfoRequest))
	}
	m[platformv1.CAService_InitCA_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.InitCA(ctx, req.(*platformv1.InitCARequest))
	}
	m[platformv1.CAService_InstallCACertificates_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.InstallCACertificates(ctx, req.(*platformv1.InstallCACertificatesRequest))
	}
	m[platformv1.CAService_UninstallCACertificates_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UninstallCACertificates(ctx, req.(*platformv1.UninstallCACertificatesRequest))
	}
	m[platformv1.CAService_IssueCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.IssueCertificate(ctx, req.(*platformv1.IssueCertificateRequest))
	}
	m[platformv1.CAService_GetCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCertificate(ctx, req.(*platformv1.GetCertificateRequest))
	}
	m[platformv1.CAService_ListCertificates_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListCertificates(ctx, req.(*platformv1.ListCertificatesRequest))
	}
	m[platformv1.CAService_RevokeCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RevokeCertificate(ctx, req.(*platformv1.RevokeCertificateRequest))
	}
	m[platformv1.CAService_RenewCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RenewCertificate(ctx, req.(*platformv1.RenewCertificateRequest))
	}
	m[platformv1.CAService_VerifyCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyCertificate(ctx, req.(*platformv1.VerifyCertificateRequest))
	}
	m[platformv1.CAService_GetCRL_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCRL(ctx, req.(*platformv1.GetCRLRequest))
	}
	m[platformv1.CAService_GetCABundle_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCABundle(ctx, req.(*platformv1.GetCABundleRequest))
	}
}

// registerTPMHandlers registers TPMService handlers.
func registerTPMHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.TPM == nil {
		return
	}
	svc := reg.TPM

	m[platformv1.TPMService_Info_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Info(ctx, req.(*platformv1.TPMInfoRequest))
	}
	m[platformv1.TPMService_Provision_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Provision(ctx, req.(*platformv1.TPMProvisionRequest))
	}
	m[platformv1.TPMService_Clear_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Clear(ctx, req.(*platformv1.TPMClearRequest))
	}
	m[platformv1.TPMService_CreateEK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateEK(ctx, req.(*platformv1.CreateEKRequest))
	}
	m[platformv1.TPMService_GetEK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetEK(ctx, req.(*platformv1.GetEKRequest))
	}
	m[platformv1.TPMService_GetEKCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetEKCertificate(ctx, req.(*platformv1.GetEKCertificateRequest))
	}
	m[platformv1.TPMService_ImportEKCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ImportEKCertificate(ctx, req.(*platformv1.ImportEKCertificateRequest))
	}
	m[platformv1.TPMService_DeleteEK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteEK(ctx, req.(*platformv1.DeleteEKRequest))
	}
	m[platformv1.TPMService_CreateSRK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateSRK(ctx, req.(*platformv1.CreateSRKRequest))
	}
	m[platformv1.TPMService_GetSRK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetSRK(ctx, req.(*platformv1.GetSRKRequest))
	}
	m[platformv1.TPMService_DeleteSRK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteSRK(ctx, req.(*platformv1.DeleteSRKRequest))
	}
	m[platformv1.TPMService_CreateAK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateAK(ctx, req.(*platformv1.CreateAKRequest))
	}
	m[platformv1.TPMService_GetAK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetAK(ctx, req.(*platformv1.GetAKRequest))
	}
	m[platformv1.TPMService_DeleteAK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteAK(ctx, req.(*platformv1.DeleteAKRequest))
	}
	m[platformv1.TPMService_Seal_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Seal(ctx, req.(*platformv1.SealRequest))
	}
	m[platformv1.TPMService_Unseal_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Unseal(ctx, req.(*platformv1.UnsealRequest))
	}
	m[platformv1.TPMService_Quote_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Quote(ctx, req.(*platformv1.QuoteRequest))
	}
	m[platformv1.TPMService_VerifyQuote_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyQuote(ctx, req.(*platformv1.VerifyQuoteRequest))
	}
	m[platformv1.TPMService_GetEventLog_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetEventLog(ctx, req.(*platformv1.GetEventLogRequest))
	}
	m[platformv1.TPMService_GetPCRs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPCRs(ctx, req.(*platformv1.GetPCRsRequest))
	}
	m[platformv1.TPMService_DefineNVRAM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DefineNVRAM(ctx, req.(*platformv1.DefineNVRAMRequest))
	}
	m[platformv1.TPMService_WriteNVRAM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.WriteNVRAM(ctx, req.(*platformv1.WriteNVRAMRequest))
	}
	m[platformv1.TPMService_ReadNVRAM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ReadNVRAM(ctx, req.(*platformv1.ReadNVRAMRequest))
	}
	m[platformv1.TPMService_UndefineNVRAM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UndefineNVRAM(ctx, req.(*platformv1.UndefineNVRAMRequest))
	}
	m[platformv1.TPMService_GetRandom_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetRandom(ctx, req.(*platformv1.GetRandomRequest))
	}
}

// registerVTPMHandlers registers VTPMService handlers.
func registerVTPMHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.VTPM == nil {
		return
	}
	svc := reg.VTPM

	m[platformv1.VTPMService_CreateBundle_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateBundle(ctx, req.(*platformv1.CreateBundleRequest))
	}
	m[platformv1.VTPMService_GetBundle_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetBundle(ctx, req.(*platformv1.GetBundleRequest))
	}
	m[platformv1.VTPMService_DeleteBundle_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteBundle(ctx, req.(*platformv1.DeleteBundleRequest))
	}
	m[platformv1.VTPMService_ListBundles_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListBundles(ctx, req.(*platformv1.ListBundlesRequest))
	}
	m[platformv1.VTPMService_CreateTemplate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateTemplate(ctx, req.(*platformv1.CreateTemplateRequest))
	}
	m[platformv1.VTPMService_GetTemplate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTemplate(ctx, req.(*platformv1.GetTemplateRequest))
	}
	m[platformv1.VTPMService_DeleteTemplate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteTemplate(ctx, req.(*platformv1.DeleteTemplateRequest))
	}
	m[platformv1.VTPMService_ListTemplates_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListTemplates(ctx, req.(*platformv1.ListTemplatesRequest))
	}
	m[platformv1.VTPMService_CloneTemplate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CloneTemplate(ctx, req.(*platformv1.CloneTemplateRequest))
	}
	m[platformv1.VTPMService_ValidateBundle_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ValidateBundle(ctx, req.(*platformv1.ValidateBundleRequest))
	}
	m[platformv1.VTPMService_GetBundlePath_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetBundlePath(ctx, req.(*platformv1.GetBundlePathRequest))
	}
	m[platformv1.VTPMService_GetTPMSocketPath_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTPMSocketPath(ctx, req.(*platformv1.GetTPMSocketPathRequest))
	}
	m[platformv1.VTPMService_GetNVRAMPath_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetNVRAMPath(ctx, req.(*platformv1.GetNVRAMPathRequest))
	}
	m[platformv1.VTPMService_StartVTPM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StartVTPM(ctx, req.(*platformv1.StartVTPMRequest))
	}
	m[platformv1.VTPMService_StopVTPM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StopVTPM(ctx, req.(*platformv1.StopVTPMRequest))
	}
	m[platformv1.VTPMService_IsVTPMRunning_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.IsVTPMRunning(ctx, req.(*platformv1.IsVTPMRunningRequest))
	}
	m[platformv1.VTPMService_QuoteVTPM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.QuoteVTPM(ctx, req.(*platformv1.QuoteVTPMRequest))
	}
	m[platformv1.VTPMService_SealVTPM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SealVTPM(ctx, req.(*platformv1.SealVTPMRequest))
	}
	m[platformv1.VTPMService_UnsealVTPM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UnsealVTPM(ctx, req.(*platformv1.UnsealVTPMRequest))
	}
	m[platformv1.VTPMService_ExtendVTPMPCR_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ExtendVTPMPCR(ctx, req.(*platformv1.ExtendVTPMPCRRequest))
	}
	m[platformv1.VTPMService_ReadVTPMPCR_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ReadVTPMPCR(ctx, req.(*platformv1.ReadVTPMPCRRequest))
	}
	// Note: ExportBundle is server-streaming and not supported by Invoke.
}

// registerDeviceHandlers registers DeviceService handlers.
func registerDeviceHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Device == nil {
		return
	}
	svc := reg.Device

	m[platformv1.DeviceService_CreateDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateDevice(ctx, req.(*platformv1.CreateDeviceRequest))
	}
	m[platformv1.DeviceService_GetDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetDevice(ctx, req.(*platformv1.GetDeviceRequest))
	}
	m[platformv1.DeviceService_UpdateDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateDevice(ctx, req.(*platformv1.UpdateDeviceRequest))
	}
	m[platformv1.DeviceService_DeleteDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteDevice(ctx, req.(*platformv1.DeleteDeviceRequest))
	}
	m[platformv1.DeviceService_ListDevices_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListDevices(ctx, req.(*platformv1.ListDevicesRequest))
	}
	m[platformv1.DeviceService_FindDeviceBySerial_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FindDeviceBySerial(ctx, req.(*platformv1.FindDeviceBySerialRequest))
	}
	m[platformv1.DeviceService_CountDevices_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CountDevices(ctx, req.(*platformv1.CountDevicesRequest))
	}
	m[platformv1.DeviceService_CreateProfile_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateProfile(ctx, req.(*platformv1.CreateProfileRequest))
	}
	m[platformv1.DeviceService_GetProfile_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetProfile(ctx, req.(*platformv1.GetProfileRequest))
	}
	m[platformv1.DeviceService_UpdateProfile_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateProfile(ctx, req.(*platformv1.UpdateProfileRequest))
	}
	m[platformv1.DeviceService_DeleteProfile_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteProfile(ctx, req.(*platformv1.DeleteProfileRequest))
	}
	m[platformv1.DeviceService_ListProfiles_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListProfiles(ctx, req.(*platformv1.ListProfilesRequest))
	}
	m[platformv1.DeviceService_FindProfileByMACAddress_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FindProfileByMACAddress(ctx, req.(*platformv1.FindProfileByMACAddressRequest))
	}
	m[platformv1.DeviceService_FindProfileBySerial_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FindProfileBySerial(ctx, req.(*platformv1.FindProfileBySerialRequest))
	}
	m[platformv1.DeviceService_FindMatchingProfile_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FindMatchingProfile(ctx, req.(*platformv1.FindMatchingProfileRequest))
	}
	m[platformv1.DeviceService_CountProfiles_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CountProfiles(ctx, req.(*platformv1.CountProfilesRequest))
	}
	m[platformv1.DeviceService_ActivateDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ActivateDevice(ctx, req.(*platformv1.ActivateDeviceRequest))
	}
}

// registerIAMHandlers registers PlatformIAMService handlers.
func registerIAMHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.IAM == nil {
		return
	}
	svc := reg.IAM

	m[platformv1.PlatformIAMService_CreateUser_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateUser(ctx, req.(*platformv1.CreateIAMUserRequest))
	}
	m[platformv1.PlatformIAMService_GetUser_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetUser(ctx, req.(*platformv1.GetIAMUserRequest))
	}
	m[platformv1.PlatformIAMService_ListUsers_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListUsers(ctx, req.(*platformv1.ListIAMUsersRequest))
	}
	m[platformv1.PlatformIAMService_UpdateUser_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateUser(ctx, req.(*platformv1.UpdateIAMUserRequest))
	}
	m[platformv1.PlatformIAMService_DeleteUser_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteUser(ctx, req.(*platformv1.DeleteIAMUserRequest))
	}
	m[platformv1.PlatformIAMService_CreateRole_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateRole(ctx, req.(*platformv1.CreateIAMRoleRequest))
	}
	m[platformv1.PlatformIAMService_GetRole_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetRole(ctx, req.(*platformv1.GetIAMRoleRequest))
	}
	m[platformv1.PlatformIAMService_ListRoles_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListRoles(ctx, req.(*platformv1.ListIAMRolesRequest))
	}
	m[platformv1.PlatformIAMService_UpdateRole_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateRole(ctx, req.(*platformv1.UpdateIAMRoleRequest))
	}
	m[platformv1.PlatformIAMService_DeleteRole_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteRole(ctx, req.(*platformv1.DeleteIAMRoleRequest))
	}
	m[platformv1.PlatformIAMService_AssignRole_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AssignRole(ctx, req.(*platformv1.AssignIAMRoleRequest))
	}
	m[platformv1.PlatformIAMService_RevokeRole_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RevokeRole(ctx, req.(*platformv1.RevokeIAMRoleRequest))
	}
	m[platformv1.PlatformIAMService_CreateGroup_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateGroup(ctx, req.(*platformv1.CreateIAMGroupRequest))
	}
	m[platformv1.PlatformIAMService_GetGroup_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetGroup(ctx, req.(*platformv1.GetIAMGroupRequest))
	}
	m[platformv1.PlatformIAMService_ListGroups_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListGroups(ctx, req.(*platformv1.ListIAMGroupsRequest))
	}
	m[platformv1.PlatformIAMService_UpdateGroup_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateGroup(ctx, req.(*platformv1.UpdateIAMGroupRequest))
	}
	m[platformv1.PlatformIAMService_DeleteGroup_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteGroup(ctx, req.(*platformv1.DeleteIAMGroupRequest))
	}
	m[platformv1.PlatformIAMService_AddGroupMember_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AddGroupMember(ctx, req.(*platformv1.AddGroupMemberRequest))
	}
	m[platformv1.PlatformIAMService_RemoveGroupMember_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RemoveGroupMember(ctx, req.(*platformv1.RemoveGroupMemberRequest))
	}
	m[platformv1.PlatformIAMService_CheckPermission_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CheckPermission(ctx, req.(*platformv1.CheckIAMPermissionRequest))
	}
	m[platformv1.PlatformIAMService_CreateToken_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateToken(ctx, req.(*platformv1.CreateIAMTokenRequest))
	}
	m[platformv1.PlatformIAMService_RevokeToken_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RevokeToken(ctx, req.(*platformv1.RevokeIAMTokenRequest))
	}
	m[platformv1.PlatformIAMService_VerifyToken_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyToken(ctx, req.(*platformv1.VerifyIAMTokenRequest))
	}
	m[platformv1.PlatformIAMService_CreateTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateTenant(ctx, req.(*platformv1.CreateIAMTenantRequest))
	}
	m[platformv1.PlatformIAMService_GetTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTenant(ctx, req.(*platformv1.GetIAMTenantRequest))
	}
	m[platformv1.PlatformIAMService_ListTenants_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListTenants(ctx, req.(*platformv1.ListIAMTenantsRequest))
	}
	m[platformv1.PlatformIAMService_UpdateTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateTenant(ctx, req.(*platformv1.UpdateIAMTenantRequest))
	}
	m[platformv1.PlatformIAMService_DeleteTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteTenant(ctx, req.(*platformv1.DeleteIAMTenantRequest))
	}
	m[platformv1.PlatformIAMService_CreatePolicy_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreatePolicy(ctx, req.(*platformv1.CreateIAMPolicyRequest))
	}
	m[platformv1.PlatformIAMService_GetPolicy_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPolicy(ctx, req.(*platformv1.GetIAMPolicyRequest))
	}
	m[platformv1.PlatformIAMService_ListPolicies_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListPolicies(ctx, req.(*platformv1.ListIAMPoliciesRequest))
	}
	m[platformv1.PlatformIAMService_UpdatePolicy_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdatePolicy(ctx, req.(*platformv1.UpdateIAMPolicyRequest))
	}
	m[platformv1.PlatformIAMService_DeletePolicy_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeletePolicy(ctx, req.(*platformv1.DeleteIAMPolicyRequest))
	}
	m[platformv1.PlatformIAMService_ValidatePolicy_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ValidatePolicy(ctx, req.(*platformv1.ValidateIAMPolicyRequest))
	}
	m[platformv1.PlatformIAMService_TestPolicy_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.TestPolicy(ctx, req.(*platformv1.TestIAMPolicyRequest))
	}
	m[platformv1.PlatformIAMService_RegisterApp_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RegisterApp(ctx, req.(*platformv1.RegisterIAMAppRequest))
	}
	m[platformv1.PlatformIAMService_GetApp_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetApp(ctx, req.(*platformv1.GetIAMAppRequest))
	}
	m[platformv1.PlatformIAMService_ListApps_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListApps(ctx, req.(*platformv1.ListIAMAppsRequest))
	}
	m[platformv1.PlatformIAMService_UpdateApp_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateApp(ctx, req.(*platformv1.UpdateIAMAppRequest))
	}
	m[platformv1.PlatformIAMService_DeleteApp_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteApp(ctx, req.(*platformv1.DeleteIAMAppRequest))
	}
	m[platformv1.PlatformIAMService_RotateAppSecret_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RotateAppSecret(ctx, req.(*platformv1.RotateIAMAppSecretRequest))
	}
}

// registerKMSHandlers registers KeyManagementService handlers.
func registerKMSHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.KMS == nil {
		return
	}
	svc := reg.KMS

	m[platformv1.KeyManagementService_GenerateKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GenerateKey(ctx, req.(*platformv1.GenerateKeyRequest))
	}
	m[platformv1.KeyManagementService_ImportKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ImportKey(ctx, req.(*platformv1.ImportKeyRequest))
	}
	m[platformv1.KeyManagementService_GetKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetKey(ctx, req.(*platformv1.GetKeyRequest))
	}
	m[platformv1.KeyManagementService_ListKeys_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListKeys(ctx, req.(*platformv1.ListKeysRequest))
	}
	m[platformv1.KeyManagementService_DeleteKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteKey(ctx, req.(*platformv1.DeleteKeyRequest))
	}
	m[platformv1.KeyManagementService_RotateKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RotateKey(ctx, req.(*platformv1.RotateKeyRequest))
	}
	m[platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateKeyStatus(ctx, req.(*platformv1.UpdateKeyStatusRequest))
	}
	m[platformv1.KeyManagementService_ExportKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ExportKey(ctx, req.(*platformv1.ExportKeyRequest))
	}
	m[platformv1.KeyManagementService_GetKeyVersions_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetKeyVersions(ctx, req.(*platformv1.GetKeyVersionsRequest))
	}
	m[platformv1.KeyManagementService_Encrypt_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Encrypt(ctx, req.(*platformv1.EncryptRequest))
	}
	m[platformv1.KeyManagementService_Decrypt_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Decrypt(ctx, req.(*platformv1.DecryptRequest))
	}
	m[platformv1.KeyManagementService_BatchEncrypt_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.BatchEncrypt(ctx, req.(*platformv1.BatchEncryptRequest))
	}
	m[platformv1.KeyManagementService_BatchDecrypt_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.BatchDecrypt(ctx, req.(*platformv1.BatchDecryptRequest))
	}
	m[platformv1.KeyManagementService_Rewrap_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Rewrap(ctx, req.(*platformv1.RewrapRequest))
	}
	m[platformv1.KeyManagementService_Sign_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Sign(ctx, req.(*platformv1.SignRequest))
	}
	m[platformv1.KeyManagementService_Verify_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Verify(ctx, req.(*platformv1.VerifyRequest))
	}
	m[platformv1.KeyManagementService_Hash_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Hash(ctx, req.(*platformv1.HashRequest))
	}
	m[platformv1.KeyManagementService_HMAC_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.HMAC(ctx, req.(*platformv1.HMACRequest))
	}
	m[platformv1.KeyManagementService_VerifyHMAC_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyHMAC(ctx, req.(*platformv1.VerifyHMACRequest))
	}
	m[platformv1.KeyManagementService_GenerateRandom_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GenerateRandom(ctx, req.(*platformv1.GenerateRandomRequest))
	}
	m[platformv1.KeyManagementService_GenerateDataKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GenerateDataKey(ctx, req.(*platformv1.GenerateDataKeyRequest))
	}
	m[platformv1.KeyManagementService_GenerateWrappedDataKey_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GenerateWrappedDataKey(ctx, req.(*platformv1.GenerateWrappedDataKeyRequest))
	}
	m[platformv1.KeyManagementService_BackendStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.BackendStatus(ctx, req.(*platformv1.BackendStatusRequest))
	}
}

// registerSDNHandlers registers SDNService handlers.
func registerSDNHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.SDN == nil {
		return
	}
	svc := reg.SDN

	m[platformv1.SDNService_CreateBridge_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateBridge(ctx, req.(*platformv1.CreateBridgeRequest))
	}
	m[platformv1.SDNService_DeleteBridge_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteBridge(ctx, req.(*platformv1.DeleteBridgeRequest))
	}
	m[platformv1.SDNService_GetBridge_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetBridge(ctx, req.(*platformv1.GetBridgeRequest))
	}
	m[platformv1.SDNService_ListBridges_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListBridges(ctx, req.(*platformv1.ListBridgesRequest))
	}
	m[platformv1.SDNService_AddPort_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AddPort(ctx, req.(*platformv1.AddPortRequest))
	}
	m[platformv1.SDNService_DeletePort_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeletePort(ctx, req.(*platformv1.DeletePortRequest))
	}
	m[platformv1.SDNService_GetPort_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPort(ctx, req.(*platformv1.GetPortRequest))
	}
	m[platformv1.SDNService_ListPorts_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListPorts(ctx, req.(*platformv1.ListPortsRequest))
	}
	m[platformv1.SDNService_AddFlow_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AddFlow(ctx, req.(*platformv1.AddFlowRequest))
	}
	m[platformv1.SDNService_DeleteFlow_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteFlow(ctx, req.(*platformv1.DeleteFlowRequest))
	}
	m[platformv1.SDNService_ListFlows_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListFlows(ctx, req.(*platformv1.ListFlowsRequest))
	}
	m[platformv1.SDNService_FlushFlows_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FlushFlows(ctx, req.(*platformv1.FlushFlowsRequest))
	}
	m[platformv1.SDNService_CreateVLAN_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateVLAN(ctx, req.(*platformv1.CreateVLANRequest))
	}
	m[platformv1.SDNService_DeleteVLAN_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteVLAN(ctx, req.(*platformv1.DeleteVLANRequest))
	}
	m[platformv1.SDNService_ListVLANs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListVLANs(ctx, req.(*platformv1.ListVLANsRequest))
	}
	m[platformv1.SDNService_AuthenticatePort_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AuthenticatePort(ctx, req.(*platformv1.AuthenticatePortRequest))
	}
	m[platformv1.SDNService_RevokePortAuth_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RevokePortAuth(ctx, req.(*platformv1.RevokePortAuthRequest))
	}
	m[platformv1.SDNService_GetPortStats_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPortStats(ctx, req.(*platformv1.GetPortStatsRequest))
	}
	m[platformv1.SDNService_GetFlowStats_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetFlowStats(ctx, req.(*platformv1.GetFlowStatsRequest))
	}
	m[platformv1.SDNService_CreateNetworkZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateNetworkZone(ctx, req.(*platformv1.CreateNetworkZoneRequest))
	}
	m[platformv1.SDNService_UpdateNetworkZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateNetworkZone(ctx, req.(*platformv1.UpdateNetworkZoneRequest))
	}
	m[platformv1.SDNService_DeleteNetworkZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteNetworkZone(ctx, req.(*platformv1.DeleteNetworkZoneRequest))
	}
	m[platformv1.SDNService_ListNetworkZones_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListNetworkZones(ctx, req.(*platformv1.ListNetworkZonesRequest))
	}
	// Note: StreamFlowLogs is server-streaming and not supported by Invoke.
}

// registerComputeHandlers registers ComputeService handlers (unary only).
func registerComputeHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Compute == nil {
		return
	}
	svc := reg.Compute

	m[platformv1.ComputeService_CreateVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateVM(ctx, req.(*platformv1.CreateVMRequest))
	}
	m[platformv1.ComputeService_StartVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StartVM(ctx, req.(*platformv1.StartVMRequest))
	}
	m[platformv1.ComputeService_StopVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StopVM(ctx, req.(*platformv1.StopVMRequest))
	}
	m[platformv1.ComputeService_RebootVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RebootVM(ctx, req.(*platformv1.RebootVMRequest))
	}
	m[platformv1.ComputeService_DeleteVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteVM(ctx, req.(*platformv1.DeleteVMRequest))
	}
	m[platformv1.ComputeService_GetVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetVM(ctx, req.(*platformv1.GetVMRequest))
	}
	m[platformv1.ComputeService_ListVMs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListVMs(ctx, req.(*platformv1.ListVMsRequest))
	}
	m[platformv1.ComputeService_GetVMMetrics_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetVMMetrics(ctx, req.(*platformv1.GetVMMetricsRequest))
	}
	m[platformv1.ComputeService_AttachDisk_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AttachDisk(ctx, req.(*platformv1.AttachDiskRequest))
	}
	m[platformv1.ComputeService_DetachDisk_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DetachDisk(ctx, req.(*platformv1.DetachDiskRequest))
	}
	m[platformv1.ComputeService_ResizeDisk_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ResizeDisk(ctx, req.(*platformv1.ResizeDiskRequest))
	}
	m[platformv1.ComputeService_CreateSnapshot_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateSnapshot(ctx, req.(*platformv1.CreateSnapshotRequest))
	}
	m[platformv1.ComputeService_RestoreSnapshot_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RestoreSnapshot(ctx, req.(*platformv1.RestoreSnapshotRequest))
	}
	m[platformv1.ComputeService_DeleteSnapshot_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteSnapshot(ctx, req.(*platformv1.DeleteSnapshotRequest))
	}
	m[platformv1.ComputeService_ListSnapshots_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListSnapshots(ctx, req.(*platformv1.ListSnapshotsRequest))
	}
	m[platformv1.ComputeService_MigrateVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.MigrateVM(ctx, req.(*platformv1.MigrateVMRequest))
	}
	m[platformv1.ComputeService_CreateContainer_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateContainer(ctx, req.(*platformv1.CreateContainerRequest))
	}
	m[platformv1.ComputeService_StartContainer_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StartContainer(ctx, req.(*platformv1.StartContainerRequest))
	}
	m[platformv1.ComputeService_StopContainer_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StopContainer(ctx, req.(*platformv1.StopContainerRequest))
	}
	m[platformv1.ComputeService_DeleteContainer_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteContainer(ctx, req.(*platformv1.DeleteContainerRequest))
	}
	m[platformv1.ComputeService_GetContainer_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetContainer(ctx, req.(*platformv1.GetContainerRequest))
	}
	m[platformv1.ComputeService_ListContainers_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListContainers(ctx, req.(*platformv1.ListContainersRequest))
	}
	m[platformv1.ComputeService_ExecContainer_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ExecContainer(ctx, req.(*platformv1.ExecContainerRequest))
	}
	m[platformv1.ComputeService_GetContainerMetrics_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetContainerMetrics(ctx, req.(*platformv1.GetContainerMetricsRequest))
	}
	m[platformv1.ComputeService_AttestVM_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AttestVM(ctx, req.(*platformv1.AttestVMRequest))
	}
	m[platformv1.ComputeService_VerifyVMAttestation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyVMAttestation(ctx, req.(*platformv1.VerifyVMAttestationRequest))
	}
	// Note: AttachVMConsole, GetVMLogs, AttachContainer, GetContainerLogs
	// are server-streaming and not supported by Invoke.
}

// registerIDevIDHandlers registers IDevIDService handlers.
func registerIDevIDHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.IDevID == nil {
		return
	}
	svc := reg.IDevID

	m[platformv1.IDevIDService_GenerateIDevID_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GenerateIDevID(ctx, req.(*platformv1.GenerateIDevIDRequest))
	}
	m[platformv1.IDevIDService_GetIDevIDInfo_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetIDevIDInfo(ctx, req.(*platformv1.GetIDevIDInfoRequest))
	}
	m[platformv1.IDevIDService_HasIDevID_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.HasIDevID(ctx, req.(*platformv1.HasIDevIDRequest))
	}
	m[platformv1.IDevIDService_DeleteIDevID_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteIDevID(ctx, req.(*platformv1.DeleteIDevIDRequest))
	}
	m[platformv1.IDevIDService_GenerateIAK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GenerateIAK(ctx, req.(*platformv1.GenerateIAKRequest))
	}
	m[platformv1.IDevIDService_GetIAKInfo_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetIAKInfo(ctx, req.(*platformv1.GetIAKInfoRequest))
	}
	m[platformv1.IDevIDService_HasIAK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.HasIAK(ctx, req.(*platformv1.HasIAKRequest))
	}
	m[platformv1.IDevIDService_DeleteIAK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteIAK(ctx, req.(*platformv1.DeleteIAKRequest))
	}
	m[platformv1.IDevIDService_CreateIDevIDCSR_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateIDevIDCSR(ctx, req.(*platformv1.CreateIDevIDCSRRequest))
	}
	m[platformv1.IDevIDService_CreateIAKCSR_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateIAKCSR(ctx, req.(*platformv1.CreateIAKCSRRequest))
	}
	m[platformv1.IDevIDService_CreateLDevID_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateLDevID(ctx, req.(*platformv1.CreateLDevIDRequest))
	}
	m[platformv1.IDevIDService_InstallIDevIDCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.InstallIDevIDCertificate(ctx, req.(*platformv1.InstallIDevIDCertificateRequest))
	}
	m[platformv1.IDevIDService_InstallIAKCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.InstallIAKCertificate(ctx, req.(*platformv1.InstallIAKCertificateRequest))
	}
	m[platformv1.IDevIDService_GetIDevIDCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetIDevIDCertificate(ctx, req.(*platformv1.GetIDevIDCertificateRequest))
	}
	m[platformv1.IDevIDService_GetIAKCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetIAKCertificate(ctx, req.(*platformv1.GetIAKCertificateRequest))
	}
	m[platformv1.IDevIDService_DeleteIDevIDCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteIDevIDCertificate(ctx, req.(*platformv1.DeleteIDevIDCertificateRequest))
	}
	m[platformv1.IDevIDService_DeleteIAKCertificate_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteIAKCertificate(ctx, req.(*platformv1.DeleteIAKCertificateRequest))
	}
	m[platformv1.IDevIDService_GetDeviceAttributes_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetDeviceAttributes(ctx, req.(*platformv1.GetDeviceAttributesRequest))
	}
	m[platformv1.IDevIDService_FlushTransientContexts_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.FlushTransientContexts(ctx, req.(*platformv1.FlushTransientContextsRequest))
	}
	m[platformv1.IDevIDService_ActivateCredential_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ActivateCredential(ctx, req.(*platformv1.ActivateCredentialRequest))
	}
}

// registerAttestationHandlers registers AttestationService handlers.
func registerAttestationHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Attestation == nil {
		return
	}
	svc := reg.Attestation

	m[platformv1.AttestationService_GetManifest_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetManifest(ctx, req.(*platformv1.GetManifestRequest))
	}
	m[platformv1.AttestationService_BuildManifest_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.BuildManifest(ctx, req.(*platformv1.BuildManifestRequest))
	}
	m[platformv1.AttestationService_VerifyManifest_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyManifest(ctx, req.(*platformv1.VerifyManifestRequest))
	}
	m[platformv1.AttestationService_ListManifests_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListManifests(ctx, req.(*platformv1.ListManifestsRequest))
	}
	m[platformv1.AttestationService_DeleteManifest_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteManifest(ctx, req.(*platformv1.DeleteManifestRequest))
	}
	m[platformv1.AttestationService_GetAttestationQuote_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetAttestationQuote(ctx, req.(*platformv1.GetAttestationQuoteRequest))
	}
	m[platformv1.AttestationService_VerifyAttestationQuote_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.VerifyAttestationQuote(ctx, req.(*platformv1.VerifyAttestationQuoteRequest))
	}
	m[platformv1.AttestationService_CollectHostAttestation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CollectHostAttestation(ctx, req.(*platformv1.CollectHostAttestationRequest))
	}
	m[platformv1.AttestationService_CollectVMAttestation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CollectVMAttestation(ctx, req.(*platformv1.CollectVMAttestationRequest))
	}
	m[platformv1.AttestationService_CollectContainerAttestation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CollectContainerAttestation(ctx, req.(*platformv1.CollectContainerAttestationRequest))
	}
}

// registerTenantHandlers registers TenantService handlers.
func registerTenantHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Tenant == nil {
		return
	}
	svc := reg.Tenant

	m[platformv1.TenantService_ListTenants_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListTenants(ctx, req.(*platformv1.ListTenantsRequest))
	}
	m[platformv1.TenantService_GetTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTenant(ctx, req.(*platformv1.GetTenantRequest))
	}
	m[platformv1.TenantService_GetTenantByName_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTenantByName(ctx, req.(*platformv1.GetTenantByNameRequest))
	}
	m[platformv1.TenantService_CreateTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateTenant(ctx, req.(*platformv1.CreateTenantRequest))
	}
	m[platformv1.TenantService_UpdateTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateTenant(ctx, req.(*platformv1.UpdateTenantRequest))
	}
	m[platformv1.TenantService_DeleteTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteTenant(ctx, req.(*platformv1.DeleteTenantRequest))
	}
	m[platformv1.TenantService_SuspendTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SuspendTenant(ctx, req.(*platformv1.SuspendTenantRequest))
	}
	m[platformv1.TenantService_ResumeTenant_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ResumeTenant(ctx, req.(*platformv1.ResumeTenantRequest))
	}
	m[platformv1.TenantService_GetQuotas_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetQuotas(ctx, req.(*platformv1.GetQuotasRequest))
	}
	m[platformv1.TenantService_UpdateQuotas_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateQuotas(ctx, req.(*platformv1.UpdateQuotasRequest))
	}
	m[platformv1.TenantService_GetUsage_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetUsage(ctx, req.(*platformv1.GetUsageRequest))
	}
	m[platformv1.TenantService_CheckQuota_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CheckQuota(ctx, req.(*platformv1.CheckQuotaRequest))
	}
	m[platformv1.TenantService_Sync_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Sync(ctx, req.(*platformv1.SyncTenantsRequest))
	}
	m[platformv1.TenantService_RotateTenantDEK_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RotateTenantDEK(ctx, req.(*platformv1.RotateTenantDEKRequest))
	}
	m[platformv1.TenantService_GetTenantDEKStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTenantDEKStatus(ctx, req.(*platformv1.GetTenantDEKStatusRequest))
	}
}

// registerPXEHandlers registers PXEService handlers.
func registerPXEHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.PXE == nil {
		return
	}
	svc := reg.PXE

	m[platformv1.PXEService_RegisterDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RegisterDevice(ctx, req.(*platformv1.RegisterPXEDeviceRequest))
	}
	m[platformv1.PXEService_GetDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetDevice(ctx, req.(*platformv1.GetPXEDeviceRequest))
	}
	m[platformv1.PXEService_GetDeviceByMAC_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetDeviceByMAC(ctx, req.(*platformv1.GetPXEDeviceByMACRequest))
	}
	m[platformv1.PXEService_ListDevices_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListDevices(ctx, req.(*platformv1.ListPXEDevicesRequest))
	}
	m[platformv1.PXEService_RemoveDevice_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RemoveDevice(ctx, req.(*platformv1.RemovePXEDeviceRequest))
	}
	m[platformv1.PXEService_UpdateState_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateState(ctx, req.(*platformv1.UpdatePXEStateRequest))
	}
	m[platformv1.PXEService_SetDeviceEnrolled_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SetDeviceEnrolled(ctx, req.(*platformv1.SetPXEDeviceEnrolledRequest))
	}
	m[platformv1.PXEService_Authorize_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Authorize(ctx, req.(*platformv1.AuthorizePXEDeviceRequest))
	}
	m[platformv1.PXEService_Quarantine_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Quarantine(ctx, req.(*platformv1.QuarantinePXEDeviceRequest))
	}
	m[platformv1.PXEService_Retry_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Retry(ctx, req.(*platformv1.RetryPXEDeviceRequest))
	}
	m[platformv1.PXEService_GetEvents_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetEvents(ctx, req.(*platformv1.GetPXEEventsRequest))
	}
	m[platformv1.PXEService_GetStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetStatus(ctx, req.(*platformv1.GetPXEStatusRequest))
	}
	m[platformv1.PXEService_StartService_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StartService(ctx, req.(*platformv1.StartPXEServiceRequest))
	}
	m[platformv1.PXEService_StopService_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.StopService(ctx, req.(*platformv1.StopPXEServiceRequest))
	}
	m[platformv1.PXEService_WebhookComplete_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.WebhookComplete(ctx, req.(*platformv1.PXEWebhookCompleteRequest))
	}
}

// registerDNSHandlers registers DNSService handlers.
func registerDNSHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.DNS == nil {
		return
	}
	svc := reg.DNS

	m[platformv1.DNSService_CreateZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateZone(ctx, req.(*platformv1.CreateZoneRequest))
	}
	m[platformv1.DNSService_GetZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetZone(ctx, req.(*platformv1.GetZoneRequest))
	}
	m[platformv1.DNSService_UpdateZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateZone(ctx, req.(*platformv1.UpdateZoneRequest))
	}
	m[platformv1.DNSService_DeleteZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteZone(ctx, req.(*platformv1.DeleteZoneRequest))
	}
	m[platformv1.DNSService_ListZones_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListZones(ctx, req.(*platformv1.ListZonesRequest))
	}
	m[platformv1.DNSService_AddRecord_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AddRecord(ctx, req.(*platformv1.AddRecordRequest))
	}
	m[platformv1.DNSService_DeleteRecord_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteRecord(ctx, req.(*platformv1.DeleteRecordRequest))
	}
	m[platformv1.DNSService_UpdateRecord_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateRecord(ctx, req.(*platformv1.UpdateRecordRequest))
	}
	m[platformv1.DNSService_ListRecords_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListRecords(ctx, req.(*platformv1.ListRecordsRequest))
	}
	m[platformv1.DNSService_SignZone_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SignZone(ctx, req.(*platformv1.SignZoneRequest))
	}
	m[platformv1.DNSService_GetDNSSECStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetDNSSECStatus(ctx, req.(*platformv1.GetDNSSECStatusRequest))
	}
	m[platformv1.DNSService_Resolve_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Resolve(ctx, req.(*platformv1.ResolveRequest))
	}
	m[platformv1.DNSService_Register_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Register(ctx, req.(*platformv1.RegisterRequest))
	}
}

// registerGatewayHandlers registers GatewayService handlers.
func registerGatewayHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Gateway == nil {
		return
	}
	svc := reg.Gateway

	m[platformv1.GatewayService_GetGatewayStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetGatewayStatus(ctx, req.(*platformv1.GetGatewayStatusRequest))
	}
	m[platformv1.GatewayService_SetGatewayMode_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SetGatewayMode(ctx, req.(*platformv1.SetGatewayModeRequest))
	}
	m[platformv1.GatewayService_GetBGPStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetBGPStatus(ctx, req.(*platformv1.GetBGPStatusRequest))
	}
	m[platformv1.GatewayService_ListBGPPeers_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListBGPPeers(ctx, req.(*platformv1.ListBGPPeersRequest))
	}
	m[platformv1.GatewayService_AnnouncePrefix_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AnnouncePrefix(ctx, req.(*platformv1.AnnouncePrefixRequest))
	}
	m[platformv1.GatewayService_WithdrawPrefix_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.WithdrawPrefix(ctx, req.(*platformv1.WithdrawPrefixRequest))
	}
	m[platformv1.GatewayService_ListAnnouncedPrefixes_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListAnnouncedPrefixes(ctx, req.(*platformv1.ListAnnouncedPrefixesRequest))
	}
	m[platformv1.GatewayService_ListIPAMPools_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListIPAMPools(ctx, req.(*platformv1.ListIPAMPoolsRequest))
	}
	m[platformv1.GatewayService_CreateIPAMPool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateIPAMPool(ctx, req.(*platformv1.CreateIPAMPoolRequest))
	}
	m[platformv1.GatewayService_GetIPAMPool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetIPAMPool(ctx, req.(*platformv1.GetIPAMPoolRequest))
	}
	m[platformv1.GatewayService_UpdateIPAMPool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateIPAMPool(ctx, req.(*platformv1.UpdateIPAMPoolRequest))
	}
	m[platformv1.GatewayService_DeleteIPAMPool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteIPAMPool(ctx, req.(*platformv1.DeleteIPAMPoolRequest))
	}
	m[platformv1.GatewayService_AllocateIP_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AllocateIP(ctx, req.(*platformv1.AllocateIPRequest))
	}
	m[platformv1.GatewayService_ReleaseIP_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ReleaseIP(ctx, req.(*platformv1.ReleaseIPRequest))
	}
	m[platformv1.GatewayService_ListAllocations_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListAllocations(ctx, req.(*platformv1.ListAllocationsRequest))
	}
	m[platformv1.GatewayService_AddVIP_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AddVIP(ctx, req.(*platformv1.AddVIPRequest))
	}
	m[platformv1.GatewayService_RemoveVIP_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RemoveVIP(ctx, req.(*platformv1.RemoveVIPRequest))
	}
	m[platformv1.GatewayService_GetVIP_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetVIP(ctx, req.(*platformv1.GetVIPRequest))
	}
	m[platformv1.GatewayService_ListVIPs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListVIPs(ctx, req.(*platformv1.ListVIPsRequest))
	}
	m[platformv1.GatewayService_SetVIPBackends_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.SetVIPBackends(ctx, req.(*platformv1.SetVIPBackendsRequest))
	}
	m[platformv1.GatewayService_GetLBStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetLBStatus(ctx, req.(*platformv1.GetLBStatusRequest))
	}
	m[platformv1.GatewayService_GetNAT64Status_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetNAT64Status(ctx, req.(*platformv1.GetNAT64StatusRequest))
	}
	m[platformv1.GatewayService_GetPerfFlows_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPerfFlows(ctx, req.(*platformv1.GetPerfFlowsRequest))
	}
	m[platformv1.GatewayService_GetPerfDatapath_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPerfDatapath(ctx, req.(*platformv1.GetPerfDatapathRequest))
	}
	m[platformv1.GatewayService_GetPerfConntrack_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPerfConntrack(ctx, req.(*platformv1.GetPerfConntrackRequest))
	}
}

// registerOverlayHandlers registers OverlayService handlers.
func registerOverlayHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Overlay == nil {
		return
	}
	svc := reg.Overlay

	m[platformv1.OverlayService_ListVTEPs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListVTEPs(ctx, req.(*platformv1.ListVTEPsRequest))
	}
	m[platformv1.OverlayService_GetVTEP_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetVTEP(ctx, req.(*platformv1.GetVTEPRequest))
	}
	m[platformv1.OverlayService_CreateVNI_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateVNI(ctx, req.(*platformv1.CreateVNIRequest))
	}
	m[platformv1.OverlayService_DeleteVNI_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteVNI(ctx, req.(*platformv1.DeleteVNIRequest))
	}
	m[platformv1.OverlayService_ListVNIs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListVNIs(ctx, req.(*platformv1.ListVNIsRequest))
	}
	m[platformv1.OverlayService_ListTunnels_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListTunnels(ctx, req.(*platformv1.ListTunnelsRequest))
	}
	m[platformv1.OverlayService_GetTunnelStats_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetTunnelStats(ctx, req.(*platformv1.GetTunnelStatsRequest))
	}
	m[platformv1.OverlayService_ListRemoteMACs_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListRemoteMACs(ctx, req.(*platformv1.ListRemoteMACsRequest))
	}
	m[platformv1.OverlayService_ForgetMAC_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ForgetMAC(ctx, req.(*platformv1.ForgetMACRequest))
	}
	m[platformv1.OverlayService_GetOverlayStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetOverlayStatus(ctx, req.(*platformv1.GetOverlayStatusRequest))
	}
}

// registerRegistryHandlers registers RegistryService handlers.
func registerRegistryHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Registry == nil {
		return
	}
	svc := reg.Registry

	m[platformv1.RegistryService_List_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.List(ctx, req.(*platformv1.ListArtifactsRequest))
	}
	m[platformv1.RegistryService_Inspect_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Inspect(ctx, req.(*platformv1.InspectArtifactRequest))
	}
	m[platformv1.RegistryService_Delete_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Delete(ctx, req.(*platformv1.DeleteArtifactRequest))
	}
	m[platformv1.RegistryService_Status_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Status(ctx, req.(*platformv1.RegistryStatusRequest))
	}
	// Note: Pull is server-streaming and not supported by Invoke.
}

// registerClusterHandlers registers ClusterService handlers.
func registerClusterHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Cluster == nil {
		return
	}
	svc := reg.Cluster

	m[platformv1.ClusterService_Bootstrap_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Bootstrap(ctx, req.(*platformv1.BootstrapClusterRequest))
	}
	m[platformv1.ClusterService_Join_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Join(ctx, req.(*platformv1.JoinClusterRequest))
	}
	m[platformv1.ClusterService_Leave_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.Leave(ctx, req.(*platformv1.LeaveClusterRequest))
	}
	m[platformv1.ClusterService_GetStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetStatus(ctx, req.(*platformv1.GetClusterStatusRequest))
	}
	m[platformv1.ClusterService_ListNodes_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListNodes(ctx, req.(*platformv1.ListClusterNodesRequest))
	}
}

// registerEABHandlers registers EABService handlers.
func registerEABHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.EAB == nil {
		return
	}
	svc := reg.EAB

	m[platformv1.EABService_CreateCredential_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateCredential(ctx, req.(*platformv1.CreateEABCredentialRequest))
	}
	m[platformv1.EABService_GetCredential_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCredential(ctx, req.(*platformv1.GetEABCredentialRequest))
	}
	m[platformv1.EABService_GetCredentialByKeyID_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCredentialByKeyID(ctx, req.(*platformv1.GetEABCredentialByKeyIDRequest))
	}
	m[platformv1.EABService_ListCredentials_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListCredentials(ctx, req.(*platformv1.ListEABCredentialsRequest))
	}
	m[platformv1.EABService_RevokeCredential_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RevokeCredential(ctx, req.(*platformv1.RevokeEABCredentialRequest))
	}
	m[platformv1.EABService_ValidateCredential_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ValidateCredential(ctx, req.(*platformv1.ValidateEABCredentialRequest))
	}
	m[platformv1.EABService_DeleteCredential_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteCredential(ctx, req.(*platformv1.DeleteEABCredentialRequest))
	}
	m[platformv1.EABService_GetCredentialQRCode_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetCredentialQRCode(ctx, req.(*platformv1.GetEABCredentialQRCodeRequest))
	}
	m[platformv1.EABService_GetEnrollmentURL_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetEnrollmentURL(ctx, req.(*platformv1.GetEABEnrollmentURLRequest))
	}
	m[platformv1.EABService_MarkCredentialUsed_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.MarkCredentialUsed(ctx, req.(*platformv1.MarkEABCredentialUsedRequest))
	}
	m[platformv1.EABService_CleanupExpiredCredentials_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CleanupExpiredCredentials(ctx, req.(*platformv1.CleanupExpiredEABCredentialsRequest))
	}
}

// registerInvitationHandlers registers InvitationService handlers.
func registerInvitationHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Invitation == nil {
		return
	}
	svc := reg.Invitation

	m[platformv1.InvitationService_CreateInvitation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateInvitation(ctx, req.(*platformv1.CreateInvitationRequest))
	}
	m[platformv1.InvitationService_GetInvitation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetInvitation(ctx, req.(*platformv1.GetInvitationRequest))
	}
	m[platformv1.InvitationService_GetInvitationByToken_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetInvitationByToken(ctx, req.(*platformv1.GetInvitationByTokenRequest))
	}
	m[platformv1.InvitationService_ListInvitations_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListInvitations(ctx, req.(*platformv1.ListInvitationsRequest))
	}
	m[platformv1.InvitationService_RevokeInvitation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.RevokeInvitation(ctx, req.(*platformv1.RevokeInvitationRequest))
	}
	m[platformv1.InvitationService_AcceptInvitation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.AcceptInvitation(ctx, req.(*platformv1.AcceptInvitationRequest))
	}
	m[platformv1.InvitationService_DeleteInvitation_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteInvitation(ctx, req.(*platformv1.DeleteInvitationRequest))
	}
}

// registerProxyHandlers registers ProxyService handlers.
func registerProxyHandlers(m map[string]handlerFunc, reg *ServiceRegistry) {
	if reg.Proxy == nil {
		return
	}
	svc := reg.Proxy

	m[platformv1.ProxyService_CreateRoute_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreateRoute(ctx, req.(*platformv1.CreateProxyRouteRequest))
	}
	m[platformv1.ProxyService_GetRoute_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetRoute(ctx, req.(*platformv1.GetProxyRouteRequest))
	}
	m[platformv1.ProxyService_UpdateRoute_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdateRoute(ctx, req.(*platformv1.UpdateProxyRouteRequest))
	}
	m[platformv1.ProxyService_DeleteRoute_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeleteRoute(ctx, req.(*platformv1.DeleteProxyRouteRequest))
	}
	m[platformv1.ProxyService_ListRoutes_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListRoutes(ctx, req.(*platformv1.ListProxyRoutesRequest))
	}
	m[platformv1.ProxyService_CreatePool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.CreatePool(ctx, req.(*platformv1.CreateProxyPoolRequest))
	}
	m[platformv1.ProxyService_GetPool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetPool(ctx, req.(*platformv1.GetProxyPoolRequest))
	}
	m[platformv1.ProxyService_UpdatePool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.UpdatePool(ctx, req.(*platformv1.UpdateProxyPoolRequest))
	}
	m[platformv1.ProxyService_DeletePool_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.DeletePool(ctx, req.(*platformv1.DeleteProxyPoolRequest))
	}
	m[platformv1.ProxyService_ListPools_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ListPools(ctx, req.(*platformv1.ListProxyPoolsRequest))
	}
	m[platformv1.ProxyService_GetProxyConfig_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetProxyConfig(ctx, req.(*platformv1.GetProxyConfigRequest))
	}
	m[platformv1.ProxyService_GetProxyStatus_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetProxyStatus(ctx, req.(*platformv1.GetProxyStatusRequest))
	}
	m[platformv1.ProxyService_ReloadProxyConfig_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.ReloadProxyConfig(ctx, req.(*platformv1.ReloadProxyConfigRequest))
	}
	m[platformv1.ProxyService_GetZoneMatrix_FullMethodName] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return svc.GetZoneMatrix(ctx, req.(*platformv1.GetProxyZoneMatrixRequest))
	}
}
