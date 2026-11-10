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

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// cov964Logger discards everything the bindings log.
func cov964Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// cov964Registry serves every service the bindings reach with the
// generated Unimplemented server, which answers codes.Unimplemented as a
// daemon without that service does. Tests replace one field with a fake.
func cov964Registry() *embedded.ServiceRegistry {
	return &embedded.ServiceRegistry{
		Daemon:      platformv1.UnimplementedPlatformDaemonServer{},
		CA:          platformv1.UnimplementedCAServiceServer{},
		TPM:         platformv1.UnimplementedTPMServiceServer{},
		VTPM:        platformv1.UnimplementedVTPMServiceServer{},
		Device:      platformv1.UnimplementedDeviceServiceServer{},
		IAM:         platformv1.UnimplementedPlatformIAMServiceServer{},
		KMS:         platformv1.UnimplementedKeyManagementServiceServer{},
		SDN:         platformv1.UnimplementedSDNServiceServer{},
		Compute:     platformv1.UnimplementedComputeServiceServer{},
		IDevID:      platformv1.UnimplementedIDevIDServiceServer{},
		Attestation: platformv1.UnimplementedAttestationServiceServer{},
		Tenant:      platformv1.UnimplementedTenantServiceServer{},
		PXE:         platformv1.UnimplementedPXEServiceServer{},
		DNS:         platformv1.UnimplementedDNSServiceServer{},
		Gateway:     platformv1.UnimplementedGatewayServiceServer{},
		Overlay:     platformv1.UnimplementedOverlayServiceServer{},
		Registry:    platformv1.UnimplementedRegistryServiceServer{},
		Cluster:     platformv1.UnimplementedClusterServiceServer{},
		NTP:         platformv1.UnimplementedNTPServiceServer{},
	}
}

// cov964Connected returns a connection whose client reaches registry
// through the SDK's embedded transport.
func cov964Connected(t *testing.T, registry *embedded.ServiceRegistry) *ConnectionBinding {
	t.Helper()
	conn := NewConnectionBinding(cov964Logger())
	cl, err := platform.NewClient(
		context.Background(),
		platform.WithOnlyProtocol(platform.ProtocolEmbedded),
		platform.WithEmbeddedServices(registry),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := cl.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	conn.SetClient(&cl)
	return conn
}

// cov964Set holds one of every service binding over a shared connection.
type cov964Set struct {
	att     *AttestationBinding
	ca      *CABinding
	cluster *ClusterBinding
	compute *ComputeBinding
	daemon  *DaemonBinding
	device  *DeviceBinding
	dns     *DNSBinding
	gateway *GatewayBinding
	iam     *IAMBinding
	idevid  *IDevIDBinding
	kms     *KMSBinding
	ntp     *NTPBinding
	overlay *OverlayBinding
	pxe     *PXEBinding
	reg     *RegistryBinding
	sdn     *SDNBinding
	tenant  *TenantBinding
	tpm     *TPMBinding
	vtpm    *VTPMBinding
}

func cov964NewSet(conn *ConnectionBinding) *cov964Set {
	l := cov964Logger()
	return &cov964Set{
		att:     NewAttestationBinding(l, conn),
		ca:      NewCABinding(l, conn),
		cluster: NewClusterBinding(l, conn),
		compute: NewComputeBinding(l, conn),
		daemon:  NewDaemonBinding(l, conn),
		device:  NewDeviceBinding(l, conn),
		dns:     NewDNSBinding(l, conn),
		gateway: NewGatewayBinding(l, conn),
		iam:     NewIAMBinding(l, conn),
		idevid:  NewIDevIDBinding(l, conn),
		kms:     NewKMSBinding(l, conn),
		ntp:     NewNTPBinding(l, conn),
		overlay: NewOverlayBinding(l, conn),
		pxe:     NewPXEBinding(l, conn),
		reg:     NewRegistryBinding(l, conn),
		sdn:     NewSDNBinding(l, conn),
		tenant:  NewTenantBinding(l, conn),
		tpm:     NewTPMBinding(l, conn),
		vtpm:    NewVTPMBinding(l, conn),
	}
}

// cov964Call is one binding method invoked with valid arguments.
type cov964Call struct {
	name string
	call func() error
}

// cov964Err drops a binding's result and keeps its error.
func cov964Err(_ map[string]interface{}, err error) error { return err }

// cov964Calls lists every exported service-binding method, each with
// arguments its own parsing accepts, so the error a call returns comes
// from the connection or the service.
func cov964Calls(s *cov964Set) []cov964Call {
	nonce := []byte("nonce")
	return []cov964Call{
		// Attestation.
		{"Attestation.GetManifest", func() error { return cov964Err(s.att.GetManifest("m1")) }},
		{"Attestation.BuildManifest", func() error { return cov964Err(s.att.BuildManifest(nonce, true, true, true)) }},
		{"Attestation.VerifyManifest", func() error { return cov964Err(s.att.VerifyManifest("m1", nonce, []byte("pem"))) }},
		{"Attestation.ListManifests", func() error { return cov964Err(s.att.ListManifests("h1", 10, 0)) }},
		{"Attestation.DeleteManifest", func() error { return cov964Err(s.att.DeleteManifest("m1")) }},
		{"Attestation.GetAttestationQuote", func() error { return cov964Err(s.att.GetAttestationQuote([]uint32{0}, nonce)) }},
		{"Attestation.VerifyAttestationQuote", func() error {
			return cov964Err(s.att.VerifyAttestationQuote([]byte("q"), []byte("s"), "RSASSA", []byte("ak"), nonce, []byte("cb")))
		}},
		{"Attestation.CollectHostAttestation", func() error { return cov964Err(s.att.CollectHostAttestation(nonce)) }},
		// CA.
		{"CA.GetCAInfo", func() error { return cov964Err(s.ca.GetCAInfo()) }},
		{"CA.IssueCertificate", func() error { return cov964Err(s.ca.IssueCertificate("host", "ecdsa_p256", 30)) }},
		{"CA.SignCSR", func() error { _, err := s.ca.SignCSR("csr", 30); return err }},
		{"CA.GetCertificate", func() error { return cov964Err(s.ca.GetCertificate("0a")) }},
		{"CA.ListCertificates", func() error { return cov964Err(s.ca.ListCertificates()) }},
		{"CA.RevokeCertificate", func() error { return cov964Err(s.ca.RevokeCertificate("0a", "key_compromise")) }},
		{"CA.RenewCertificate", func() error { return cov964Err(s.ca.RenewCertificate("0a")) }},
		{"CA.VerifyCertificate", func() error { return cov964Err(s.ca.VerifyCertificate("cGVt")) }},
		{"CA.GetCRL", func() error { return cov964Err(s.ca.GetCRL()) }},
		{"CA.GetCABundle", func() error { return cov964Err(s.ca.GetCABundle()) }},
		// Cluster.
		{"Cluster.Bootstrap", func() error { return cov964Err(s.cluster.Bootstrap("c", "n", "0.0.0.0", 7000, "10.0.0.1", 7000)) }},
		{"Cluster.Join", func() error {
			return cov964Err(s.cluster.Join("n", "0.0.0.0", 7000, "10.0.0.2", 7000, []string{"10.0.0.1:7000"}))
		}},
		{"Cluster.Leave", func() error { return cov964Err(s.cluster.Leave("n", false)) }},
		{"Cluster.GetStatus", func() error { return cov964Err(s.cluster.GetStatus()) }},
		{"Cluster.ListNodes", func() error { return cov964Err(s.cluster.ListNodes()) }},
		// Compute.
		{"Compute.CreateVM", func() error { return cov964Err(s.compute.CreateVM("vm", "d", false)) }},
		{"Compute.StartVM", func() error { return cov964Err(s.compute.StartVM("vm1")) }},
		{"Compute.StopVM", func() error { return cov964Err(s.compute.StopVM("vm1", true, 5)) }},
		{"Compute.DeleteVM", func() error { return cov964Err(s.compute.DeleteVM("vm1", true)) }},
		{"Compute.GetVM", func() error { return cov964Err(s.compute.GetVM("vm1")) }},
		{"Compute.ListVMs", func() error { return cov964Err(s.compute.ListVMs()) }},
		{"Compute.GetVMMetrics", func() error { return cov964Err(s.compute.GetVMMetrics("vm1")) }},
		{"Compute.CreateContainer", func() error { return cov964Err(s.compute.CreateContainer("c", "alpine", false)) }},
		{"Compute.StartContainer", func() error { return cov964Err(s.compute.StartContainer("c1")) }},
		{"Compute.StopContainer", func() error { return cov964Err(s.compute.StopContainer("c1", 5)) }},
		{"Compute.DeleteContainer", func() error { return cov964Err(s.compute.DeleteContainer("c1", true, true)) }},
		{"Compute.GetContainer", func() error { return cov964Err(s.compute.GetContainer("c1")) }},
		{"Compute.ListContainers", func() error { return cov964Err(s.compute.ListContainers()) }},
		{"Compute.GetContainerMetrics", func() error { return cov964Err(s.compute.GetContainerMetrics("c1")) }},
		{"Compute.ExecContainer", func() error { return cov964Err(s.compute.ExecContainer("c1", []string{"true"}, "/")) }},
		{"Compute.CreateSnapshot", func() error { return cov964Err(s.compute.CreateSnapshot("vm1", "s", "d", true, true)) }},
		{"Compute.ListSnapshots", func() error { return cov964Err(s.compute.ListSnapshots("vm1")) }},
		{"Compute.DeleteSnapshot", func() error { return cov964Err(s.compute.DeleteSnapshot("vm1", "s1")) }},
		{"Compute.RestoreSnapshot", func() error { return cov964Err(s.compute.RestoreSnapshot("vm1", "s1")) }},
		{"Compute.AttestVM", func() error { return cov964Err(s.compute.AttestVM("vm1", nonce, []uint32{0})) }},
		// Daemon.
		{"Daemon.GetVersion", func() error { return cov964Err(s.daemon.GetVersion()) }},
		{"Daemon.GetStatus", func() error { return cov964Err(s.daemon.GetStatus()) }},
		{"Daemon.GetHealth", func() error { return cov964Err(s.daemon.GetHealth(true)) }},
		{"Daemon.ListServices", func() error { _, err := s.daemon.ListServices(); return err }},
		{"Daemon.StartService", func() error { return s.daemon.StartService("tpm") }},
		{"Daemon.StopService", func() error { return s.daemon.StopService("tpm") }},
		{"Daemon.RestartService", func() error { return s.daemon.RestartService("tpm") }},
		{"Daemon.GetServiceStatus", func() error { return cov964Err(s.daemon.GetServiceStatus("tpm")) }},
		// Device.
		{"Device.CreateDevice", func() error {
			return cov964Err(s.device.CreateDevice("ap", "ac", "ek", nil, 11, "m", "sn", "sp"))
		}},
		{"Device.GetDevice", func() error { return cov964Err(s.device.GetDevice(1)) }},
		{"Device.UpdateDevice", func() error {
			return cov964Err(s.device.UpdateDevice(1, "ap", "ac", "ek", nil, 11, "m", "sn", "sp"))
		}},
		{"Device.DeleteDevice", func() error { return cov964Err(s.device.DeleteDevice(1)) }},
		{"Device.ListDevices", func() error { return cov964Err(s.device.ListDevices(1, 10, "id", true)) }},
		{"Device.FindDeviceBySerial", func() error { return cov964Err(s.device.FindDeviceBySerial("sn")) }},
		{"Device.CountDevices", func() error { return cov964Err(s.device.CountDevices()) }},
		{"Device.CreateProfile", func() error { return cov964Err(s.device.CreateProfile("p", "m", "server")) }},
		{"Device.GetProfile", func() error { return cov964Err(s.device.GetProfile(1)) }},
		{"Device.UpdateProfile", func() error { return cov964Err(s.device.UpdateProfile(1, "p", "m", "server")) }},
		{"Device.DeleteProfile", func() error { return cov964Err(s.device.DeleteProfile(1)) }},
		{"Device.ListProfiles", func() error { return cov964Err(s.device.ListProfiles(1, 10, "id", true)) }},
		{"Device.FindProfileByMACAddress", func() error { return cov964Err(s.device.FindProfileByMACAddress("aa:bb:cc:dd:ee:ff")) }},
		{"Device.FindProfileBySerial", func() error { return cov964Err(s.device.FindProfileBySerial("sn")) }},
		{"Device.FindMatchingProfile", func() error {
			return cov964Err(s.device.FindMatchingProfile("aa:bb:cc:dd:ee:ff", "sn", "m"))
		}},
		{"Device.CountProfiles", func() error { return cov964Err(s.device.CountProfiles()) }},
		{"Device.ActivateDevice", func() error { return cov964Err(s.device.ActivateDevice("sn", "aa:bb:cc:dd:ee:ff")) }},
		{"Device.AssignProfileToDevice", func() error {
			return cov964Err(s.device.AssignProfileToDevice(1, 2, "eksn", "aa:bb:cc:dd:ee:ff", ""))
		}},
		{"Device.UnassignProfileFromDevice", func() error { return cov964Err(s.device.UnassignProfileFromDevice(1)) }},
		// DNS.
		{"DNS.CreateZone", func() error { return cov964Err(s.dns.CreateZone("example.", 300, "d", true)) }},
		{"DNS.GetZone", func() error { return cov964Err(s.dns.GetZone("example.")) }},
		{"DNS.DeleteZone", func() error { return cov964Err(s.dns.DeleteZone("example.")) }},
		{"DNS.ListZones", func() error { return cov964Err(s.dns.ListZones(true, false)) }},
		{"DNS.AddRecord", func() error { return cov964Err(s.dns.AddRecord("example.", "www", "A", "10.0.0.1", 300)) }},
		{"DNS.DeleteRecord", func() error { return cov964Err(s.dns.DeleteRecord("example.", "A", "www")) }},
		{"DNS.ListRecords", func() error { return cov964Err(s.dns.ListRecords("example.", "A")) }},
		{"DNS.Resolve", func() error { return cov964Err(s.dns.Resolve("www.example.", "A")) }},
		{"DNS.GetDNSSECStatus", func() error { return cov964Err(s.dns.GetDNSSECStatus("example.")) }},
		{"DNS.SignZone", func() error { return cov964Err(s.dns.SignZone("example.")) }},
		{"DNS.Register", func() error { return cov964Err(s.dns.Register("www.example.", "10.0.0.1")) }},
		// Gateway.
		{"Gateway.GetGatewayStatus", func() error { return cov964Err(s.gateway.GetGatewayStatus()) }},
		{"Gateway.SetGatewayMode", func() error { return cov964Err(s.gateway.SetGatewayMode(1)) }},
		{"Gateway.GetBGPStatus", func() error { return cov964Err(s.gateway.GetBGPStatus()) }},
		{"Gateway.ListBGPPeers", func() error { return cov964Err(s.gateway.ListBGPPeers()) }},
		{"Gateway.AnnouncePrefix", func() error { return cov964Err(s.gateway.AnnouncePrefix("10.0.0.0/24", "10.0.0.1")) }},
		{"Gateway.WithdrawPrefix", func() error { return cov964Err(s.gateway.WithdrawPrefix("10.0.0.0/24")) }},
		{"Gateway.ListAnnouncedPrefixes", func() error { return cov964Err(s.gateway.ListAnnouncedPrefixes()) }},
		{"Gateway.ListIPAMPools", func() error { return cov964Err(s.gateway.ListIPAMPools()) }},
		{"Gateway.AllocateIP", func() error { return cov964Err(s.gateway.AllocateIP("pool", "dev", "host")) }},
		{"Gateway.ReleaseIP", func() error { return cov964Err(s.gateway.ReleaseIP("10.0.0.5")) }},
		{"Gateway.ListAllocations", func() error { return cov964Err(s.gateway.ListAllocations("pool")) }},
		// IAM.
		{"IAM.CreateUser", func() error { return cov964Err(s.iam.CreateUser("t", "a@example.com", "A", nil, nil)) }},
		{"IAM.GetUser", func() error { return cov964Err(s.iam.GetUser("t", "u")) }},
		{"IAM.ListUsers", func() error { return cov964Err(s.iam.ListUsers("t")) }},
		{"IAM.DeleteUser", func() error { return cov964Err(s.iam.DeleteUser("t", "u")) }},
		{"IAM.CreateRole", func() error { return cov964Err(s.iam.CreateRole("t", "r", "R", "d", []string{"ca:read"})) }},
		{"IAM.GetRole", func() error { return cov964Err(s.iam.GetRole("t", "r")) }},
		{"IAM.ListRoles", func() error { return cov964Err(s.iam.ListRoles("t")) }},
		{"IAM.DeleteRole", func() error { return cov964Err(s.iam.DeleteRole("t", "r")) }},
		{"IAM.AssignRole", func() error { return cov964Err(s.iam.AssignRole("t", "u", "r")) }},
		{"IAM.RevokeRole", func() error { return cov964Err(s.iam.RevokeRole("t", "u", "r")) }},
		{"IAM.CreateToken", func() error { return cov964Err(s.iam.CreateToken("t", "u", []string{"ca"}, 60)) }},
		{"IAM.VerifyToken", func() error { return cov964Err(s.iam.VerifyToken("tok")) }},
		{"IAM.CheckPermission", func() error { return cov964Err(s.iam.CheckPermission("t", "u", "read", "ca")) }},
		// IDevID.
		{"IDevID.GenerateIDevID", func() error { return cov964Err(s.idevid.GenerateIDevID()) }},
		{"IDevID.GetIDevIDInfo", func() error { return cov964Err(s.idevid.GetIDevIDInfo()) }},
		{"IDevID.HasIDevID", func() error { return cov964Err(s.idevid.HasIDevID()) }},
		{"IDevID.DeleteIDevID", func() error { return cov964Err(s.idevid.DeleteIDevID()) }},
		{"IDevID.GenerateIAK", func() error { return cov964Err(s.idevid.GenerateIAK()) }},
		{"IDevID.GetIAKInfo", func() error { return cov964Err(s.idevid.GetIAKInfo()) }},
		{"IDevID.HasIAK", func() error { return cov964Err(s.idevid.HasIAK()) }},
		{"IDevID.DeleteIAK", func() error { return cov964Err(s.idevid.DeleteIAK()) }},
		{"IDevID.CreateIDevIDCSR", func() error { return cov964Err(s.idevid.CreateIDevIDCSR()) }},
		{"IDevID.InstallIDevIDCertificate", func() error { return cov964Err(s.idevid.InstallIDevIDCertificate([]byte("pem"))) }},
		{"IDevID.GetIDevIDCertificate", func() error { return cov964Err(s.idevid.GetIDevIDCertificate()) }},
		{"IDevID.GetDeviceAttributes", func() error { return cov964Err(s.idevid.GetDeviceAttributes()) }},
		// KMS.
		{"KMS.GenerateKey", func() error { return cov964Err(s.kms.GenerateKey("rsa_2048", "k", "d", 2048)) }},
		{"KMS.GetKey", func() error { return cov964Err(s.kms.GetKey("k1")) }},
		{"KMS.ListKeys", func() error { return cov964Err(s.kms.ListKeys()) }},
		{"KMS.DeleteKey", func() error { return cov964Err(s.kms.DeleteKey("k1")) }},
		{"KMS.RotateKey", func() error { return cov964Err(s.kms.RotateKey("k1")) }},
		{"KMS.Encrypt", func() error { return cov964Err(s.kms.Encrypt("k1", "aGVsbG8=")) }},
		{"KMS.Decrypt", func() error { return cov964Err(s.kms.Decrypt("k1", "aGVsbG8=")) }},
		{"KMS.Sign", func() error { return cov964Err(s.kms.Sign("k1", "aGVsbG8=", "sha256")) }},
		{"KMS.Verify", func() error { return cov964Err(s.kms.Verify("k1", "aGVsbG8=", "c2ln", "sha256")) }},
		{"KMS.GenerateRandom", func() error { return cov964Err(s.kms.GenerateRandom(16)) }},
		{"KMS.BackendStatus", func() error { return cov964Err(s.kms.BackendStatus()) }},
		// NTP.
		{"NTP.GetStatus", func() error { return cov964Err(s.ntp.GetStatus()) }},
		{"NTP.ListSources", func() error { return cov964Err(s.ntp.ListSources()) }},
		{"NTP.Step", func() error { return cov964Err(s.ntp.Step()) }},
		// Overlay.
		{"Overlay.ListVTEPs", func() error { return cov964Err(s.overlay.ListVTEPs()) }},
		{"Overlay.GetVTEP", func() error { return cov964Err(s.overlay.GetVTEP("n1")) }},
		{"Overlay.CreateVNI", func() error { return cov964Err(s.overlay.CreateVNI(100, 10, "v")) }},
		{"Overlay.DeleteVNI", func() error { return cov964Err(s.overlay.DeleteVNI(100)) }},
		{"Overlay.ListVNIs", func() error { return cov964Err(s.overlay.ListVNIs()) }},
		{"Overlay.ListTunnels", func() error { return cov964Err(s.overlay.ListTunnels(100)) }},
		{"Overlay.GetTunnelStats", func() error { return cov964Err(s.overlay.GetTunnelStats("10.0.0.2", 100)) }},
		{"Overlay.ListRemoteMACs", func() error { return cov964Err(s.overlay.ListRemoteMACs(100)) }},
		{"Overlay.ForgetMAC", func() error { return cov964Err(s.overlay.ForgetMAC("aa:bb:cc:dd:ee:ff", 100)) }},
		{"Overlay.GetOverlayStatus", func() error { return cov964Err(s.overlay.GetOverlayStatus()) }},
		// PXE.
		{"PXE.RegisterDevice", func() error { return cov964Err(s.pxe.RegisterDevice("aa:bb:cc:dd:ee:ff", "p1")) }},
		{"PXE.GetDevice", func() error { return cov964Err(s.pxe.GetDevice("d1")) }},
		{"PXE.ListDevices", func() error { return cov964Err(s.pxe.ListDevices()) }},
		{"PXE.RemoveDevice", func() error { return cov964Err(s.pxe.RemoveDevice("d1")) }},
		{"PXE.UpdateState", func() error { return cov964Err(s.pxe.UpdateState("d1", 1, "r")) }},
		{"PXE.Authorize", func() error { return cov964Err(s.pxe.Authorize("d1")) }},
		{"PXE.Quarantine", func() error { return cov964Err(s.pxe.Quarantine("d1", "r")) }},
		{"PXE.GetStatus", func() error { return cov964Err(s.pxe.GetStatus()) }},
		{"PXE.StartService", func() error { return cov964Err(s.pxe.StartService()) }},
		{"PXE.StopService", func() error { return cov964Err(s.pxe.StopService()) }},
		// Registry.
		{"Registry.List", func() error { return cov964Err(s.reg.List("repo", 10, 0)) }},
		{"Registry.Inspect", func() error { return cov964Err(s.reg.Inspect("repo", "latest", "")) }},
		{"Registry.Delete", func() error { return cov964Err(s.reg.Delete("repo", "latest", "")) }},
		{"Registry.Status", func() error { return cov964Err(s.reg.Status()) }},
		// SDN.
		{"SDN.CreateBridge", func() error { return cov964Err(s.sdn.CreateBridge("br0", 1500)) }},
		{"SDN.DeleteBridge", func() error { return cov964Err(s.sdn.DeleteBridge("br0", true)) }},
		{"SDN.GetBridge", func() error { return cov964Err(s.sdn.GetBridge("br0")) }},
		{"SDN.ListBridges", func() error { return cov964Err(s.sdn.ListBridges()) }},
		{"SDN.AddPort", func() error { return cov964Err(s.sdn.AddPort("br0", "eth0", 10)) }},
		{"SDN.DeletePort", func() error { return cov964Err(s.sdn.DeletePort("br0", "p1")) }},
		{"SDN.GetPort", func() error { return cov964Err(s.sdn.GetPort("br0", "p1")) }},
		{"SDN.ListPorts", func() error { return cov964Err(s.sdn.ListPorts("br0")) }},
		{"SDN.AddFlow", func() error { return cov964Err(s.sdn.AddFlow("br0", 0, 100)) }},
		{"SDN.DeleteFlow", func() error { return cov964Err(s.sdn.DeleteFlow("br0", "f1")) }},
		{"SDN.ListFlows", func() error { return cov964Err(s.sdn.ListFlows("br0", 0)) }},
		{"SDN.FlushFlows", func() error { return cov964Err(s.sdn.FlushFlows("br0", 0)) }},
		{"SDN.CreateVLAN", func() error { return cov964Err(s.sdn.CreateVLAN("br0", "v10", 10)) }},
		{"SDN.DeleteVLAN", func() error { return cov964Err(s.sdn.DeleteVLAN("br0", 10)) }},
		{"SDN.ListVLANs", func() error { return cov964Err(s.sdn.ListVLANs("br0")) }},
		{"SDN.AuthenticatePort", func() error { return cov964Err(s.sdn.AuthenticatePort("br0", "p1", []byte("pem"), "pem")) }},
		{"SDN.RevokePortAuth", func() error { return cov964Err(s.sdn.RevokePortAuth("br0", "p1")) }},
		{"SDN.GetPortStats", func() error { return cov964Err(s.sdn.GetPortStats("br0", "p1")) }},
		{"SDN.GetFlowStats", func() error { return cov964Err(s.sdn.GetFlowStats("br0", "f1")) }},
		// Tenant.
		{"Tenant.ListTenants", func() error { return cov964Err(s.tenant.ListTenants(10, 0)) }},
		{"Tenant.GetTenant", func() error { return cov964Err(s.tenant.GetTenant("t1")) }},
		{"Tenant.CreateTenant", func() error { return cov964Err(s.tenant.CreateTenant("t", "T")) }},
		{"Tenant.UpdateTenant", func() error { return cov964Err(s.tenant.UpdateTenant("t1", "T")) }},
		{"Tenant.DeleteTenant", func() error { return cov964Err(s.tenant.DeleteTenant("t1")) }},
		{"Tenant.SuspendTenant", func() error { return cov964Err(s.tenant.SuspendTenant("t1")) }},
		{"Tenant.ResumeTenant", func() error { return cov964Err(s.tenant.ResumeTenant("t1")) }},
		{"Tenant.GetQuotas", func() error { return cov964Err(s.tenant.GetQuotas("t1")) }},
		{"Tenant.UpdateQuotas", func() error { return cov964Err(s.tenant.UpdateQuotas("t1")) }},
		{"Tenant.GetUsage", func() error { return cov964Err(s.tenant.GetUsage("t1")) }},
		// TPM.
		{"TPM.Info", func() error { return cov964Err(s.tpm.Info()) }},
		{"TPM.Provision", func() error { return cov964Err(s.tpm.Provision("o", "e", true, true, true)) }},
		{"TPM.Clear", func() error { return cov964Err(s.tpm.Clear("o", true)) }},
		{"TPM.CreateEK", func() error { return cov964Err(s.tpm.CreateEK(true)) }},
		{"TPM.GetEK", func() error { return cov964Err(s.tpm.GetEK("ecdsa_p256", 0x81010001)) }},
		{"TPM.GetEKCertificate", func() error { return cov964Err(s.tpm.GetEKCertificate("ecdsa_p256", 0x81010001)) }},
		{"TPM.ImportEKCertificate", func() error { return cov964Err(s.tpm.ImportEKCertificate([]byte("der"), "der", 0x01c00002)) }},
		{"TPM.DeleteEK", func() error { return cov964Err(s.tpm.DeleteEK(0x81010001, "ecdsa_p256", "p")) }},
		{"TPM.CreateSRK", func() error { return cov964Err(s.tpm.CreateSRK(true, 0x81010001, "p")) }},
		{"TPM.GetSRK", func() error { return cov964Err(s.tpm.GetSRK("ecdsa_p256", 0x81000001)) }},
		{"TPM.DeleteSRK", func() error { return cov964Err(s.tpm.DeleteSRK(0x81000001, "ecdsa_p256", "p")) }},
		{"TPM.CreateAK", func() error { return cov964Err(s.tpm.CreateAK(true, 0x81000001, "p")) }},
		{"TPM.GetAK", func() error { return cov964Err(s.tpm.GetAK("ecdsa_p256", 0x81010002)) }},
		{"TPM.DeleteAK", func() error { return cov964Err(s.tpm.DeleteAK(0x81010002, "ecdsa_p256", "p")) }},
		{"TPM.Seal", func() error {
			return cov964Err(s.tpm.Seal([]byte("d"), "cn", 0x81000001, "pp", "p", []uint32{7}, "sha256", true))
		}},
		{"TPM.Unseal", func() error { return cov964Err(s.tpm.Unseal("cn", 0x81000001, "pp", "p", []uint32{7}, "sha256")) }},
		{"TPM.Quote", func() error { return cov964Err(s.tpm.Quote(0x81010002, "p", []uint32{0}, "sha256", nonce)) }},
		{"TPM.VerifyQuote", func() error {
			return cov964Err(s.tpm.VerifyQuote([]byte("q"), []byte("s"), []byte("ak"), nonce, []byte("cb"), "RSASSA"))
		}},
		{"TPM.GetEventLog", func() error { return cov964Err(s.tpm.GetEventLog("json")) }},
		{"TPM.GetPCRs", func() error { return cov964Err(s.tpm.GetPCRs([]uint32{0, 7}, "sha256")) }},
		{"TPM.DefineNVRAM", func() error { return cov964Err(s.tpm.DefineNVRAM(0x01500000, 32, "p", []string{"ownerwrite"})) }},
		{"TPM.WriteNVRAM", func() error { return cov964Err(s.tpm.WriteNVRAM(0x01500000, []byte("d"), "p", 0)) }},
		{"TPM.ReadNVRAM", func() error { return cov964Err(s.tpm.ReadNVRAM(0x01500000, "p", 0, 1)) }},
		{"TPM.UndefineNVRAM", func() error { return cov964Err(s.tpm.UndefineNVRAM(0x01500000, "p")) }},
		{"TPM.GetRandom", func() error { return cov964Err(s.tpm.GetRandom(16)) }},
		// vTPM.
		{"VTPM.CreateBundle", func() error {
			return cov964Err(s.vtpm.CreateBundle("template", "h", "rsa", "tpl", true, map[string]string{"a": "b"}))
		}},
		{"VTPM.GetBundle", func() error { return cov964Err(s.vtpm.GetBundle("b1")) }},
		{"VTPM.DeleteBundle", func() error { return cov964Err(s.vtpm.DeleteBundle("b1")) }},
		{"VTPM.ListBundles", func() error { return cov964Err(s.vtpm.ListBundles("template", map[string]string{"a": "b"}, 10, 0)) }},
		{"VTPM.CreateTemplate", func() error { return cov964Err(s.vtpm.CreateTemplate("tpl", "d", "rsa", true)) }},
		{"VTPM.GetTemplate", func() error { return cov964Err(s.vtpm.GetTemplate("tpl")) }},
		{"VTPM.DeleteTemplate", func() error { return cov964Err(s.vtpm.DeleteTemplate("tpl")) }},
		{"VTPM.ListTemplates", func() error { return cov964Err(s.vtpm.ListTemplates()) }},
		{"VTPM.CloneTemplate", func() error { return cov964Err(s.vtpm.CloneTemplate("tpl", "h", map[string]string{"a": "b"})) }},
		{"VTPM.ValidateBundle", func() error { return cov964Err(s.vtpm.ValidateBundle("b1")) }},
		{"VTPM.GetBundlePath", func() error { return cov964Err(s.vtpm.GetBundlePath("b1")) }},
		{"VTPM.GetTPMSocketPath", func() error { return cov964Err(s.vtpm.GetTPMSocketPath("b1")) }},
		{"VTPM.GetNVRAMPath", func() error { return cov964Err(s.vtpm.GetNVRAMPath("b1")) }},
		{"VTPM.StartVTPM", func() error { return cov964Err(s.vtpm.StartVTPM("b1")) }},
		{"VTPM.StopVTPM", func() error { return cov964Err(s.vtpm.StopVTPM("b1")) }},
		{"VTPM.IsVTPMRunning", func() error { return cov964Err(s.vtpm.IsVTPMRunning("b1")) }},
		{"VTPM.QuoteVTPM", func() error { return cov964Err(s.vtpm.QuoteVTPM("b1", nonce, []int32{0})) }},
		{"VTPM.SealVTPM", func() error { return cov964Err(s.vtpm.SealVTPM("b1", []byte("d"), []int32{7}, "a")) }},
		{"VTPM.UnsealVTPM", func() error { return cov964Err(s.vtpm.UnsealVTPM("b1", []byte("sealed"), "a")) }},
		{"VTPM.ExtendVTPMPCR", func() error { return cov964Err(s.vtpm.ExtendVTPMPCR("b1", 16, []byte("d"))) }},
		{"VTPM.ReadVTPMPCR", func() error { return cov964Err(s.vtpm.ReadVTPMPCR("b1", 16)) }},
	}
}

// Every service binding refuses before any SDK call when no client has
// been set: the frontend sees NotConnectedError, never a nil dereference.
func TestCov964_EveryBindingNeedsAConnection(t *testing.T) {
	set := cov964NewSet(NewConnectionBinding(cov964Logger()))
	for _, tc := range cov964Calls(set) {
		t.Run(tc.name, func(t *testing.T) {
			var notConnected *NotConnectedError
			if err := tc.call(); !errors.As(err, &notConnected) {
				t.Fatalf("err = %v, want NotConnectedError", err)
			}
		})
	}
}

// cov964ChannelBound names the calls whose quote must be bound to a TLS
// channel; the embedded transport has none, so the SDK refuses them.
var cov964ChannelBound = map[string]bool{
	"Attestation.GetAttestationQuote":    true,
	"Attestation.CollectHostAttestation": true,
	"TPM.Quote":                          true,
}

// A daemon that does not implement a call answers Unimplemented, and every
// binding hands that status to the frontend instead of a result.
func TestCov964_EveryBindingReturnsTheServiceStatus(t *testing.T) {
	set := cov964NewSet(cov964Connected(t, cov964Registry()))
	for _, tc := range cov964Calls(set) {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if cov964ChannelBound[tc.name] {
				var unbound *transport.ErrChannelBindingUnavailable
				if !errors.As(err, &unbound) {
					t.Fatalf("err = %v, want ErrChannelBindingUnavailable", err)
				}
				return
			}
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("err = %v, want codes.Unimplemented", err)
			}
		})
	}
}

func TestCov964_ConnectionLifecycle(t *testing.T) {
	conn := NewConnectionBinding(cov964Logger())
	if conn.IsConnected() {
		t.Fatal("a new connection reports connected")
	}
	if err := conn.Disconnect(); err != nil {
		t.Fatalf("Disconnect without a client: %v", err)
	}

	cl, err := platform.NewClient(
		context.Background(),
		platform.WithOnlyProtocol(platform.ProtocolEmbedded),
		platform.WithEmbeddedServices(cov964Registry()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn.SetClient(&cl)
	if !conn.IsConnected() {
		t.Fatal("IsConnected = false after SetClient")
	}
	if err := conn.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if conn.IsConnected() {
		t.Fatal("IsConnected = true after Disconnect")
	}
	if _, err := conn.loadClient(); err == nil {
		t.Fatal("loadClient after Disconnect returned a client")
	}
}

func TestCov964_ConnectRefusesAnUnknownProtocol(t *testing.T) {
	conn := NewConnectionBinding(cov964Logger())
	err := conn.Connect("carrier-pigeon", "localhost:1", nil)

	var connectErr *ConnectError
	if !errors.As(err, &connectErr) || connectErr.Address != "localhost:1" {
		t.Fatalf("err = %v, want ConnectError for localhost:1", err)
	}
	var invalid *InvalidProtocolError
	if !errors.As(err, &invalid) || invalid.Protocol != "carrier-pigeon" {
		t.Fatalf("err = %v, want InvalidProtocolError{carrier-pigeon}", err)
	}
	if conn.IsConnected() {
		t.Fatal("a refused Connect left a client behind")
	}
}

func TestCov964_GetVersionReportsTheBuild(t *testing.T) {
	got := NewConnectionBinding(cov964Logger()).GetVersion()
	want := map[string]string{"version": version, "gitCommit": gitCommit, "buildDate": buildDate}
	if len(got) != len(want) {
		t.Fatalf("GetVersion = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("GetVersion[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// Each typed error names the value it rejects, so the frontend can show it.
func TestCov964_ErrorMessagesNameTheirField(t *testing.T) {
	cause := errors.New("dial refused")
	tests := []struct {
		err  error
		want string
	}{
		{&GUIUnavailableError{}, "GUI unavailable"},
		{&NotConnectedError{}, "not connected"},
		{&ConnectError{Address: "host:1", Err: cause}, "connect to host:1 failed: dial refused"},
		{&InvalidProtocolError{Protocol: "smoke"}, "invalid protocol: smoke"},
		{&InvalidServiceTypeError{Input: "bogus-svc"}, "invalid service type: bogus-svc"},
		{&InvalidInputError{Field: "nonce", Reason: "empty"}, "invalid input for nonce: empty"},
		{&InvalidKeyAlgorithmError{Input: "rot13"}, "invalid key algorithm: rot13"},
		{&InvalidPCRBankError{Input: "md5"}, "invalid PCR bank: md5"},
		{&InvalidBundleModeError{Input: "odd"}, "invalid bundle mode: odd"},
		{&InvalidDeviceRoleError{Input: "king"}, "invalid device role: king"},
		{&InvalidEKAlgorithmError{Input: "dsa"}, "invalid EK algorithm: dsa"},
		{&ServiceUnavailableError{Service: "KMS"}, "the KMS service is not available"},
		{&NoCertificateIssuedError{}, "returned no certificate"},
		{&InvalidRecordTypeError{Input: "ZZZ"}, "invalid DNS record type: ZZZ"},
		{&UnsupportedRecordTypeError{Type: "RECORD_TYPE_SOA"}, "unsupported record type for simple add: RECORD_TYPE_SOA"},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); !strings.Contains(got, tc.want) {
			t.Errorf("%T.Error() = %q, want it to contain %q", tc.err, got, tc.want)
		}
	}
	if got := errors.Unwrap(&ConnectError{Address: "host:1", Err: cause}); got != cause {
		t.Fatalf("Unwrap = %v, want the cause", got)
	}
}

// cov964WithArgs sets os.Args for one case and restores it afterwards.
func cov964WithArgs(t *testing.T, args ...string) {
	t.Helper()
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = append([]string{"platformctl"}, args...)
}

func TestCov964_LogArgsAndGUIOnly(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantLevel string
		wantGUI   bool
	}{
		{"no arguments", nil, "info", true},
		{"separate value", []string{"--log-level", "debug"}, "debug", true},
		{"joined value", []string{"--log-level=warn"}, "warn", true},
		{"trailing flag without a value", []string{"--log-level"}, "info", true},
		{"subcommand", []string{"--log-level", "error", "tpm", "info"}, "error", false},
		{"subcommand only", []string{"version"}, "info", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cov964WithArgs(t, tc.args...)
			if got := parseLogArgs(); got != tc.wantLevel {
				t.Errorf("parseLogArgs = %q, want %q", got, tc.wantLevel)
			}
			if got := isGUIOnly(); got != tc.wantGUI {
				t.Errorf("isGUIOnly = %v, want %v", got, tc.wantGUI)
			}
		})
	}
}

// cov964Is reports whether err holds a T.
func cov964Is[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// cov964InputField reports whether err is an InvalidInputError for field.
func cov964InputField(err error, field string) bool {
	var input *InvalidInputError
	return errors.As(err, &input) && input.Field == field
}

// Bad arguments are refused with a typed error before the SDK is called:
// the connected daemon answers Unimplemented, so any other error proves the
// binding returned first.
func TestCov964_BadInputIsRefusedBeforeTheCall(t *testing.T) {
	s := cov964NewSet(cov964Connected(t, cov964Registry()))
	isAlgorithm := func(err error) bool { return cov964InputField(err, "algorithm") }
	isBank := cov964Is[*InvalidPCRBankError]
	isService := cov964Is[*InvalidServiceTypeError]
	isRecord := cov964Is[*InvalidRecordTypeError]
	isRole := cov964Is[*InvalidDeviceRoleError]
	isMode := cov964Is[*InvalidBundleModeError]
	isEK := cov964Is[*InvalidEKAlgorithmError]
	field := func(name string) func(error) bool {
		return func(err error) bool { return cov964InputField(err, name) }
	}
	tests := []struct {
		name string
		call func() error
		want func(error) bool
	}{
		{"TPM.GetEK", func() error { return cov964Err(s.tpm.GetEK("rot13", 1)) }, isAlgorithm},
		{"TPM.GetEKCertificate", func() error { return cov964Err(s.tpm.GetEKCertificate("rot13", 1)) }, isAlgorithm},
		{"TPM.DeleteEK", func() error { return cov964Err(s.tpm.DeleteEK(1, "rot13", "")) }, isAlgorithm},
		{"TPM.GetSRK", func() error { return cov964Err(s.tpm.GetSRK("rot13", 1)) }, isAlgorithm},
		{"TPM.DeleteSRK", func() error { return cov964Err(s.tpm.DeleteSRK(1, "rot13", "")) }, isAlgorithm},
		{"TPM.GetAK", func() error { return cov964Err(s.tpm.GetAK("rot13", 1)) }, isAlgorithm},
		{"TPM.DeleteAK", func() error { return cov964Err(s.tpm.DeleteAK(1, "rot13", "")) }, isAlgorithm},
		{"TPM.Seal", func() error { return cov964Err(s.tpm.Seal(nil, "cn", 1, "", "", nil, "md5", false)) }, isBank},
		{"TPM.Unseal", func() error { return cov964Err(s.tpm.Unseal("cn", 1, "", "", nil, "md5")) }, isBank},
		{"TPM.Quote", func() error { return cov964Err(s.tpm.Quote(1, "", nil, "md5", []byte("n"))) }, isBank},
		{"TPM.GetPCRs", func() error { return cov964Err(s.tpm.GetPCRs(nil, "md5")) }, isBank},
		{"CA.IssueCertificate", func() error { return cov964Err(s.ca.IssueCertificate("h", "rot13", 1)) }, isAlgorithm},
		{"CA.RevokeCertificate", func() error { return cov964Err(s.ca.RevokeCertificate("0a", "boredom")) }, field("reason")},
		{"CA.VerifyCertificate", func() error { return cov964Err(s.ca.VerifyCertificate("!!")) }, field("certificatePem")},
		{"KMS.GenerateKey", func() error { return cov964Err(s.kms.GenerateKey("rot13", "k", "", 0)) }, isAlgorithm},
		{"KMS.Encrypt", func() error { return cov964Err(s.kms.Encrypt("k", "!!")) }, field("plaintext")},
		{"KMS.Decrypt", func() error { return cov964Err(s.kms.Decrypt("k", "!!")) }, field("ciphertext")},
		{"KMS.Sign data", func() error { return cov964Err(s.kms.Sign("k", "!!", "sha256")) }, field("data")},
		{"KMS.Sign hash", func() error { return cov964Err(s.kms.Sign("k", "aGk=", "md4")) }, field("hashAlgorithm")},
		{"KMS.Verify data", func() error { return cov964Err(s.kms.Verify("k", "!!", "aGk=", "sha256")) }, field("data")},
		{"KMS.Verify signature", func() error { return cov964Err(s.kms.Verify("k", "aGk=", "!!", "sha256")) }, field("signature")},
		{"KMS.Verify hash", func() error { return cov964Err(s.kms.Verify("k", "aGk=", "aGk=", "md4")) }, field("hashAlgorithm")},
		{"Daemon.StartService", func() error { return s.daemon.StartService("bogus") }, isService},
		{"Daemon.StopService", func() error { return s.daemon.StopService("bogus") }, isService},
		{"Daemon.RestartService", func() error { return s.daemon.RestartService("bogus") }, isService},
		{"Daemon.GetServiceStatus", func() error { return cov964Err(s.daemon.GetServiceStatus("bogus")) }, isService},
		{"DNS.AddRecord type", func() error { return cov964Err(s.dns.AddRecord("z.", "w", "ZZZ", "v", 1)) }, isRecord},
		{"DNS.AddRecord unspecified", func() error {
			return cov964Err(s.dns.AddRecord("z.", "w", "RECORD_TYPE_UNSPECIFIED", "v", 1))
		}, cov964Is[*UnsupportedRecordTypeError]},
		{"DNS.DeleteRecord", func() error { return cov964Err(s.dns.DeleteRecord("z.", "ZZZ", "w")) }, isRecord},
		{"DNS.ListRecords", func() error { return cov964Err(s.dns.ListRecords("z.", "ZZZ")) }, isRecord},
		{"DNS.Resolve", func() error { return cov964Err(s.dns.Resolve("w.z.", "ZZZ")) }, isRecord},
		{"Device.CreateProfile", func() error { return cov964Err(s.device.CreateProfile("p", "m", "king")) }, isRole},
		{"Device.UpdateProfile", func() error { return cov964Err(s.device.UpdateProfile(1, "p", "m", "king")) }, isRole},
		{"VTPM.CreateBundle mode", func() error { return cov964Err(s.vtpm.CreateBundle("odd", "h", "rsa", "", false, nil)) }, isMode},
		{"VTPM.CreateBundle EK", func() error { return cov964Err(s.vtpm.CreateBundle("template", "h", "dsa", "", false, nil)) }, isEK},
		{"VTPM.ListBundles", func() error { return cov964Err(s.vtpm.ListBundles("odd", nil, 0, 0)) }, isMode},
		{"VTPM.CreateTemplate", func() error { return cov964Err(s.vtpm.CreateTemplate("t", "", "dsa", false)) }, isEK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !tc.want(err) {
				t.Fatalf("err = %v, want the typed input error", err)
			}
		})
	}
}

// Each parser takes the short name in any case and the full enum name.
func TestCov964_ParsersAcceptShortAndFullNames(t *testing.T) {
	tests := []struct {
		name  string
		parse func(string) (int32, error)
		short string
		full  string
	}{
		{"service type", func(s string) (int32, error) { v, err := parseServiceType(s); return int32(v), err }, "tpm", "SERVICE_TYPE_TPM"},
		{"record type", func(s string) (int32, error) { v, err := parseRecordType(s); return int32(v), err }, "aaaa", "RECORD_TYPE_AAAA"},
		{"key algorithm", func(s string) (int32, error) { v, err := parseKeyAlgorithm(s); return int32(v), err }, "ecdsa_p256", "KEY_ALGORITHM_ECDSA_P256"},
		{"revocation reason", func(s string) (int32, error) { v, err := parseRevocationReason(s); return int32(v), err }, "key_compromise", "REVOCATION_REASON_KEY_COMPROMISE"},
		{"KMS key algorithm", func(s string) (int32, error) { v, err := parseKMSKeyAlgorithm(s); return int32(v), err }, "rsa_2048", "KMS_KEY_ALGORITHM_RSA_2048"},
		{"hash algorithm", func(s string) (int32, error) { v, err := parseHashAlgorithm(s); return int32(v), err }, "sha256", "HASH_ALGORITHM_SHA256"},
		{"PCR bank", func(s string) (int32, error) { v, err := parsePCRBank(s); return int32(v), err }, "sha256", "PCR_BANK_SHA256"},
		{"device role", func(s string) (int32, error) { v, err := parseDeviceRole(s); return int32(v), err }, "server", "DEVICE_ROLE_SERVER"},
		{"bundle mode", func(s string) (int32, error) { v, err := parseBundleMode(s); return int32(v), err }, "template", "BUNDLE_MODE_TEMPLATE"},
		{"EK algorithm", func(s string) (int32, error) { v, err := parseEKAlgorithm(s); return int32(v), err }, "rsa", "EK_ALGORITHM_RSA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			short, err := tc.parse(tc.short)
			if err != nil {
				t.Fatalf("parse(%q): %v", tc.short, err)
			}
			full, err := tc.parse(tc.full)
			if err != nil {
				t.Fatalf("parse(%q): %v", tc.full, err)
			}
			if short == 0 || short != full {
				t.Fatalf("parse(%q) = %d, parse(%q) = %d, want the same non-zero value", tc.short, short, tc.full, full)
			}
		})
	}
}

// The optional enums map an empty string to UNSPECIFIED rather than failing.
func TestCov964_OptionalEnumsDefaultToUnspecified(t *testing.T) {
	if v, err := parsePCRBank(""); err != nil || v != platformv1.PCRBank_PCR_BANK_UNSPECIFIED {
		t.Errorf("parsePCRBank(\"\") = %v, %v", v, err)
	}
	if v, err := parseDeviceRole(""); err != nil || v != platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED {
		t.Errorf("parseDeviceRole(\"\") = %v, %v", v, err)
	}
	if v, err := parseBundleMode(""); err != nil || v != platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED {
		t.Errorf("parseBundleMode(\"\") = %v, %v", v, err)
	}
	if v, err := parseEKAlgorithm(""); err != nil || v != platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED {
		t.Errorf("parseEKAlgorithm(\"\") = %v, %v", v, err)
	}
}

// buildRecord puts name, value and TTL in the oneof the type selects.
func TestCov964_BuildRecordFillsTheMatchingOneof(t *testing.T) {
	tests := []struct {
		rtype platformv1.RecordType
		want  *platformv1.Record
	}{
		{platformv1.RecordType_RECORD_TYPE_A, &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "n", Value: "v", Ttl: 9}}}},
		{platformv1.RecordType_RECORD_TYPE_AAAA, &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_AAAA,
			Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "n", Value: "v", Ttl: 9}}}},
		{platformv1.RecordType_RECORD_TYPE_CNAME, &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_CNAME,
			Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "n", Value: "v", Ttl: 9}}}},
		{platformv1.RecordType_RECORD_TYPE_MX, &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_MX,
			Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "n", Value: "v", Ttl: 9}}}},
		{platformv1.RecordType_RECORD_TYPE_NS, &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_NS,
			Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "n", Value: "v", Ttl: 9}}}},
		{platformv1.RecordType_RECORD_TYPE_TXT, &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_TXT,
			Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "n", Value: "v", Ttl: 9}}}},
	}
	for _, tc := range tests {
		got, err := buildRecord(tc.rtype, "n", "v", 9)
		if err != nil {
			t.Fatalf("buildRecord(%v): %v", tc.rtype, err)
		}
		if !proto.Equal(got, tc.want) {
			t.Fatalf("buildRecord(%v) = %v, want %v", tc.rtype, got, tc.want)
		}
	}
}

func TestCov964_ProtoToMap(t *testing.T) {
	got, err := protoToMap(&platformv1.GetVersionResponse{Version: "1.2.3", GitCommit: "abc"})
	if err != nil {
		t.Fatalf("protoToMap: %v", err)
	}
	if got["version"] != "1.2.3" || got["gitCommit"] != "abc" || len(got) != 2 {
		t.Fatalf("protoToMap = %v, want camelCase version and gitCommit only", got)
	}
	if got, err := protoToMap(nil); got != nil || err != nil {
		t.Fatalf("protoToMap(nil) = %v, %v, want nil, nil", got, err)
	}
}

// cov964Recorder keeps the last request a fake server received.
type cov964Recorder struct{ got proto.Message }

type cov964TPMServer struct {
	platformv1.UnimplementedTPMServiceServer
	cov964Recorder
}

func (f *cov964TPMServer) Info(_ context.Context, r *platformv1.TPMInfoRequest) (*platformv1.TPMInfoResponse, error) {
	f.got = r
	return &platformv1.TPMInfoResponse{}, nil
}
func (f *cov964TPMServer) Provision(_ context.Context, r *platformv1.TPMProvisionRequest) (*platformv1.TPMProvisionResponse, error) {
	f.got = r
	return &platformv1.TPMProvisionResponse{}, nil
}
func (f *cov964TPMServer) Clear(_ context.Context, r *platformv1.TPMClearRequest) (*platformv1.TPMClearResponse, error) {
	f.got = r
	return &platformv1.TPMClearResponse{}, nil
}
func (f *cov964TPMServer) CreateEK(_ context.Context, r *platformv1.CreateEKRequest) (*platformv1.CreateEKResponse, error) {
	f.got = r
	return &platformv1.CreateEKResponse{}, nil
}
func (f *cov964TPMServer) GetEK(_ context.Context, r *platformv1.GetEKRequest) (*platformv1.GetEKResponse, error) {
	f.got = r
	return &platformv1.GetEKResponse{}, nil
}
func (f *cov964TPMServer) GetEKCertificate(_ context.Context, r *platformv1.GetEKCertificateRequest) (*platformv1.GetEKCertificateResponse, error) {
	f.got = r
	return &platformv1.GetEKCertificateResponse{}, nil
}
func (f *cov964TPMServer) ImportEKCertificate(_ context.Context, r *platformv1.ImportEKCertificateRequest) (*platformv1.ImportEKCertificateResponse, error) {
	f.got = r
	return &platformv1.ImportEKCertificateResponse{}, nil
}
func (f *cov964TPMServer) DeleteEK(_ context.Context, r *platformv1.DeleteEKRequest) (*platformv1.DeleteEKResponse, error) {
	f.got = r
	return &platformv1.DeleteEKResponse{}, nil
}
func (f *cov964TPMServer) CreateSRK(_ context.Context, r *platformv1.CreateSRKRequest) (*platformv1.CreateSRKResponse, error) {
	f.got = r
	return &platformv1.CreateSRKResponse{}, nil
}
func (f *cov964TPMServer) GetSRK(_ context.Context, r *platformv1.GetSRKRequest) (*platformv1.GetSRKResponse, error) {
	f.got = r
	return &platformv1.GetSRKResponse{}, nil
}
func (f *cov964TPMServer) DeleteSRK(_ context.Context, r *platformv1.DeleteSRKRequest) (*platformv1.DeleteSRKResponse, error) {
	f.got = r
	return &platformv1.DeleteSRKResponse{}, nil
}
func (f *cov964TPMServer) CreateAK(_ context.Context, r *platformv1.CreateAKRequest) (*platformv1.CreateAKResponse, error) {
	f.got = r
	return &platformv1.CreateAKResponse{}, nil
}
func (f *cov964TPMServer) GetAK(_ context.Context, r *platformv1.GetAKRequest) (*platformv1.GetAKResponse, error) {
	f.got = r
	return &platformv1.GetAKResponse{}, nil
}
func (f *cov964TPMServer) DeleteAK(_ context.Context, r *platformv1.DeleteAKRequest) (*platformv1.DeleteAKResponse, error) {
	f.got = r
	return &platformv1.DeleteAKResponse{}, nil
}
func (f *cov964TPMServer) Seal(_ context.Context, r *platformv1.SealRequest) (*platformv1.SealResponse, error) {
	f.got = r
	return &platformv1.SealResponse{}, nil
}
func (f *cov964TPMServer) Unseal(_ context.Context, r *platformv1.UnsealRequest) (*platformv1.UnsealResponse, error) {
	f.got = r
	return &platformv1.UnsealResponse{}, nil
}
func (f *cov964TPMServer) GetEventLog(_ context.Context, r *platformv1.GetEventLogRequest) (*platformv1.GetEventLogResponse, error) {
	f.got = r
	return &platformv1.GetEventLogResponse{}, nil
}
func (f *cov964TPMServer) GetPCRs(_ context.Context, r *platformv1.GetPCRsRequest) (*platformv1.GetPCRsResponse, error) {
	f.got = r
	return &platformv1.GetPCRsResponse{}, nil
}
func (f *cov964TPMServer) DefineNVRAM(_ context.Context, r *platformv1.DefineNVRAMRequest) (*platformv1.DefineNVRAMResponse, error) {
	f.got = r
	return &platformv1.DefineNVRAMResponse{}, nil
}
func (f *cov964TPMServer) WriteNVRAM(_ context.Context, r *platformv1.WriteNVRAMRequest) (*platformv1.WriteNVRAMResponse, error) {
	f.got = r
	return &platformv1.WriteNVRAMResponse{}, nil
}
func (f *cov964TPMServer) ReadNVRAM(_ context.Context, r *platformv1.ReadNVRAMRequest) (*platformv1.ReadNVRAMResponse, error) {
	f.got = r
	return &platformv1.ReadNVRAMResponse{}, nil
}
func (f *cov964TPMServer) UndefineNVRAM(_ context.Context, r *platformv1.UndefineNVRAMRequest) (*platformv1.UndefineNVRAMResponse, error) {
	f.got = r
	return &platformv1.UndefineNVRAMResponse{}, nil
}
func (f *cov964TPMServer) GetRandom(_ context.Context, r *platformv1.GetRandomRequest) (*platformv1.GetRandomResponse, error) {
	f.got = r
	return &platformv1.GetRandomResponse{}, nil
}

type cov964VTPMServer struct {
	platformv1.UnimplementedVTPMServiceServer
	cov964Recorder
}

func (f *cov964VTPMServer) CreateBundle(_ context.Context, r *platformv1.CreateBundleRequest) (*platformv1.CreateBundleResponse, error) {
	f.got = r
	return &platformv1.CreateBundleResponse{}, nil
}
func (f *cov964VTPMServer) GetBundle(_ context.Context, r *platformv1.GetBundleRequest) (*platformv1.GetBundleResponse, error) {
	f.got = r
	return &platformv1.GetBundleResponse{}, nil
}
func (f *cov964VTPMServer) DeleteBundle(_ context.Context, r *platformv1.DeleteBundleRequest) (*platformv1.DeleteBundleResponse, error) {
	f.got = r
	return &platformv1.DeleteBundleResponse{}, nil
}
func (f *cov964VTPMServer) ListBundles(_ context.Context, r *platformv1.ListBundlesRequest) (*platformv1.ListBundlesResponse, error) {
	f.got = r
	return &platformv1.ListBundlesResponse{}, nil
}
func (f *cov964VTPMServer) CreateTemplate(_ context.Context, r *platformv1.CreateTemplateRequest) (*platformv1.CreateTemplateResponse, error) {
	f.got = r
	return &platformv1.CreateTemplateResponse{}, nil
}
func (f *cov964VTPMServer) GetTemplate(_ context.Context, r *platformv1.GetTemplateRequest) (*platformv1.GetTemplateResponse, error) {
	f.got = r
	return &platformv1.GetTemplateResponse{}, nil
}
func (f *cov964VTPMServer) DeleteTemplate(_ context.Context, r *platformv1.DeleteTemplateRequest) (*platformv1.DeleteTemplateResponse, error) {
	f.got = r
	return &platformv1.DeleteTemplateResponse{}, nil
}
func (f *cov964VTPMServer) ListTemplates(_ context.Context, r *platformv1.ListTemplatesRequest) (*platformv1.ListTemplatesResponse, error) {
	f.got = r
	return &platformv1.ListTemplatesResponse{}, nil
}
func (f *cov964VTPMServer) CloneTemplate(_ context.Context, r *platformv1.CloneTemplateRequest) (*platformv1.CloneTemplateResponse, error) {
	f.got = r
	return &platformv1.CloneTemplateResponse{}, nil
}
func (f *cov964VTPMServer) ValidateBundle(_ context.Context, r *platformv1.ValidateBundleRequest) (*platformv1.ValidateBundleResponse, error) {
	f.got = r
	return &platformv1.ValidateBundleResponse{}, nil
}
func (f *cov964VTPMServer) GetBundlePath(_ context.Context, r *platformv1.GetBundlePathRequest) (*platformv1.GetBundlePathResponse, error) {
	f.got = r
	return &platformv1.GetBundlePathResponse{}, nil
}
func (f *cov964VTPMServer) GetTPMSocketPath(_ context.Context, r *platformv1.GetTPMSocketPathRequest) (*platformv1.GetTPMSocketPathResponse, error) {
	f.got = r
	return &platformv1.GetTPMSocketPathResponse{}, nil
}
func (f *cov964VTPMServer) GetNVRAMPath(_ context.Context, r *platformv1.GetNVRAMPathRequest) (*platformv1.GetNVRAMPathResponse, error) {
	f.got = r
	return &platformv1.GetNVRAMPathResponse{}, nil
}
func (f *cov964VTPMServer) StartVTPM(_ context.Context, r *platformv1.StartVTPMRequest) (*platformv1.StartVTPMResponse, error) {
	f.got = r
	return &platformv1.StartVTPMResponse{}, nil
}
func (f *cov964VTPMServer) StopVTPM(_ context.Context, r *platformv1.StopVTPMRequest) (*platformv1.StopVTPMResponse, error) {
	f.got = r
	return &platformv1.StopVTPMResponse{}, nil
}
func (f *cov964VTPMServer) IsVTPMRunning(_ context.Context, r *platformv1.IsVTPMRunningRequest) (*platformv1.IsVTPMRunningResponse, error) {
	f.got = r
	return &platformv1.IsVTPMRunningResponse{}, nil
}
func (f *cov964VTPMServer) QuoteVTPM(_ context.Context, r *platformv1.QuoteVTPMRequest) (*platformv1.QuoteVTPMResponse, error) {
	f.got = r
	return &platformv1.QuoteVTPMResponse{}, nil
}
func (f *cov964VTPMServer) SealVTPM(_ context.Context, r *platformv1.SealVTPMRequest) (*platformv1.SealVTPMResponse, error) {
	f.got = r
	return &platformv1.SealVTPMResponse{}, nil
}
func (f *cov964VTPMServer) UnsealVTPM(_ context.Context, r *platformv1.UnsealVTPMRequest) (*platformv1.UnsealVTPMResponse, error) {
	f.got = r
	return &platformv1.UnsealVTPMResponse{}, nil
}
func (f *cov964VTPMServer) ExtendVTPMPCR(_ context.Context, r *platformv1.ExtendVTPMPCRRequest) (*platformv1.ExtendVTPMPCRResponse, error) {
	f.got = r
	return &platformv1.ExtendVTPMPCRResponse{}, nil
}
func (f *cov964VTPMServer) ReadVTPMPCR(_ context.Context, r *platformv1.ReadVTPMPCRRequest) (*platformv1.ReadVTPMPCRResponse, error) {
	f.got = r
	return &platformv1.ReadVTPMPCRResponse{}, nil
}

type cov964DeviceServer struct {
	platformv1.UnimplementedDeviceServiceServer
	cov964Recorder
}

func (f *cov964DeviceServer) CreateDevice(_ context.Context, r *platformv1.CreateDeviceRequest) (*platformv1.CreateDeviceResponse, error) {
	f.got = r
	return &platformv1.CreateDeviceResponse{}, nil
}
func (f *cov964DeviceServer) GetDevice(_ context.Context, r *platformv1.GetDeviceRequest) (*platformv1.GetDeviceResponse, error) {
	f.got = r
	return &platformv1.GetDeviceResponse{}, nil
}
func (f *cov964DeviceServer) UpdateDevice(_ context.Context, r *platformv1.UpdateDeviceRequest) (*platformv1.UpdateDeviceResponse, error) {
	f.got = r
	return &platformv1.UpdateDeviceResponse{}, nil
}
func (f *cov964DeviceServer) DeleteDevice(_ context.Context, r *platformv1.DeleteDeviceRequest) (*platformv1.DeleteDeviceResponse, error) {
	f.got = r
	return &platformv1.DeleteDeviceResponse{}, nil
}
func (f *cov964DeviceServer) ListDevices(_ context.Context, r *platformv1.ListDevicesRequest) (*platformv1.ListDevicesResponse, error) {
	f.got = r
	return &platformv1.ListDevicesResponse{}, nil
}
func (f *cov964DeviceServer) FindDeviceBySerial(_ context.Context, r *platformv1.FindDeviceBySerialRequest) (*platformv1.FindDeviceBySerialResponse, error) {
	f.got = r
	return &platformv1.FindDeviceBySerialResponse{}, nil
}
func (f *cov964DeviceServer) CountDevices(_ context.Context, r *platformv1.CountDevicesRequest) (*platformv1.CountDevicesResponse, error) {
	f.got = r
	return &platformv1.CountDevicesResponse{}, nil
}
func (f *cov964DeviceServer) CreateProfile(_ context.Context, r *platformv1.CreateProfileRequest) (*platformv1.CreateProfileResponse, error) {
	f.got = r
	return &platformv1.CreateProfileResponse{}, nil
}
func (f *cov964DeviceServer) GetProfile(_ context.Context, r *platformv1.GetProfileRequest) (*platformv1.GetProfileResponse, error) {
	f.got = r
	return &platformv1.GetProfileResponse{}, nil
}
func (f *cov964DeviceServer) UpdateProfile(_ context.Context, r *platformv1.UpdateProfileRequest) (*platformv1.UpdateProfileResponse, error) {
	f.got = r
	return &platformv1.UpdateProfileResponse{}, nil
}
func (f *cov964DeviceServer) DeleteProfile(_ context.Context, r *platformv1.DeleteProfileRequest) (*platformv1.DeleteProfileResponse, error) {
	f.got = r
	return &platformv1.DeleteProfileResponse{}, nil
}
func (f *cov964DeviceServer) ListProfiles(_ context.Context, r *platformv1.ListProfilesRequest) (*platformv1.ListProfilesResponse, error) {
	f.got = r
	return &platformv1.ListProfilesResponse{}, nil
}
func (f *cov964DeviceServer) FindProfileByMACAddress(_ context.Context, r *platformv1.FindProfileByMACAddressRequest) (*platformv1.FindProfileByMACAddressResponse, error) {
	f.got = r
	return &platformv1.FindProfileByMACAddressResponse{}, nil
}
func (f *cov964DeviceServer) FindProfileBySerial(_ context.Context, r *platformv1.FindProfileBySerialRequest) (*platformv1.FindProfileBySerialResponse, error) {
	f.got = r
	return &platformv1.FindProfileBySerialResponse{}, nil
}
func (f *cov964DeviceServer) FindMatchingProfile(_ context.Context, r *platformv1.FindMatchingProfileRequest) (*platformv1.FindMatchingProfileResponse, error) {
	f.got = r
	return &platformv1.FindMatchingProfileResponse{}, nil
}
func (f *cov964DeviceServer) CountProfiles(_ context.Context, r *platformv1.CountProfilesRequest) (*platformv1.CountProfilesResponse, error) {
	f.got = r
	return &platformv1.CountProfilesResponse{}, nil
}
func (f *cov964DeviceServer) ActivateDevice(_ context.Context, r *platformv1.ActivateDeviceRequest) (*platformv1.ActivateDeviceResponse, error) {
	f.got = r
	return &platformv1.ActivateDeviceResponse{}, nil
}
func (f *cov964DeviceServer) AssignProfileToDevice(_ context.Context, r *platformv1.AssignProfileToDeviceRequest) (*platformv1.AssignProfileToDeviceResponse, error) {
	f.got = r
	return &platformv1.AssignProfileToDeviceResponse{}, nil
}
func (f *cov964DeviceServer) UnassignProfileFromDevice(_ context.Context, r *platformv1.UnassignProfileFromDeviceRequest) (*platformv1.UnassignProfileFromDeviceResponse, error) {
	f.got = r
	return &platformv1.UnassignProfileFromDeviceResponse{}, nil
}

type cov964ComputeServer struct {
	platformv1.UnimplementedComputeServiceServer
	cov964Recorder
}

func (f *cov964ComputeServer) CreateVM(_ context.Context, r *platformv1.CreateVMRequest) (*platformv1.CreateVMResponse, error) {
	f.got = r
	return &platformv1.CreateVMResponse{}, nil
}
func (f *cov964ComputeServer) StartVM(_ context.Context, r *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	f.got = r
	return &platformv1.StartVMResponse{}, nil
}
func (f *cov964ComputeServer) StopVM(_ context.Context, r *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	f.got = r
	return &platformv1.StopVMResponse{}, nil
}
func (f *cov964ComputeServer) DeleteVM(_ context.Context, r *platformv1.DeleteVMRequest) (*platformv1.DeleteVMResponse, error) {
	f.got = r
	return &platformv1.DeleteVMResponse{}, nil
}
func (f *cov964ComputeServer) GetVM(_ context.Context, r *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	f.got = r
	return &platformv1.GetVMResponse{}, nil
}
func (f *cov964ComputeServer) ListVMs(_ context.Context, r *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	f.got = r
	return &platformv1.ListVMsResponse{}, nil
}
func (f *cov964ComputeServer) GetVMMetrics(_ context.Context, r *platformv1.GetVMMetricsRequest) (*platformv1.VMMetricsResponse, error) {
	f.got = r
	return &platformv1.VMMetricsResponse{}, nil
}
func (f *cov964ComputeServer) CreateContainer(_ context.Context, r *platformv1.CreateContainerRequest) (*platformv1.CreateContainerResponse, error) {
	f.got = r
	return &platformv1.CreateContainerResponse{}, nil
}
func (f *cov964ComputeServer) StartContainer(_ context.Context, r *platformv1.StartContainerRequest) (*platformv1.StartContainerResponse, error) {
	f.got = r
	return &platformv1.StartContainerResponse{}, nil
}
func (f *cov964ComputeServer) StopContainer(_ context.Context, r *platformv1.StopContainerRequest) (*platformv1.StopContainerResponse, error) {
	f.got = r
	return &platformv1.StopContainerResponse{}, nil
}
func (f *cov964ComputeServer) DeleteContainer(_ context.Context, r *platformv1.DeleteContainerRequest) (*platformv1.DeleteContainerResponse, error) {
	f.got = r
	return &platformv1.DeleteContainerResponse{}, nil
}
func (f *cov964ComputeServer) GetContainer(_ context.Context, r *platformv1.GetContainerRequest) (*platformv1.GetContainerResponse, error) {
	f.got = r
	return &platformv1.GetContainerResponse{}, nil
}
func (f *cov964ComputeServer) ListContainers(_ context.Context, r *platformv1.ListContainersRequest) (*platformv1.ListContainersResponse, error) {
	f.got = r
	return &platformv1.ListContainersResponse{}, nil
}
func (f *cov964ComputeServer) GetContainerMetrics(_ context.Context, r *platformv1.GetContainerMetricsRequest) (*platformv1.ContainerMetricsResponse, error) {
	f.got = r
	return &platformv1.ContainerMetricsResponse{}, nil
}
func (f *cov964ComputeServer) ExecContainer(_ context.Context, r *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	f.got = r
	return &platformv1.ExecContainerResponse{}, nil
}
func (f *cov964ComputeServer) CreateSnapshot(_ context.Context, r *platformv1.CreateSnapshotRequest) (*platformv1.CreateSnapshotResponse, error) {
	f.got = r
	return &platformv1.CreateSnapshotResponse{}, nil
}
func (f *cov964ComputeServer) ListSnapshots(_ context.Context, r *platformv1.ListSnapshotsRequest) (*platformv1.ListSnapshotsResponse, error) {
	f.got = r
	return &platformv1.ListSnapshotsResponse{}, nil
}
func (f *cov964ComputeServer) DeleteSnapshot(_ context.Context, r *platformv1.DeleteSnapshotRequest) (*platformv1.DeleteSnapshotResponse, error) {
	f.got = r
	return &platformv1.DeleteSnapshotResponse{}, nil
}
func (f *cov964ComputeServer) RestoreSnapshot(_ context.Context, r *platformv1.RestoreSnapshotRequest) (*platformv1.RestoreSnapshotResponse, error) {
	f.got = r
	return &platformv1.RestoreSnapshotResponse{}, nil
}
func (f *cov964ComputeServer) AttestVM(_ context.Context, r *platformv1.AttestVMRequest) (*platformv1.AttestVMResponse, error) {
	f.got = r
	return &platformv1.AttestVMResponse{}, nil
}

type cov964SDNServer struct {
	platformv1.UnimplementedSDNServiceServer
	cov964Recorder
}

func (f *cov964SDNServer) CreateBridge(_ context.Context, r *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
	f.got = r
	return &platformv1.CreateBridgeResponse{}, nil
}
func (f *cov964SDNServer) DeleteBridge(_ context.Context, r *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
	f.got = r
	return &platformv1.DeleteBridgeResponse{}, nil
}
func (f *cov964SDNServer) GetBridge(_ context.Context, r *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
	f.got = r
	return &platformv1.GetBridgeResponse{}, nil
}
func (f *cov964SDNServer) ListBridges(_ context.Context, r *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
	f.got = r
	return &platformv1.ListBridgesResponse{}, nil
}
func (f *cov964SDNServer) AddPort(_ context.Context, r *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
	f.got = r
	return &platformv1.AddPortResponse{}, nil
}
func (f *cov964SDNServer) DeletePort(_ context.Context, r *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
	f.got = r
	return &platformv1.DeletePortResponse{}, nil
}
func (f *cov964SDNServer) GetPort(_ context.Context, r *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
	f.got = r
	return &platformv1.GetPortResponse{}, nil
}
func (f *cov964SDNServer) ListPorts(_ context.Context, r *platformv1.ListPortsRequest) (*platformv1.ListPortsResponse, error) {
	f.got = r
	return &platformv1.ListPortsResponse{}, nil
}
func (f *cov964SDNServer) AddFlow(_ context.Context, r *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
	f.got = r
	return &platformv1.AddFlowResponse{}, nil
}
func (f *cov964SDNServer) DeleteFlow(_ context.Context, r *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
	f.got = r
	return &platformv1.DeleteFlowResponse{}, nil
}
func (f *cov964SDNServer) ListFlows(_ context.Context, r *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
	f.got = r
	return &platformv1.ListFlowsResponse{}, nil
}
func (f *cov964SDNServer) FlushFlows(_ context.Context, r *platformv1.FlushFlowsRequest) (*platformv1.FlushFlowsResponse, error) {
	f.got = r
	return &platformv1.FlushFlowsResponse{}, nil
}
func (f *cov964SDNServer) CreateVLAN(_ context.Context, r *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	f.got = r
	return &platformv1.CreateVLANResponse{}, nil
}
func (f *cov964SDNServer) DeleteVLAN(_ context.Context, r *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error) {
	f.got = r
	return &platformv1.DeleteVLANResponse{}, nil
}
func (f *cov964SDNServer) ListVLANs(_ context.Context, r *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	f.got = r
	return &platformv1.ListVLANsResponse{}, nil
}
func (f *cov964SDNServer) AuthenticatePort(_ context.Context, r *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
	f.got = r
	return &platformv1.AuthenticatePortResponse{}, nil
}
func (f *cov964SDNServer) RevokePortAuth(_ context.Context, r *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
	f.got = r
	return &platformv1.RevokePortAuthResponse{}, nil
}
func (f *cov964SDNServer) GetPortStats(_ context.Context, r *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
	f.got = r
	return &platformv1.GetPortStatsResponse{}, nil
}
func (f *cov964SDNServer) GetFlowStats(_ context.Context, r *platformv1.GetFlowStatsRequest) (*platformv1.GetFlowStatsResponse, error) {
	f.got = r
	return &platformv1.GetFlowStatsResponse{}, nil
}

// cov964Sent is one successful call and the request the binding must send.
type cov964Sent struct {
	name string
	call func() (map[string]interface{}, error)
	want proto.Message
}

// cov964CheckSent runs each call against a fake that answers, and checks
// the binding sent exactly the request its arguments describe and handed
// the answer back as a map.
func cov964CheckSent(t *testing.T, rec *cov964Recorder, tests []cov964Sent) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec.got = nil
			got, err := tc.call()
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got == nil {
				t.Fatal("result map is nil")
			}
			if !proto.Equal(rec.got, tc.want) {
				t.Fatalf("request = %v, want %v", rec.got, tc.want)
			}
		})
	}
}

func TestCov964_TPMSendsTheRequestItsArgumentsDescribe(t *testing.T) {
	fake := &cov964TPMServer{}
	reg := cov964Registry()
	reg.TPM = fake
	b := cov964NewSet(cov964Connected(t, reg)).tpm
	ecc := platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	sha256 := platformv1.PCRBank_PCR_BANK_SHA256
	cov964CheckSent(t, &fake.cov964Recorder, []cov964Sent{
		{"Info", b.Info, &platformv1.TPMInfoRequest{}},
		{"Provision", func() (map[string]interface{}, error) { return b.Provision("o", "e", true, false, true) },
			&platformv1.TPMProvisionRequest{OwnerPassword: "o", EndorsementPassword: "e", CreateEk: true, CreateAk: true}},
		{"Clear", func() (map[string]interface{}, error) { return b.Clear("o", true) },
			&platformv1.TPMClearRequest{OwnerPassword: "o", Confirm: true}},
		{"CreateEK", func() (map[string]interface{}, error) { return b.CreateEK(true) }, &platformv1.CreateEKRequest{Persistent: true}},
		{"GetEK", func() (map[string]interface{}, error) { return b.GetEK("ecdsa_p256", 0x81010001) },
			&platformv1.GetEKRequest{Algorithm: ecc, Handle: 0x81010001}},
		{"GetEKCertificate", func() (map[string]interface{}, error) { return b.GetEKCertificate("KEY_ALGORITHM_ECDSA_P256", 7) },
			&platformv1.GetEKCertificateRequest{Algorithm: ecc, Handle: 7}},
		{"ImportEKCertificate", func() (map[string]interface{}, error) { return b.ImportEKCertificate([]byte("der"), "der", 0x01c00002) },
			&platformv1.ImportEKCertificateRequest{Certificate: []byte("der"), Format: "der", NvramIndex: 0x01c00002}},
		{"DeleteEK", func() (map[string]interface{}, error) { return b.DeleteEK(7, "ecdsa_p256", "p") },
			&platformv1.DeleteEKRequest{Handle: 7, Algorithm: ecc, Password: "p"}},
		{"CreateSRK", func() (map[string]interface{}, error) { return b.CreateSRK(true, 7, "pp") },
			&platformv1.CreateSRKRequest{Persistent: true, ParentHandle: 7, ParentPassword: "pp"}},
		{"GetSRK", func() (map[string]interface{}, error) { return b.GetSRK("ecdsa_p256", 8) },
			&platformv1.GetSRKRequest{Algorithm: ecc, Handle: 8}},
		{"DeleteSRK", func() (map[string]interface{}, error) { return b.DeleteSRK(8, "ecdsa_p256", "p") },
			&platformv1.DeleteSRKRequest{Handle: 8, Algorithm: ecc, Password: "p"}},
		{"CreateAK", func() (map[string]interface{}, error) { return b.CreateAK(false, 8, "pp") },
			&platformv1.CreateAKRequest{ParentHandle: 8, ParentPassword: "pp"}},
		{"GetAK", func() (map[string]interface{}, error) { return b.GetAK("ecdsa_p256", 9) },
			&platformv1.GetAKRequest{Algorithm: ecc, Handle: 9}},
		{"DeleteAK", func() (map[string]interface{}, error) { return b.DeleteAK(9, "ecdsa_p256", "p") },
			&platformv1.DeleteAKRequest{Handle: 9, Algorithm: ecc, Password: "p"}},
		{"Seal", func() (map[string]interface{}, error) {
			return b.Seal([]byte("d"), "cn", 8, "pp", "p", []uint32{7}, "sha256", true)
		}, &platformv1.SealRequest{Data: []byte("d"), Cn: "cn", ParentHandle: 8, ParentPassword: "pp", Password: "p",
			PcrIndices: []uint32{7}, PcrBank: sha256, Overwrite: true}},
		{"Unseal", func() (map[string]interface{}, error) {
			return b.Unseal("cn", 8, "pp", "p", []uint32{7}, "PCR_BANK_SHA256")
		},
			&platformv1.UnsealRequest{Cn: "cn", ParentHandle: 8, ParentPassword: "pp", Password: "p", PcrIndices: []uint32{7}, PcrBank: sha256}},
		{"GetEventLog", func() (map[string]interface{}, error) { return b.GetEventLog("json") }, &platformv1.GetEventLogRequest{Format: "json"}},
		{"GetPCRs", func() (map[string]interface{}, error) { return b.GetPCRs([]uint32{0, 7}, "sha256") },
			&platformv1.GetPCRsRequest{Indices: []uint32{0, 7}, Bank: sha256}},
		{"DefineNVRAM", func() (map[string]interface{}, error) {
			return b.DefineNVRAM(0x01500000, 32, "p", []string{"ownerwrite"})
		},
			&platformv1.DefineNVRAMRequest{Index: 0x01500000, Size: 32, Password: "p", Attributes: []string{"ownerwrite"}}},
		{"WriteNVRAM", func() (map[string]interface{}, error) { return b.WriteNVRAM(0x01500000, []byte("d"), "p", 4) },
			&platformv1.WriteNVRAMRequest{Index: 0x01500000, Data: []byte("d"), Password: "p", Offset: 4}},
		{"ReadNVRAM", func() (map[string]interface{}, error) { return b.ReadNVRAM(0x01500000, "p", 4, 8) },
			&platformv1.ReadNVRAMRequest{Index: 0x01500000, Password: "p", Offset: 4, Size: 8}},
		{"UndefineNVRAM", func() (map[string]interface{}, error) { return b.UndefineNVRAM(0x01500000, "p") },
			&platformv1.UndefineNVRAMRequest{Index: 0x01500000, Password: "p"}},
		{"GetRandom", func() (map[string]interface{}, error) { return b.GetRandom(16) }, &platformv1.GetRandomRequest{NumBytes: 16}},
	})
}

func TestCov964_VTPMSendsTheRequestItsArgumentsDescribe(t *testing.T) {
	fake := &cov964VTPMServer{}
	reg := cov964Registry()
	reg.VTPM = fake
	b := cov964NewSet(cov964Connected(t, reg)).vtpm
	labels := map[string]string{"env": "lab"}
	rsa := platformv1.EKAlgorithm_EK_ALGORITHM_RSA
	template := platformv1.BundleMode_BUNDLE_MODE_TEMPLATE
	cov964CheckSent(t, &fake.cov964Recorder, []cov964Sent{
		{"CreateBundle", func() (map[string]interface{}, error) {
			return b.CreateBundle("template", "h", "rsa", "tpl", true, labels)
		},
			&platformv1.CreateBundleRequest{Options: &platformv1.CreateBundleOptions{Mode: template, Hostname: "h", EkAlgorithm: rsa,
				SecureBootEnabled: true, Labels: labels, TemplateId: "tpl"}}},
		{"GetBundle", func() (map[string]interface{}, error) { return b.GetBundle("b1") }, &platformv1.GetBundleRequest{Id: "b1"}},
		{"DeleteBundle", func() (map[string]interface{}, error) { return b.DeleteBundle("b1") }, &platformv1.DeleteBundleRequest{Id: "b1"}},
		{"ListBundles", func() (map[string]interface{}, error) { return b.ListBundles("", labels, 10, 20) },
			&platformv1.ListBundlesRequest{Options: &platformv1.ListBundleOptions{Labels: labels, Limit: 10, Offset: 20}}},
		{"CreateTemplate", func() (map[string]interface{}, error) { return b.CreateTemplate("tpl", "d", "EK_ALGORITHM_RSA", true) },
			&platformv1.CreateTemplateRequest{Options: &platformv1.CreateTemplateOptions{Id: "tpl", Description: "d", EkAlgorithm: rsa, SecureBootEnabled: true}}},
		{"GetTemplate", func() (map[string]interface{}, error) { return b.GetTemplate("tpl") }, &platformv1.GetTemplateRequest{Id: "tpl"}},
		{"DeleteTemplate", func() (map[string]interface{}, error) { return b.DeleteTemplate("tpl") }, &platformv1.DeleteTemplateRequest{Id: "tpl"}},
		{"ListTemplates", b.ListTemplates, &platformv1.ListTemplatesRequest{}},
		{"CloneTemplate", func() (map[string]interface{}, error) { return b.CloneTemplate("tpl", "h", labels) },
			&platformv1.CloneTemplateRequest{Options: &platformv1.CloneOptions{TemplateId: "tpl", Hostname: "h", Labels: labels}}},
		{"ValidateBundle", func() (map[string]interface{}, error) { return b.ValidateBundle("b1") }, &platformv1.ValidateBundleRequest{Id: "b1"}},
		{"GetBundlePath", func() (map[string]interface{}, error) { return b.GetBundlePath("b1") }, &platformv1.GetBundlePathRequest{Id: "b1"}},
		{"GetTPMSocketPath", func() (map[string]interface{}, error) { return b.GetTPMSocketPath("b1") }, &platformv1.GetTPMSocketPathRequest{Id: "b1"}},
		{"GetNVRAMPath", func() (map[string]interface{}, error) { return b.GetNVRAMPath("b1") }, &platformv1.GetNVRAMPathRequest{Id: "b1"}},
		{"StartVTPM", func() (map[string]interface{}, error) { return b.StartVTPM("b1") }, &platformv1.StartVTPMRequest{BundleId: "b1"}},
		{"StopVTPM", func() (map[string]interface{}, error) { return b.StopVTPM("b1") }, &platformv1.StopVTPMRequest{BundleId: "b1"}},
		{"IsVTPMRunning", func() (map[string]interface{}, error) { return b.IsVTPMRunning("b1") }, &platformv1.IsVTPMRunningRequest{BundleId: "b1"}},
		{"QuoteVTPM", func() (map[string]interface{}, error) { return b.QuoteVTPM("b1", []byte("n"), []int32{0, 7}) },
			&platformv1.QuoteVTPMRequest{BundleId: "b1", Nonce: []byte("n"), Pcrs: []int32{0, 7}}},
		{"SealVTPM", func() (map[string]interface{}, error) { return b.SealVTPM("b1", []byte("d"), []int32{7}, "a") },
			&platformv1.SealVTPMRequest{BundleId: "b1", Data: []byte("d"), Pcrs: []int32{7}, AuthValue: "a"}},
		{"UnsealVTPM", func() (map[string]interface{}, error) { return b.UnsealVTPM("b1", []byte("s"), "a") },
			&platformv1.UnsealVTPMRequest{BundleId: "b1", SealedData: []byte("s"), AuthValue: "a"}},
		{"ExtendVTPMPCR", func() (map[string]interface{}, error) { return b.ExtendVTPMPCR("b1", 16, []byte("d")) },
			&platformv1.ExtendVTPMPCRRequest{BundleId: "b1", PcrIndex: 16, Data: []byte("d")}},
		{"ReadVTPMPCR", func() (map[string]interface{}, error) { return b.ReadVTPMPCR("b1", 16) },
			&platformv1.ReadVTPMPCRRequest{BundleId: "b1", PcrIndex: 16}},
	})
}

func TestCov964_DeviceSendsTheRequestItsArgumentsDescribe(t *testing.T) {
	fake := &cov964DeviceServer{}
	reg := cov964Registry()
	reg.Device = fake
	b := cov964NewSet(cov964Connected(t, reg)).device
	mac := "aa:bb:cc:dd:ee:ff"
	server := platformv1.DeviceRole_DEVICE_ROLE_SERVER
	page := &platformv1.PaginationRequest{Page: 2, PageSize: 10, SortBy: "id", Ascending: true}
	device := &platformv1.Device{AttestPub: "ap", AttestCert: "ac", EkCert: "ek", EventLog: []byte("log"),
		HashAlgoId: 11, Model: "m", Serial: "sn", SigningPub: "sp"}
	updated := proto.Clone(device).(*platformv1.Device)
	updated.Id = 5
	cov964CheckSent(t, &fake.cov964Recorder, []cov964Sent{
		{"CreateDevice", func() (map[string]interface{}, error) {
			return b.CreateDevice("ap", "ac", "ek", []byte("log"), 11, "m", "sn", "sp")
		}, &platformv1.CreateDeviceRequest{Device: device}},
		{"GetDevice", func() (map[string]interface{}, error) { return b.GetDevice(5) }, &platformv1.GetDeviceRequest{Id: 5}},
		{"UpdateDevice", func() (map[string]interface{}, error) {
			return b.UpdateDevice(5, "ap", "ac", "ek", []byte("log"), 11, "m", "sn", "sp")
		}, &platformv1.UpdateDeviceRequest{Device: updated}},
		{"DeleteDevice", func() (map[string]interface{}, error) { return b.DeleteDevice(5) }, &platformv1.DeleteDeviceRequest{Id: 5}},
		{"ListDevices", func() (map[string]interface{}, error) { return b.ListDevices(2, 10, "id", true) },
			&platformv1.ListDevicesRequest{Pagination: page}},
		{"FindDeviceBySerial", func() (map[string]interface{}, error) { return b.FindDeviceBySerial("sn") },
			&platformv1.FindDeviceBySerialRequest{Serial: "sn"}},
		{"CountDevices", b.CountDevices, &platformv1.CountDevicesRequest{}},
		{"CreateProfile", func() (map[string]interface{}, error) { return b.CreateProfile("p", "m", "server") },
			&platformv1.CreateProfileRequest{Profile: &platformv1.DeviceProfile{Name: "p", Model: "m", Role: server}}},
		{"GetProfile", func() (map[string]interface{}, error) { return b.GetProfile(3) }, &platformv1.GetProfileRequest{Id: 3}},
		{"UpdateProfile", func() (map[string]interface{}, error) { return b.UpdateProfile(3, "p", "m", "") },
			&platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{Id: 3, Name: "p", Model: "m"}}},
		{"DeleteProfile", func() (map[string]interface{}, error) { return b.DeleteProfile(3) }, &platformv1.DeleteProfileRequest{Id: 3}},
		{"ListProfiles", func() (map[string]interface{}, error) { return b.ListProfiles(2, 10, "id", true) },
			&platformv1.ListProfilesRequest{Pagination: page}},
		{"FindProfileByMACAddress", func() (map[string]interface{}, error) { return b.FindProfileByMACAddress(mac) },
			&platformv1.FindProfileByMACAddressRequest{MacAddress: mac}},
		{"FindProfileBySerial", func() (map[string]interface{}, error) { return b.FindProfileBySerial("sn") },
			&platformv1.FindProfileBySerialRequest{Serial: "sn"}},
		{"FindMatchingProfile", func() (map[string]interface{}, error) { return b.FindMatchingProfile(mac, "sn", "m") },
			&platformv1.FindMatchingProfileRequest{MacAddress: mac, Serial: "sn", Model: "m"}},
		{"CountProfiles", b.CountProfiles, &platformv1.CountProfilesRequest{}},
		{"ActivateDevice", func() (map[string]interface{}, error) { return b.ActivateDevice("sn", mac) },
			&platformv1.ActivateDeviceRequest{Serial: "sn", MacAddress: mac}},
		{"AssignProfileToDevice", func() (map[string]interface{}, error) { return b.AssignProfileToDevice(3, 5, "eksn", mac, "pem") },
			&platformv1.AssignProfileToDeviceRequest{ProfileId: 3, DeviceId: 5, EkSerial: "eksn", MacAddress: mac, EkCert: "pem"}},
		{"UnassignProfileFromDevice", func() (map[string]interface{}, error) { return b.UnassignProfileFromDevice(3) },
			&platformv1.UnassignProfileFromDeviceRequest{ProfileId: 3}},
	})
}

func TestCov964_ComputeSendsTheRequestItsArgumentsDescribe(t *testing.T) {
	fake := &cov964ComputeServer{}
	reg := cov964Registry()
	reg.Compute = fake
	b := cov964NewSet(cov964Connected(t, reg)).compute
	cov964CheckSent(t, &fake.cov964Recorder, []cov964Sent{
		{"CreateVM", func() (map[string]interface{}, error) { return b.CreateVM("vm", "d", true) },
			&platformv1.CreateVMRequest{Config: &platformv1.VMConfig{Name: "vm", Description: "d"}, Start: true}},
		{"StartVM", func() (map[string]interface{}, error) { return b.StartVM("vm1") }, &platformv1.StartVMRequest{Id: "vm1"}},
		{"StopVM", func() (map[string]interface{}, error) { return b.StopVM("vm1", true, 5) },
			&platformv1.StopVMRequest{Id: "vm1", Force: true, TimeoutSeconds: 5}},
		{"DeleteVM", func() (map[string]interface{}, error) { return b.DeleteVM("vm1", true) },
			&platformv1.DeleteVMRequest{Id: "vm1", DeleteDisks: true}},
		{"GetVM", func() (map[string]interface{}, error) { return b.GetVM("vm1") }, &platformv1.GetVMRequest{Id: "vm1"}},
		{"ListVMs", b.ListVMs, &platformv1.ListVMsRequest{}},
		{"GetVMMetrics", func() (map[string]interface{}, error) { return b.GetVMMetrics("vm1") }, &platformv1.GetVMMetricsRequest{Id: "vm1"}},
		{"CreateContainer", func() (map[string]interface{}, error) { return b.CreateContainer("c", "alpine", true) },
			&platformv1.CreateContainerRequest{Config: &platformv1.ContainerConfig{Name: "c", Image: "alpine"}, Start: true}},
		{"StartContainer", func() (map[string]interface{}, error) { return b.StartContainer("c1") }, &platformv1.StartContainerRequest{Id: "c1"}},
		{"StopContainer", func() (map[string]interface{}, error) { return b.StopContainer("c1", 5) },
			&platformv1.StopContainerRequest{Id: "c1", TimeoutSeconds: 5}},
		{"DeleteContainer", func() (map[string]interface{}, error) { return b.DeleteContainer("c1", true, false) },
			&platformv1.DeleteContainerRequest{Id: "c1", Force: true}},
		{"GetContainer", func() (map[string]interface{}, error) { return b.GetContainer("c1") }, &platformv1.GetContainerRequest{Id: "c1"}},
		{"ListContainers", b.ListContainers, &platformv1.ListContainersRequest{}},
		{"GetContainerMetrics", func() (map[string]interface{}, error) { return b.GetContainerMetrics("c1") },
			&platformv1.GetContainerMetricsRequest{Id: "c1"}},
		{"ExecContainer", func() (map[string]interface{}, error) { return b.ExecContainer("c1", []string{"ls", "-l"}, "/srv") },
			&platformv1.ExecContainerRequest{Id: "c1", Command: []string{"ls", "-l"}, WorkingDir: "/srv"}},
		{"CreateSnapshot", func() (map[string]interface{}, error) { return b.CreateSnapshot("vm1", "s", "d", true, false) },
			&platformv1.CreateSnapshotRequest{VmId: "vm1", Config: &platformv1.SnapshotConfig{Name: "s", Description: "d", MemorySnapshot: true}}},
		{"ListSnapshots", func() (map[string]interface{}, error) { return b.ListSnapshots("vm1") }, &platformv1.ListSnapshotsRequest{VmId: "vm1"}},
		{"DeleteSnapshot", func() (map[string]interface{}, error) { return b.DeleteSnapshot("vm1", "s1") },
			&platformv1.DeleteSnapshotRequest{VmId: "vm1", SnapshotId: "s1"}},
		{"RestoreSnapshot", func() (map[string]interface{}, error) { return b.RestoreSnapshot("vm1", "s1") },
			&platformv1.RestoreSnapshotRequest{VmId: "vm1", SnapshotId: "s1"}},
		{"AttestVM", func() (map[string]interface{}, error) { return b.AttestVM("vm1", []byte("n"), []uint32{0, 7}) },
			&platformv1.AttestVMRequest{VmId: "vm1", Nonce: []byte("n"), PcrIndices: []uint32{0, 7}}},
	})
}

func TestCov964_SDNSendsTheRequestItsArgumentsDescribe(t *testing.T) {
	fake := &cov964SDNServer{}
	reg := cov964Registry()
	reg.SDN = fake
	b := cov964NewSet(cov964Connected(t, reg)).sdn
	cov964CheckSent(t, &fake.cov964Recorder, []cov964Sent{
		{"CreateBridge", func() (map[string]interface{}, error) { return b.CreateBridge("br0", 9000) },
			&platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: "br0", Mtu: 9000}}},
		{"DeleteBridge", func() (map[string]interface{}, error) { return b.DeleteBridge("br0", true) },
			&platformv1.DeleteBridgeRequest{Id: "br0", Force: true}},
		{"GetBridge", func() (map[string]interface{}, error) { return b.GetBridge("br0") }, &platformv1.GetBridgeRequest{Id: "br0"}},
		{"ListBridges", b.ListBridges, &platformv1.ListBridgesRequest{}},
		{"AddPort", func() (map[string]interface{}, error) { return b.AddPort("br0", "eth0", 10) },
			&platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{Name: "eth0", Vlan: 10}}},
		{"DeletePort", func() (map[string]interface{}, error) { return b.DeletePort("br0", "p1") },
			&platformv1.DeletePortRequest{BridgeId: "br0", PortId: "p1"}},
		{"GetPort", func() (map[string]interface{}, error) { return b.GetPort("br0", "p1") },
			&platformv1.GetPortRequest{BridgeId: "br0", PortId: "p1"}},
		{"ListPorts", func() (map[string]interface{}, error) { return b.ListPorts("br0") }, &platformv1.ListPortsRequest{BridgeId: "br0"}},
		{"AddFlow", func() (map[string]interface{}, error) { return b.AddFlow("br0", 2, 100) },
			&platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: "br0", Table: platformv1.FlowTable(2), Priority: 100}}},
		{"DeleteFlow", func() (map[string]interface{}, error) { return b.DeleteFlow("br0", "f1") },
			&platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "f1"}},
		{"ListFlows", func() (map[string]interface{}, error) { return b.ListFlows("br0", 2) },
			&platformv1.ListFlowsRequest{BridgeId: "br0", Table: platformv1.FlowTable(2)}},
		{"FlushFlows", func() (map[string]interface{}, error) { return b.FlushFlows("br0", 2) },
			&platformv1.FlushFlowsRequest{BridgeId: "br0", Table: platformv1.FlowTable(2)}},
		{"CreateVLAN", func() (map[string]interface{}, error) { return b.CreateVLAN("br0", "v10", 10) },
			&platformv1.CreateVLANRequest{Config: &platformv1.VLANConfig{BridgeId: "br0", Name: "v10", VlanId: 10}}},
		{"DeleteVLAN", func() (map[string]interface{}, error) { return b.DeleteVLAN("br0", 10) },
			&platformv1.DeleteVLANRequest{BridgeId: "br0", VlanId: 10}},
		{"ListVLANs", func() (map[string]interface{}, error) { return b.ListVLANs("br0") }, &platformv1.ListVLANsRequest{BridgeId: "br0"}},
		{"AuthenticatePort", func() (map[string]interface{}, error) { return b.AuthenticatePort("br0", "p1", []byte("pem"), "pem") },
			&platformv1.AuthenticatePortRequest{BridgeId: "br0", PortId: "p1", Certificate: []byte("pem"), Format: "pem"}},
		{"RevokePortAuth", func() (map[string]interface{}, error) { return b.RevokePortAuth("br0", "p1") },
			&platformv1.RevokePortAuthRequest{BridgeId: "br0", PortId: "p1"}},
		{"GetPortStats", func() (map[string]interface{}, error) { return b.GetPortStats("br0", "p1") },
			&platformv1.GetPortStatsRequest{BridgeId: "br0", PortId: "p1"}},
		{"GetFlowStats", func() (map[string]interface{}, error) { return b.GetFlowStats("br0", "f1") },
			&platformv1.GetFlowStatsRequest{BridgeId: "br0", FlowId: "f1"}},
	})
}

type cov964DaemonServer struct {
	platformv1.UnimplementedPlatformDaemonServer
	cov964Recorder
	service *platformv1.ServiceInfo
}

func (f *cov964DaemonServer) GetVersion(_ context.Context, r *platformv1.GetVersionRequest) (*platformv1.GetVersionResponse, error) {
	f.got = r
	return &platformv1.GetVersionResponse{Version: "1.2.3", BuildTime: "bt", GitCommit: "abc", GoVersion: "go1"}, nil
}
func (f *cov964DaemonServer) GetStatus(_ context.Context, r *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
	f.got = r
	return &platformv1.GetStatusResponse{
		Status:   1,
		Info:     &platformv1.PlatformInfo{Hostname: "node1", PlatformId: "pid", Version: "1.2.3"},
		Services: []*platformv1.ServiceInfo{f.service},
	}, nil
}
func (f *cov964DaemonServer) GetHealth(_ context.Context, r *platformv1.GetHealthRequest) (*platformv1.GetHealthResponse, error) {
	f.got = r
	return &platformv1.GetHealthResponse{Status: 1, Components: []*platformv1.ComponentHealth{{Name: "tpm", Status: 1}}}, nil
}
func (f *cov964DaemonServer) ListServices(_ context.Context, r *platformv1.ListServicesRequest) (*platformv1.ListServicesResponse, error) {
	f.got = r
	return &platformv1.ListServicesResponse{Services: []*platformv1.ServiceInfo{f.service}}, nil
}
func (f *cov964DaemonServer) StartService(_ context.Context, r *platformv1.StartServiceRequest) (*platformv1.StartServiceResponse, error) {
	f.got = r
	return &platformv1.StartServiceResponse{}, nil
}
func (f *cov964DaemonServer) StopService(_ context.Context, r *platformv1.StopServiceRequest) (*platformv1.StopServiceResponse, error) {
	f.got = r
	return &platformv1.StopServiceResponse{}, nil
}
func (f *cov964DaemonServer) RestartService(_ context.Context, r *platformv1.RestartServiceRequest) (*platformv1.RestartServiceResponse, error) {
	f.got = r
	return &platformv1.RestartServiceResponse{}, nil
}
func (f *cov964DaemonServer) GetServiceStatus(_ context.Context, r *platformv1.GetServiceStatusRequest) (*platformv1.GetServiceStatusResponse, error) {
	f.got = r
	if r.GetService() == platformv1.ServiceType_SERVICE_TYPE_TPM {
		return &platformv1.GetServiceStatusResponse{Service: f.service}, nil
	}
	return &platformv1.GetServiceStatusResponse{}, nil
}

// cov964DaemonOver serves the daemon binding with a fake whose one service
// is the TPM, running and healthy.
func cov964DaemonOver(t *testing.T) (*DaemonBinding, *cov964DaemonServer) {
	t.Helper()
	fake := &cov964DaemonServer{service: &platformv1.ServiceInfo{
		Name: "tpm", Type: platformv1.ServiceType_SERVICE_TYPE_TPM, Status: 1, Health: 1,
	}}
	reg := cov964Registry()
	reg.Daemon = fake
	return cov964NewSet(cov964Connected(t, reg)).daemon, fake
}

// The daemon binding builds its own maps; each key carries the field the
// daemon answered with, enums by name.
func TestCov964_DaemonMapsTheAnswer(t *testing.T) {
	b, fake := cov964DaemonOver(t)
	svc := fake.service
	wantSvc := map[string]interface{}{
		"name": "tpm", "type": "SERVICE_TYPE_TPM", "status": svc.GetStatus().String(), "health": svc.GetHealth().String(),
	}
	cov964SameMap := func(t *testing.T, got, want map[string]interface{}) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("map = %v, want %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("map[%q] = %v, want %v", k, got[k], v)
			}
		}
	}

	t.Run("GetVersion", func(t *testing.T) {
		got, err := b.GetVersion()
		if err != nil {
			t.Fatal(err)
		}
		cov964SameMap(t, got, map[string]interface{}{"version": "1.2.3", "buildTime": "bt", "gitCommit": "abc", "goVersion": "go1"})
	})
	t.Run("GetStatus", func(t *testing.T) {
		got, err := b.GetStatus()
		if err != nil {
			t.Fatal(err)
		}
		services, ok := got["services"].([]map[string]interface{})
		if !ok || len(services) != 1 {
			t.Fatalf("services = %v, want one service", got["services"])
		}
		cov964SameMap(t, services[0], map[string]interface{}{"name": "tpm", "status": svc.GetStatus().String(), "health": svc.GetHealth().String()})
		delete(got, "services")
		cov964SameMap(t, got, map[string]interface{}{
			"status": platformv1.SystemStatus(1).String(), "hostname": "node1", "platformId": "pid", "version": "1.2.3",
		})
	})
	t.Run("GetHealth detailed", func(t *testing.T) {
		got, err := b.GetHealth(true)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(fake.got, &platformv1.GetHealthRequest{Detailed: true}) {
			t.Fatalf("request = %v", fake.got)
		}
		components, ok := got["components"].([]map[string]interface{})
		if !ok || len(components) != 1 || components[0]["name"] != "tpm" {
			t.Fatalf("components = %v, want the tpm component", got["components"])
		}
	})
	t.Run("GetHealth summary", func(t *testing.T) {
		got, err := b.GetHealth(false)
		if err != nil {
			t.Fatal(err)
		}
		cov964SameMap(t, got, map[string]interface{}{"status": platformv1.HealthStatus(1).String()})
	})
	t.Run("ListServices", func(t *testing.T) {
		got, err := b.ListServices()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("ListServices = %v, want one service", got)
		}
		cov964SameMap(t, got[0], wantSvc)
	})
	t.Run("GetServiceStatus", func(t *testing.T) {
		got, err := b.GetServiceStatus("tpm")
		if err != nil {
			t.Fatal(err)
		}
		cov964SameMap(t, got, wantSvc)
	})
	t.Run("GetServiceStatus unknown", func(t *testing.T) {
		got, err := b.GetServiceStatus("unspecified")
		if err != nil {
			t.Fatal(err)
		}
		cov964SameMap(t, got, map[string]interface{}{"type": "unspecified", "status": "unknown"})
	})
}

// Start, stop and restart name the service the caller asked for.
func TestCov964_DaemonServiceControlNamesTheService(t *testing.T) {
	b, fake := cov964DaemonOver(t)
	tpm := platformv1.ServiceType_SERVICE_TYPE_TPM
	tests := []struct {
		name string
		call func(string) error
		want proto.Message
	}{
		{"StartService", b.StartService, &platformv1.StartServiceRequest{Service: tpm}},
		{"StopService", b.StopService, &platformv1.StopServiceRequest{Service: tpm}},
		{"RestartService", b.RestartService, &platformv1.RestartServiceRequest{Service: tpm}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call("tpm"); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(fake.got, tc.want) {
				t.Fatalf("request = %v, want %v", fake.got, tc.want)
			}
		})
	}
}
