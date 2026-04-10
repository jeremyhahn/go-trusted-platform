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

package bmc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// redfishBootDeviceMap maps BMC BootDevice values to Redfish BootSourceOverrideTarget values.
var redfishBootDeviceMap = map[BootDevice]string{
	BootDevicePXE:          "Pxe",
	BootDeviceDisk:         "Hdd",
	BootDeviceCDROM:        "Cd",
	BootDeviceVirtualMedia: "Cd",
	BootDeviceNone:         "None",
}

// redfishBootDeviceReverse maps Redfish BootSourceOverrideTarget values back to BMC BootDevice.
var redfishBootDeviceReverse = map[string]BootDevice{
	"Pxe":  BootDevicePXE,
	"Hdd":  BootDeviceDisk,
	"Cd":   BootDeviceCDROM,
	"None": BootDeviceNone,
}

// redfishPowerStateMap maps Redfish PowerState strings to BMC PowerState values.
var redfishPowerStateMap = map[string]PowerState{
	"On":               PowerStateOn,
	"Off":              PowerStateOff,
	"PoweringOn":       PowerStateOn,
	"PoweringOff":      PowerStateOff,
	"Paused":           PowerStateOn,
	"GracefulShutdown": PowerStateOff,
}

// redfishClient implements the Client interface using the Redfish REST API.
type redfishClient struct {
	config     *Config
	httpClient *http.Client
	baseURL    string
	logger     *slog.Logger
	closed     atomic.Bool

	// Discovery state protected by sync.Once for lock-free subsequent reads.
	discoverOnce sync.Once
	discoverErr  error

	// Cached Redfish paths discovered from service root.
	systemPath       atomic.Value // string
	chassisPath      atomic.Value // string
	managerPath      atomic.Value // string
	virtualMediaPath atomic.Value // string
	resetActionPath  atomic.Value // string
}

// Compile-time interface check.
var _ Client = (*redfishClient)(nil)

// newRedfishClient creates a new redfishClient with the given configuration.
func newRedfishClient(config *Config, logger *slog.Logger) *redfishClient {
	rc := &redfishClient{
		config:  config,
		logger:  logger,
		baseURL: fmt.Sprintf("https://%s:%d", config.Address, config.Port),
	}
	rc.httpClient = rc.buildHTTPClient()
	return rc
}

// buildHTTPClient creates an http.Client with appropriate TLS configuration.
func (c *redfishClient) buildHTTPClient() *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if c.config.SkipTLSVerify {
		c.logger.Warn("bmc: redfish TLS verification disabled — this is insecure and should only be used with BMCs that have self-signed certificates")
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // BMC self-signed cert support, guarded by config flag with warning
	}

	if c.config.CACertPath != "" {
		caCert, err := os.ReadFile(c.config.CACertPath)
		if err != nil {
			c.logger.Error("bmc: failed to read CA certificate",
				slog.String("path", c.config.CACertPath),
				slog.String("error", err.Error()))
		} else {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = pool
			} else {
				c.logger.Error("bmc: failed to parse CA certificate PEM",
					slog.String("path", c.config.CACertPath))
			}
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// discover performs Redfish service root discovery and caches resource paths.
// It is called via sync.Once to ensure discovery runs exactly once.
func (c *redfishClient) discover(ctx context.Context) error {
	c.discoverOnce.Do(func() {
		c.discoverErr = c.performDiscovery(ctx)
	})
	return c.discoverErr
}

// performDiscovery fetches the Redfish service root and resolves the first
// system, chassis, and manager resource paths from their respective collections.
func (c *redfishClient) performDiscovery(ctx context.Context) error {
	// Fetch service root.
	var root redfishServiceRoot
	if err := c.doGET(ctx, "/redfish/v1/", &root); err != nil {
		return ErrRedfishDiscovery{Resource: "service root", Cause: err}
	}

	// Discover first system.
	systemPath, err := c.discoverFirstMember(ctx, root.Systems.ODataID, "Systems")
	if err != nil {
		return err
	}
	c.systemPath.Store(systemPath)

	// Discover first chassis.
	chassisPath, err := c.discoverFirstMember(ctx, root.Chassis.ODataID, "Chassis")
	if err != nil {
		return err
	}
	c.chassisPath.Store(chassisPath)

	// Discover first manager.
	managerPath, err := c.discoverFirstMember(ctx, root.Managers.ODataID, "Managers")
	if err != nil {
		return err
	}
	c.managerPath.Store(managerPath)

	// Discover virtual media collection from the manager.
	virtualMediaPath, err := c.discoverVirtualMedia(ctx, managerPath)
	if err != nil {
		// Virtual media may not be available on all BMCs — log but don't fail.
		c.logger.Warn("bmc: redfish virtual media discovery failed",
			slog.String("error", err.Error()))
	} else {
		c.virtualMediaPath.Store(virtualMediaPath)
	}

	// Discover reset action target from the system.
	var sys redfishSystem
	if err := c.doGET(ctx, systemPath, &sys); err != nil {
		return ErrRedfishDiscovery{Resource: "system", Cause: err}
	}
	if sys.Actions.ComputerSystemReset.Target != "" {
		c.resetActionPath.Store(sys.Actions.ComputerSystemReset.Target)
	} else {
		// Fall back to standard path.
		c.resetActionPath.Store(systemPath + "/Actions/ComputerSystem.Reset")
	}

	return nil
}

// discoverFirstMember fetches a Redfish collection and returns the @odata.id
// of the first member.
func (c *redfishClient) discoverFirstMember(ctx context.Context, collectionPath string, resource string) (string, error) {
	if collectionPath == "" {
		return "", ErrRedfishDiscovery{Resource: resource, Cause: ErrRedfishEmptyCollection{Resource: resource}}
	}
	var collection redfishCollection
	if err := c.doGET(ctx, collectionPath, &collection); err != nil {
		return "", ErrRedfishDiscovery{Resource: resource, Cause: err}
	}
	if len(collection.Members) == 0 {
		return "", ErrRedfishDiscovery{Resource: resource, Cause: ErrRedfishEmptyCollection{Resource: resource}}
	}
	return collection.Members[0].ODataID, nil
}

// discoverVirtualMedia discovers the virtual media collection path from a manager resource.
func (c *redfishClient) discoverVirtualMedia(ctx context.Context, managerPath string) (string, error) {
	// The manager resource typically has a VirtualMedia link. We fetch the manager
	// and look for that link. Since our redfishSystem struct doesn't include manager
	// fields, we use a lightweight struct here.
	type managerResource struct {
		VirtualMedia redfishRef `json:"VirtualMedia"`
	}
	var mgr managerResource
	if err := c.doGET(ctx, managerPath, &mgr); err != nil {
		return "", ErrRedfishDiscovery{Resource: "VirtualMedia", Cause: err}
	}
	if mgr.VirtualMedia.ODataID == "" {
		return "", ErrRedfishDiscovery{Resource: "VirtualMedia",
			Cause: ErrRedfishEmptyCollection{Resource: "VirtualMedia"}}
	}
	return mgr.VirtualMedia.ODataID, nil
}

// ensureDiscovered ensures Redfish discovery has been performed.
func (c *redfishClient) ensureDiscovered(ctx context.Context) error {
	if c.closed.Load() {
		return ErrClientClosed{}
	}
	return c.discover(ctx)
}

// getSystemPath returns the cached system path.
func (c *redfishClient) getSystemPath() string {
	v := c.systemPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getChassisPath returns the cached chassis path.
func (c *redfishClient) getChassisPath() string {
	v := c.chassisPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getVirtualMediaPath returns the cached virtual media collection path.
func (c *redfishClient) getVirtualMediaPath() string {
	v := c.virtualMediaPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// getResetActionPath returns the cached reset action target path.
func (c *redfishClient) getResetActionPath() string {
	v := c.resetActionPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// PowerStatus returns the current power state from the Redfish system resource.
func (c *redfishClient) PowerStatus(ctx context.Context) (PowerState, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return PowerStateUnknown, err
	}
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return PowerStateUnknown, ErrPowerOperation{Operation: "status", Cause: err}
	}
	if state, ok := redfishPowerStateMap[sys.PowerState]; ok {
		return state, nil
	}
	return PowerStateUnknown, nil
}

// PowerOn powers on the system via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerOn(ctx context.Context) error {
	return c.doResetAction(ctx, "On", "on")
}

// PowerOff powers off the system via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerOff(ctx context.Context) error {
	return c.doResetAction(ctx, "ForceOff", "off")
}

// PowerReset performs a hard reset via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerReset(ctx context.Context) error {
	return c.doResetAction(ctx, "ForceRestart", "reset")
}

// PowerCycle power cycles the system via the Redfish ComputerSystem.Reset action.
func (c *redfishClient) PowerCycle(ctx context.Context) error {
	return c.doResetAction(ctx, "PowerCycle", "cycle")
}

// doResetAction performs a ComputerSystem.Reset action with the given reset type.
func (c *redfishClient) doResetAction(ctx context.Context, resetType string, operation string) error {
	if err := c.ensureDiscovered(ctx); err != nil {
		return ErrPowerOperation{Operation: operation, Cause: err}
	}
	body := redfishResetBody{ResetType: resetType}
	if err := c.doPOST(ctx, c.getResetActionPath(), body, nil); err != nil {
		return ErrPowerOperation{Operation: operation, Cause: err}
	}
	return nil
}

// GetBootDevice returns the current boot device override from the Redfish system resource.
func (c *redfishClient) GetBootDevice(ctx context.Context) (BootDevice, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return BootDeviceNone, err
	}
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return BootDeviceNone, ErrBootDevice{Cause: err}
	}
	if dev, ok := redfishBootDeviceReverse[sys.Boot.BootSourceOverrideTarget]; ok {
		return dev, nil
	}
	return BootDeviceNone, nil
}

// SetBootDevice sets the boot device override via PATCH on the Redfish system resource.
func (c *redfishClient) SetBootDevice(ctx context.Context, device BootDevice, persistent bool) error {
	if !device.IsValid() {
		return ErrInvalidBootDevice{Device: string(device)}
	}
	if err := c.ensureDiscovered(ctx); err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}

	redfishTarget, ok := redfishBootDeviceMap[device]
	if !ok {
		return ErrInvalidBootDevice{Device: string(device)}
	}

	enabled := "Once"
	if persistent {
		enabled = "Continuous"
	}

	patch := redfishBootPatch{
		Boot: redfishBootPatchInner{
			BootSourceOverrideTarget:  redfishTarget,
			BootSourceOverrideEnabled: enabled,
		},
	}

	if err := c.doPATCH(ctx, c.getSystemPath(), patch); err != nil {
		return ErrBootDevice{Device: string(device), Cause: err}
	}
	return nil
}

// GetSystemInfo returns system identification information from the Redfish system resource.
func (c *redfishClient) GetSystemInfo(ctx context.Context) (*SystemInfo, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, ErrInventory{Cause: err}
	}
	var sys redfishSystem
	if err := c.doGET(ctx, c.getSystemPath(), &sys); err != nil {
		return nil, ErrInventory{Cause: err}
	}

	powerState := PowerStateUnknown
	if state, ok := redfishPowerStateMap[sys.PowerState]; ok {
		powerState = state
	}

	return &SystemInfo{
		Manufacturer:    sys.Manufacturer,
		Product:         sys.Model,
		SerialNumber:    sys.SerialNumber,
		FirmwareVersion: fmt.Sprintf("CPU: %s (%d cores), RAM: %.0f GiB", sys.ProcessorSummary.Model, sys.ProcessorSummary.Count, sys.MemorySummary.TotalSystemMemoryGiB),
		BIOSVersion:     sys.BiosVersion,
		PowerState:      powerState,
	}, nil
}

// GetSensors returns sensor readings from the Redfish Thermal and Power resources.
func (c *redfishClient) GetSensors(ctx context.Context) ([]SensorReading, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, ErrSensorRead{Cause: err}
	}

	chassisPath := c.getChassisPath()
	sensors := make([]SensorReading, 0, 16)

	// Fetch thermal data.
	var thermal redfishThermal
	thermalErr := c.doGET(ctx, chassisPath+"/Thermal", &thermal)
	if thermalErr == nil {
		for i := range thermal.Temperatures {
			t := &thermal.Temperatures[i]
			sensors = append(sensors, SensorReading{
				Name:   t.Name,
				Value:  t.ReadingCelsius,
				Units:  "degrees C",
				Status: normalizeRedfishHealth(t.Status.Health),
			})
		}
		for i := range thermal.Fans {
			f := &thermal.Fans[i]
			units := "RPM"
			if f.ReadingUnits != "" {
				units = f.ReadingUnits
			}
			sensors = append(sensors, SensorReading{
				Name:   f.Name,
				Value:  f.Reading,
				Units:  units,
				Status: normalizeRedfishHealth(f.Status.Health),
			})
		}
	} else {
		c.logger.Debug("bmc: redfish thermal read failed",
			slog.String("error", thermalErr.Error()))
	}

	// Fetch power data.
	var power redfishPower
	powerErr := c.doGET(ctx, chassisPath+"/Power", &power)
	if powerErr == nil {
		for i := range power.PowerControl {
			pc := &power.PowerControl[i]
			sensors = append(sensors, SensorReading{
				Name:   pc.Name,
				Value:  pc.PowerConsumedWatts,
				Units:  "Watts",
				Status: "ok",
			})
		}
		for i := range power.PowerSupplies {
			ps := &power.PowerSupplies[i]
			sensors = append(sensors, SensorReading{
				Name:   ps.Name,
				Value:  ps.LastPowerOutputWatts,
				Units:  "Watts",
				Status: normalizeRedfishHealth(ps.Status.Health),
			})
		}
	} else {
		c.logger.Debug("bmc: redfish power read failed",
			slog.String("error", powerErr.Error()))
	}

	if thermalErr != nil && powerErr != nil {
		return nil, ErrSensorRead{Cause: thermalErr}
	}

	return sensors, nil
}

// MountISO is a thin wrapper around MountVirtualMedia that builds a
// MediaSpec from a bare ISO URL. The Protocol is inferred from the URL
// scheme and the media is mounted write-protected.
func (c *redfishClient) MountISO(ctx context.Context, isoURL string) error {
	spec := &MediaSpec{URL: isoURL, WriteProtected: true}
	if err := spec.inferProtocol(); err != nil {
		return ErrVirtualMedia{Operation: "mount", Cause: err}
	}
	if err := c.MountVirtualMedia(ctx, spec); err != nil {
		return ErrVirtualMedia{Operation: "mount", Cause: err}
	}
	return nil
}

// UnmountISO is a thin wrapper around UnmountVirtualMedia.
func (c *redfishClient) UnmountISO(ctx context.Context) error {
	if err := c.UnmountVirtualMedia(ctx); err != nil {
		return ErrVirtualMedia{Operation: "unmount", Cause: err}
	}
	return nil
}

// VirtualMediaStatus dispatches to the configured virtual media backends
// and returns the first successful status response.
func (c *redfishClient) VirtualMediaStatus(ctx context.Context) (*VirtualMediaInfo, error) {
	info, err := c.virtualMediaStatusDispatch(ctx)
	if err != nil {
		return nil, ErrVirtualMedia{Operation: "status", Cause: err}
	}
	return info, nil
}

// Close releases resources held by the Redfish client.

// Console returns an unsupported operation error because Redfish does not support SOL.
func (c *redfishClient) Console(_ context.Context) (*SOLSession, error) {
	return nil, ErrUnsupportedOperation{Operation: "console"}
}
func (c *redfishClient) Close() error {
	if c.closed.Swap(true) {
		return nil // already closed
	}
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}

// discoverVirtualMediaCD finds the CD/DVD virtual media member from the collection.
// It iterates collection members looking for one that supports CD/DVD media types.
func (c *redfishClient) discoverVirtualMediaCD(ctx context.Context, vmCollectionPath string) (string, error) {
	var collection redfishCollection
	if err := c.doGET(ctx, vmCollectionPath, &collection); err != nil {
		return "", ErrRedfishDiscovery{Resource: "VirtualMedia members", Cause: err}
	}
	if len(collection.Members) == 0 {
		return "", ErrRedfishEmptyCollection{Resource: "VirtualMedia"}
	}

	// Try to find a CD/DVD member by checking media types.
	for i := range collection.Members {
		memberPath := collection.Members[i].ODataID
		var vm redfishVirtualMedia
		if err := c.doGET(ctx, memberPath, &vm); err != nil {
			continue
		}
		for _, mt := range vm.MediaTypes {
			lower := strings.ToLower(mt)
			if lower == "cd" || lower == "dvd" || strings.Contains(lower, "cd") || strings.Contains(lower, "dvd") {
				return memberPath, nil
			}
		}
	}

	// If no CD/DVD member found, return the first member as a fallback.
	return collection.Members[0].ODataID, nil
}

// doGET performs an authenticated GET request and decodes the JSON response.
func (c *redfishClient) doGET(ctx context.Context, path string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return ErrRedfishRequest{Method: "GET", Path: path, Cause: err}
	}
	req.SetBasicAuth(c.config.Username, c.config.Password)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ErrRedfishRequest{Method: "GET", Path: path, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.parseErrorResponse(resp, "GET", path)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return ErrRedfishRequest{Method: "GET", Path: path, Cause: err}
		}
	}
	return nil
}

// doPOST performs an authenticated POST request with a JSON body.
func (c *redfishClient) doPOST(ctx context.Context, path string, body any, result any) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return ErrRedfishRequest{Method: "POST", Path: path, Cause: err}
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return ErrRedfishRequest{Method: "POST", Path: path, Cause: err}
	}
	req.SetBasicAuth(c.config.Username, c.config.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ErrRedfishRequest{Method: "POST", Path: path, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.parseErrorResponse(resp, "POST", path)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return ErrRedfishRequest{Method: "POST", Path: path, Cause: err}
		}
	}
	return nil
}

// doPATCH performs an authenticated PATCH request with a JSON body.
func (c *redfishClient) doPATCH(ctx context.Context, path string, body any) error {
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return ErrRedfishRequest{Method: "PATCH", Path: path, Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+path, bytes.NewReader(jsonBytes))
	if err != nil {
		return ErrRedfishRequest{Method: "PATCH", Path: path, Cause: err}
	}
	req.SetBasicAuth(c.config.Username, c.config.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ErrRedfishRequest{Method: "PATCH", Path: path, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.parseErrorResponse(resp, "PATCH", path)
	}
	return nil
}

// parseErrorResponse reads a Redfish error response body and returns a typed error.
func (c *redfishClient) parseErrorResponse(resp *http.Response, method string, path string) error {
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return ErrRedfishRequest{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Message:    resp.Status,
		}
	}

	var redfishErr redfishError
	if err := json.Unmarshal(bodyBytes, &redfishErr); err == nil && redfishErr.Error.Message != "" {
		return ErrRedfishRequest{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Message:    redfishErr.Error.Message,
		}
	}

	return ErrRedfishRequest{
		Method:     method,
		Path:       path,
		StatusCode: resp.StatusCode,
		Message:    string(bodyBytes),
	}
}

// normalizeRedfishHealth converts Redfish health status strings to BMC sensor status.
func normalizeRedfishHealth(health string) string {
	healthMap := map[string]string{
		"OK":       "ok",
		"Warning":  "warning",
		"Critical": "critical",
	}
	if status, ok := healthMap[health]; ok {
		return status
	}
	if health == "" {
		return "ok"
	}
	return strings.ToLower(health)
}
