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

// redfishRef is a JSON reference containing an @odata.id link.
type redfishRef struct {
	ODataID string `json:"@odata.id"`
}

// redfishServiceRoot represents the Redfish /redfish/v1/ service root
// response. ODataID and RedfishVersion are mandatory members of a
// ServiceRoot (DSP0266 §7.3, DSP2046) and are what identifies the resource
// as one — see isRedfishServiceRoot.
type redfishServiceRoot struct {
	ODataID        string     `json:"@odata.id"`
	RedfishVersion string     `json:"RedfishVersion"`
	Systems        redfishRef `json:"Systems"`
	Chassis        redfishRef `json:"Chassis"`
	Managers       redfishRef `json:"Managers"`
}

// redfishCollection is a generic Redfish collection response containing member links.
type redfishCollection struct {
	Members []redfishRef `json:"Members"`
}

// redfishBoot represents the Boot section of a Redfish System resource.
type redfishBoot struct {
	BootSourceOverrideTarget                string   `json:"BootSourceOverrideTarget"`
	BootSourceOverrideEnabled               string   `json:"BootSourceOverrideEnabled"`
	BootSourceOverrideMode                  string   `json:"BootSourceOverrideMode,omitempty"`
	BootSourceOverrideTargetAllowableValues []string `json:"BootSourceOverrideTarget@Redfish.AllowableValues,omitempty"`
}

// redfishProcessorSummary represents the ProcessorSummary of a Redfish System.
type redfishProcessorSummary struct {
	Count int    `json:"Count"`
	Model string `json:"Model"`
}

// redfishMemorySummary represents the MemorySummary of a Redfish System.
type redfishMemorySummary struct {
	TotalSystemMemoryGiB float64 `json:"TotalSystemMemoryGiB"`
}

// redfishResetAction represents the #ComputerSystem.Reset action in a Redfish System.
type redfishResetAction struct {
	Target string `json:"target"`
}

// redfishActions represents the Actions section of a Redfish System resource.
type redfishActions struct {
	ComputerSystemReset redfishResetAction `json:"#ComputerSystem.Reset"`
}

// redfishBiosResetAction represents the #Bios.ResetBios action target on a
// Redfish Bios resource. BMCs that expose this action let the host clear
// its UEFI NVRAM boot entries (and reset BIOS attributes to defaults) on
// the next reset. Most enterprise iDRAC/iLO firmware ships it; older
// Supermicro X10 BMCs do not.
type redfishBiosResetAction struct {
	Target string `json:"target"`
}

// redfishBiosActions represents the Actions block on a Redfish Bios resource.
type redfishBiosActions struct {
	ResetBios redfishBiosResetAction `json:"#Bios.ResetBios"`
}

// redfishBios represents a Redfish /redfish/v1/Systems/{id}/Bios resource.
type redfishBios struct {
	Attributes map[string]any     `json:"Attributes,omitempty"`
	Actions    redfishBiosActions `json:"Actions"`
}

// redfishSystem represents a Redfish /redfish/v1/Systems/{id} resource.
type redfishSystem struct {
	Manufacturer     string                  `json:"Manufacturer"`
	Model            string                  `json:"Model"`
	PartNumber       string                  `json:"PartNumber"`
	SerialNumber     string                  `json:"SerialNumber"`
	BiosVersion      string                  `json:"BiosVersion"`
	PowerState       string                  `json:"PowerState"`
	Boot             redfishBoot             `json:"Boot"`
	Bios             redfishRef              `json:"Bios,omitempty"`
	ProcessorSummary redfishProcessorSummary `json:"ProcessorSummary"`
	MemorySummary    redfishMemorySummary    `json:"MemorySummary"`
	Actions          redfishActions          `json:"Actions"`
}

// redfishStatus represents the Status block common to many Redfish resources.
type redfishStatus struct {
	State  string `json:"State"`
	Health string `json:"Health"`
}

// redfishTemperature represents a single temperature sensor reading from Thermal.
type redfishTemperature struct {
	Name           string        `json:"Name"`
	ReadingCelsius float64       `json:"ReadingCelsius"`
	Status         redfishStatus `json:"Status"`
}

// redfishFan represents a single fan sensor reading from Thermal.
type redfishFan struct {
	Name         string        `json:"Name"`
	Reading      float64       `json:"Reading"`
	ReadingUnits string        `json:"ReadingUnits"`
	Status       redfishStatus `json:"Status"`
}

// redfishThermal represents the /redfish/v1/Chassis/{id}/Thermal resource.
type redfishThermal struct {
	Temperatures []redfishTemperature `json:"Temperatures"`
	Fans         []redfishFan         `json:"Fans"`
}

// redfishPowerControl represents a single power control entry from the Power resource.
type redfishPowerControl struct {
	Name               string  `json:"Name"`
	PowerConsumedWatts float64 `json:"PowerConsumedWatts"`
	PowerCapacityWatts float64 `json:"PowerCapacityWatts"`
}

// redfishPowerSupply represents a single power supply from the Power resource.
type redfishPowerSupply struct {
	Name                 string        `json:"Name"`
	PowerCapacityWatts   float64       `json:"PowerCapacityWatts"`
	LastPowerOutputWatts float64       `json:"LastPowerOutputWatts"`
	Status               redfishStatus `json:"Status"`
}

// redfishPower represents the /redfish/v1/Chassis/{id}/Power resource.
type redfishPower struct {
	PowerControl  []redfishPowerControl `json:"PowerControl"`
	PowerSupplies []redfishPowerSupply  `json:"PowerSupplies"`
}

// redfishVirtualMedia represents a /redfish/v1/Managers/{id}/VirtualMedia/{id} resource.
type redfishVirtualMedia struct {
	Inserted   bool     `json:"Inserted"`
	Image      string   `json:"Image"`
	MediaTypes []string `json:"MediaTypes"`
	Actions    struct {
		InsertMedia redfishRef `json:"#VirtualMedia.InsertMedia"`
		EjectMedia  redfishRef `json:"#VirtualMedia.EjectMedia"`
	} `json:"Actions"`
}

// redfishResetBody is the request body for a ComputerSystem.Reset action.
type redfishResetBody struct {
	ResetType string `json:"ResetType"`
}

// redfishBootPatch is the PATCH body for setting boot device override.
type redfishBootPatch struct {
	Boot redfishBootPatchInner `json:"Boot"`
}

// redfishBootPatchInner is the inner Boot object for a boot device PATCH.
type redfishBootPatchInner struct {
	BootSourceOverrideTarget  string `json:"BootSourceOverrideTarget"`
	BootSourceOverrideEnabled string `json:"BootSourceOverrideEnabled"`
}

// redfishInsertMediaBody is the request body for VirtualMedia.InsertMedia.
type redfishInsertMediaBody struct {
	Image string `json:"Image"`
}

// redfishError represents a Redfish error response body.
type redfishError struct {
	Error struct {
		Code         string                `json:"code"`
		Message      string                `json:"message"`
		ExtendedInfo []redfishExtendedInfo `json:"@Message.ExtendedInfo"`
	} `json:"error"`
}

// redfishExtendedInfo captures one entry of the Redfish @Message.ExtendedInfo
// array — the specific actionable diagnostic that Supermicro (and most BMCs)
// surface for 4xx responses. The top-level message is often a generic
// "A general error has occurred", while ExtendedInfo[i].Message / MessageArgs /
// Resolution carry the real cause + fix.
type redfishExtendedInfo struct {
	MessageId   string   `json:"MessageId"`
	Message     string   `json:"Message"`
	MessageArgs []string `json:"MessageArgs"`
	Severity    string   `json:"Severity"`
	Resolution  string   `json:"Resolution"`
}
