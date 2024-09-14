package model

import (
	"fmt"
)

type SystemStruct struct {
	BIOS     BIOS           `yaml:"bios" json:"bios"`
	Board    Board          `yaml:"board" json:"board"`
	Chassis  Chassis        `yaml:"chassis" json:"chassis"`
	Mode     string         `yaml:"mode" json:"mode"`
	Product  Product        `yaml:"product" json:"product"`
	Runtime  *SystemRuntime `yaml:"runtime" json:"runtime"`
	Services int            `yaml:"services" json:"services"`
	// Version  *app.AppVersion `yaml:"version" json:"version"`
}

type BIOS struct {
	Date    string `yaml:"date" json:"date"`
	Release string `yaml:"release" json:"release"`
	Vendor  string `yaml:"vendor" json:"vendor"`
	Version string `yaml:"version" json:"version"`
}

func (b BIOS) Print() {
	fmt.Printf("BIOS date:             %s\n", b.Date)
	fmt.Printf("BIOS release:          %s\n", b.Release)
	fmt.Printf("BIOS vendor:           %s\n", b.Vendor)
	fmt.Printf("BIOS version:          %s\n", b.Version)
}

type Board struct {
	AssetTag string `yaml:"asset-tag" json:"asset_tag"`
	Name     string `yaml:"name" json:"name"`
	Serial   string `yaml:"serial" json:"serial"`
	Vendor   string `yaml:"vendor" json:"vendor"`
	Version  string `yaml:"version" json:"version"`
}

func (b Board) Print() {
	fmt.Printf("Board asset tag:       %s\n", b.AssetTag)
	fmt.Printf("Board name:            %s\n", b.Name)
	fmt.Printf("Board serial:          %s\n", b.Serial)
	fmt.Printf("Board vendor:          %s\n", b.Vendor)
	fmt.Printf("Board version:         %s\n", b.Version)
}

type Chassis struct {
	AssetTag string `yaml:"asset-tag" json:"asset_tag"`
	Serial   string `yaml:"serial" json:"serial"`
	Type     string `yaml:"type" json:"type"`
	Vendor   string `yaml:"vendor" json:"vendor"`
	Version  string `yaml:"version" json:"version"`
}

func (c Chassis) Print() {
	fmt.Printf("Chassis asset tag:     %s\n", c.AssetTag)
	fmt.Printf("Chassis serial:        %s\n", c.Serial)
	fmt.Printf("Chassis type:          %s\n", c.Type)
	fmt.Printf("Chassis vendor:        %s\n", c.Vendor)
	fmt.Printf("Chassis version:       %s\n", c.Version)
}

type Product struct {
	Family  string `yaml:"family" json:"family"`
	Name    string `yaml:"name" json:"name"`
	Serial  string `yaml:"serial" json:"serial"`
	SKU     string `yaml:"sku" json:"sku"`
	UUID    string `yaml:"uuid" json:"uuid"`
	Version string `yaml:"version" json:"version"`
}

func (p Product) Print() {
	fmt.Printf("Product family:        %s\n", p.Family)
	fmt.Printf("Product name:          %s\n", p.Name)
	fmt.Printf("Product serial:        %s\n", p.Serial)
	fmt.Printf("Product sku:           %s\n", p.SKU)
	fmt.Printf("Product uuid:          %s\n", p.UUID)
	fmt.Printf("Product version:       %s\n", p.Version)
}

type SystemRuntime struct {
	Version     string `yaml:"version" json:"version"`
	Goroutines  int    `yaml:"goroutines" json:"goroutines"`
	Cpus        int    `yaml:"cpus" json:"cpus"`
	Cgo         int64  `yaml:"cgo" json:"cgo"`
	HeapSize    uint64 `yaml:"heap-alloc" json:"heapAlloc"`
	Alloc       uint64 `yaml:"alloc" json:"alloc"`
	Sys         uint64 `yaml:"sys" json:"sys"`
	Mallocs     uint64 `yaml:"mallocs" json:"mallocs"`
	Frees       uint64 `yaml:"frees" json:"frees"`
	NumGC       uint32 `yaml:"gc" json:"gc"`
	NumForcedGC uint32 `yaml:"num-forced-gc" json:"numForcedGC"`
}

func (sr SystemRuntime) Print() {
	fmt.Printf("Runtime version:       %s\n", sr.Version)
	fmt.Printf("Runtime goroutines:    %d\n", sr.Goroutines)
	fmt.Printf("Runtime cpus:          %d\n", sr.Cpus)
	fmt.Printf("Runtime cgo:           %d\n", sr.Cgo)
	fmt.Printf("Runtime heap size:     %d\n", sr.HeapSize)
	fmt.Printf("Runtime alloc:         %d\n", sr.Alloc)
	fmt.Printf("Runtime sys:           %d\n", sr.Sys)
	fmt.Printf("Runtime mallocs:       %d\n", sr.Mallocs)
	fmt.Printf("Runtime frees:         %d\n", sr.Frees)
	fmt.Printf("Runtime num GCs        %d\n", sr.NumGC)
	fmt.Printf("Runtime num forced GC: %d\n", sr.NumForcedGC)
}
