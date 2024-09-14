package system

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/model"
)

func PrintSystemInfo() error {

	sys, err := SystemInfo()
	if err != nil {
		return err
	}

	sys.BIOS.Print()
	fmt.Println()

	sys.Board.Print()
	fmt.Println()

	sys.Chassis.Print()
	fmt.Println()

	sys.Product.Print()
	fmt.Println()

	sys.Runtime.Print()
	fmt.Println()
	return nil
}

func SystemInfo() (model.SystemStruct, error) {
	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)
	bios, err := BIOS()
	if err != nil {
		return model.SystemStruct{}, err
	}
	board, err := Board()
	if err != nil {
		return model.SystemStruct{}, err
	}
	chassis, err := Chassis()
	if err != nil {
		return model.SystemStruct{}, err
	}
	product, err := Product()
	if err != nil {
		return model.SystemStruct{}, err
	}
	return model.SystemStruct{
		BIOS:    bios,
		Board:   board,
		Chassis: chassis,
		Product: product,
		// Version: app.GetVersion(),
		Runtime: &model.SystemRuntime{
			Version:     runtime.Version(),
			Cpus:        runtime.NumCPU(),
			Cgo:         runtime.NumCgoCall(),
			Goroutines:  runtime.NumGoroutine(),
			HeapSize:    memstats.HeapAlloc, // essentially what the profiler is giving you (active heap memory)
			Alloc:       memstats.Alloc,     // similar to HeapAlloc, but for all go managed memory
			Sys:         memstats.Sys,       // the total amount of memory (address space) requested from the OS
			Mallocs:     memstats.Mallocs,
			Frees:       memstats.Frees,
			NumGC:       memstats.NumGC,
			NumForcedGC: memstats.NumForcedGC,
		},
	}, nil
}

func BIOS() (model.BIOS, error) {
	date, err := os.ReadFile("/sys/class/dmi/id/bios_date")
	if err != nil {
		return model.BIOS{}, err
	}
	release, err := os.ReadFile("/sys/class/dmi/id/bios_release")
	if err != nil {
		return model.BIOS{}, err
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/bios_vendor")
	if err != nil {
		return model.BIOS{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/bios_version")
	if err != nil {
		return model.BIOS{}, err
	}
	return model.BIOS{
		Date:    strings.TrimSpace(string(date)),
		Release: strings.TrimSpace(string(release)),
		Vendor:  strings.TrimSpace(string(vendor)),
		Version: strings.TrimSpace(string(version)),
	}, nil
}

func Board() (model.Board, error) {
	assetTag, err := os.ReadFile("/sys/class/dmi/id/board_asset_tag")
	if err != nil {
		return model.Board{}, err
	}
	name, err := os.ReadFile("/sys/class/dmi/id/board_name")
	if err != nil {
		return model.Board{}, err
	}
	serial, err := os.ReadFile("/sys/class/dmi/id/board_serial")
	if err != nil {
		return model.Board{}, err
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/board_vendor")
	if err != nil {
		return model.Board{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/board_version")
	if err != nil {
		return model.Board{}, err
	}
	return model.Board{
		AssetTag: strings.TrimSpace(string(assetTag)),
		Name:     strings.TrimSpace(string(name)),
		Serial:   strings.TrimSpace(string(serial)),
		Vendor:   strings.TrimSpace(string(vendor)),
		Version:  strings.TrimSpace(string(version)),
	}, nil
}

func Chassis() (model.Chassis, error) {
	assetTag, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	if err != nil {
		return model.Chassis{}, err
	}
	chassisType, err := os.ReadFile("/sys/class/dmi/id/chassis_type")
	if err != nil {
		return model.Chassis{}, err
	}
	serial, err := os.ReadFile("/sys/class/dmi/id/chassis_serial")
	if err != nil {
		return model.Chassis{}, err
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/chassis_vendor")
	if err != nil {
		return model.Chassis{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/chassis_version")
	if err != nil {
		return model.Chassis{}, err
	}
	return model.Chassis{
		AssetTag: strings.TrimSpace(string(assetTag)),
		Serial:   strings.TrimSpace(string(serial)),
		Type:     strings.TrimSpace(string(chassisType)),
		Vendor:   strings.TrimSpace(string(vendor)),
		Version:  strings.TrimSpace(string(version)),
	}, nil
}

func Product() (model.Product, error) {
	family, err := os.ReadFile("/sys/class/dmi/id/product_family")
	if err != nil {
		return model.Product{}, err
	}
	name, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return model.Product{}, err
	}
	serial, err := os.ReadFile("/sys/class/dmi/id/product_serial")
	if err != nil {
		return model.Product{}, err
	}
	sku, err := os.ReadFile("/sys/class/dmi/id/product_sku")
	if err != nil {
		return model.Product{}, err
	}
	uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return model.Product{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/product_version")
	if err != nil {
		return model.Product{}, err
	}
	return model.Product{
		Family:  strings.TrimSpace(string(family)),
		Name:    strings.TrimSpace(string(name)),
		Serial:  strings.TrimSpace(string(serial)),
		SKU:     strings.TrimSpace(string(sku)),
		UUID:    strings.TrimSpace(string(uuid)),
		Version: strings.TrimSpace(string(version)),
	}, nil
}