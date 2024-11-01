package system

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

func PrintSystemInfo() error {

	sys, err := SystemInfo()
	if err != nil {
		return err
	}

	if sys.BIOS != nil {
		sys.BIOS.Print()
		fmt.Println()
	}

	if sys.Board != nil {
		sys.Board.Print()
		fmt.Println()
	}

	if sys.Chassis != nil {
		sys.Chassis.Print()
		fmt.Println()
	}

	if sys.Product != nil {
		sys.Product.Print()
		fmt.Println()
	}

	sys.Runtime.Print()
	fmt.Println()
	return nil
}

func SystemInfo() (entities.System, error) {

	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)

	systemInfo := entities.System{
		Runtime: &entities.SystemRuntime{
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
	}

	if os.Geteuid() == 0 {
		bios, err := BIOS()
		if err != nil {
			return entities.System{}, err
		}
		board, err := Board()
		if err != nil {
			return entities.System{}, err
		}
		chassis, err := Chassis()
		if err != nil {
			return entities.System{}, err
		}
		product, err := Product()
		if err != nil {
			return entities.System{}, err
		}
		systemInfo.BIOS = &bios
		systemInfo.Board = &board
		systemInfo.Chassis = &chassis
		systemInfo.Product = &product
	}

	return systemInfo, nil
}

func BIOS() (entities.BIOS, error) {
	date, err := os.ReadFile("/sys/class/dmi/id/bios_date")
	if err != nil {
		return entities.BIOS{}, err
	}
	release, err := os.ReadFile("/sys/class/dmi/id/bios_release")
	if err != nil {
		return entities.BIOS{}, err
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/bios_vendor")
	if err != nil {
		return entities.BIOS{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/bios_version")
	if err != nil {
		return entities.BIOS{}, err
	}
	return entities.BIOS{
		Date:    strings.TrimSpace(string(date)),
		Release: strings.TrimSpace(string(release)),
		Vendor:  strings.TrimSpace(string(vendor)),
		Version: strings.TrimSpace(string(version)),
	}, nil
}

func Board() (entities.Board, error) {
	assetTag, err := os.ReadFile("/sys/class/dmi/id/board_asset_tag")
	if err != nil {
		return entities.Board{}, err
	}
	name, err := os.ReadFile("/sys/class/dmi/id/board_name")
	if err != nil {
		return entities.Board{}, err
	}
	serial, err := os.ReadFile("/sys/class/dmi/id/board_serial")
	if err != nil {
		return entities.Board{}, err
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/board_vendor")
	if err != nil {
		return entities.Board{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/board_version")
	if err != nil {
		return entities.Board{}, err
	}
	return entities.Board{
		AssetTag: strings.TrimSpace(string(assetTag)),
		Name:     strings.TrimSpace(string(name)),
		Serial:   strings.TrimSpace(string(serial)),
		Vendor:   strings.TrimSpace(string(vendor)),
		Version:  strings.TrimSpace(string(version)),
	}, nil
}

func Chassis() (entities.Chassis, error) {
	assetTag, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	if err != nil {
		return entities.Chassis{}, err
	}
	chassisType, err := os.ReadFile("/sys/class/dmi/id/chassis_type")
	if err != nil {
		return entities.Chassis{}, err
	}
	serial, err := os.ReadFile("/sys/class/dmi/id/chassis_serial")
	if err != nil {
		return entities.Chassis{}, err
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/chassis_vendor")
	if err != nil {
		return entities.Chassis{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/chassis_version")
	if err != nil {
		return entities.Chassis{}, err
	}
	return entities.Chassis{
		AssetTag: strings.TrimSpace(string(assetTag)),
		Serial:   strings.TrimSpace(string(serial)),
		Type:     strings.TrimSpace(string(chassisType)),
		Vendor:   strings.TrimSpace(string(vendor)),
		Version:  strings.TrimSpace(string(version)),
	}, nil
}

func Product() (entities.Product, error) {
	family, err := os.ReadFile("/sys/class/dmi/id/product_family")
	if err != nil {
		return entities.Product{}, err
	}
	name, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return entities.Product{}, err
	}
	serial, err := os.ReadFile("/sys/class/dmi/id/product_serial")
	if err != nil {
		return entities.Product{}, err
	}
	sku, err := os.ReadFile("/sys/class/dmi/id/product_sku")
	if err != nil {
		return entities.Product{}, err
	}
	uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return entities.Product{}, err
	}
	version, err := os.ReadFile("/sys/class/dmi/id/product_version")
	if err != nil {
		return entities.Product{}, err
	}
	return entities.Product{
		Family:  strings.TrimSpace(string(family)),
		Name:    strings.TrimSpace(string(name)),
		Serial:  strings.TrimSpace(string(serial)),
		SKU:     strings.TrimSpace(string(sku)),
		UUID:    strings.TrimSpace(string(uuid)),
		Version: strings.TrimSpace(string(version)),
	}, nil
}
