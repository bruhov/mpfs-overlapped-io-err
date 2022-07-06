package main

import (
	"fmt"
	"syscall"
)

func main() {
	vmm := VMM{}
	vmm.init()

	err := vmm.initialize([]string{"", "-waitinitialize", "-device", "fpga"})
	if err {
		_ = syscall.FreeLibrary(vmm.dll)
		panic("VMMDLL_Initialize")
	}

	pid, err := vmm.pidGetFromName("explorer.exe")
	if err {
		_ = syscall.FreeLibrary(vmm.dll)
		panic("VMMDLL_PidGetFromName")
	}

	moduleBaseAddress, _, err := vmm.mapGetModuleFromName(pid, "explorer.exe")
	if err {
		_ = syscall.FreeLibrary(vmm.dll)
		panic("VMMDLL_Map_GetModuleFromName")
	}

	for i := 0; i < 10000; i++ {
		vmm.memReadScatter(pid, moduleBaseAddress)
	}

	_ = syscall.FreeLibrary(vmm.dll)
	fmt.Println("done")
}
