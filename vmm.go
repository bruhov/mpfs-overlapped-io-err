package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	VMMDLL_FLAG_NOCACHE = 0x0001
)

type VMM struct {
	dll                          syscall.Handle
	VMMDLL_Initialize            uintptr
	VMMDLL_PidGetFromName        uintptr
	VMMDLL_Map_GetModuleFromName uintptr
	VMMDLL_MemReadScatter        uintptr
}

func (vmm *VMM) init() {
	var vmmDLLLoadError error
	vmm.dll, vmmDLLLoadError = syscall.LoadLibrary("vmm.dll")
	if vmmDLLLoadError != nil {
		vmm.abort("vmm.dll loading error", vmmDLLLoadError)
	}
	vmm.VMMDLL_Initialize = vmm.getProcAddress(vmm.dll, "VMMDLL_Initialize")
	vmm.VMMDLL_PidGetFromName = vmm.getProcAddress(vmm.dll, "VMMDLL_PidGetFromName")
	vmm.VMMDLL_Map_GetModuleFromName = vmm.getProcAddress(vmm.dll, "VMMDLL_Map_GetModuleFromNameW")
	vmm.VMMDLL_MemReadScatter = vmm.getProcAddress(vmm.dll, "VMMDLL_MemReadScatter")
}

func (vmm *VMM) abort(text string, err error) {
	_ = syscall.FreeLibrary(vmm.dll)
	panic(fmt.Sprintf("%s: %v", text, err))
}

func (vmm *VMM) getProcAddress(module syscall.Handle, procname string) uintptr {
	address, getProcAddressError := syscall.GetProcAddress(module, procname)
	if getProcAddressError != nil {
		vmm.abort("Failed to get address of '"+procname, getProcAddressError)
	}
	return address
}

// https://golang.org/pkg/syscall/#StringSlicePtr
// https://stackoverflow.com/a/56758803/9288744
func (vmm *VMM) stringSlicePtr(ss []string) []*byte {
	bb := make([]*byte, len(ss))
	for i := 0; i < len(ss); i++ {
		bb[i], _ = syscall.BytePtrFromString(ss[i])
	}
	return bb
}

func (vmm *VMM) bytePtrFromString(input string) *byte {
	result, _ := syscall.BytePtrFromString(input)
	return result
}

func (vmm *VMM) utf16PtrFromString(input string) *uint16 {
	result, _ := syscall.UTF16PtrFromString(input)
	return result
}

func (vmm *VMM) initialize(arguments []string) (isError bool) {
	argc := uint32(len(arguments))
	argv := vmm.stringSlicePtr(arguments)
	result, _, syscallError := syscall.Syscall(
		vmm.VMMDLL_Initialize,
		2,
		uintptr(argc),
		uintptr(unsafe.Pointer(&argv[0])),
		0,
	)
	if syscallError != 0 {
		vmm.abort("VMMDLL_Initialize", syscallError)
	}
	isError = result == 0
	return
}

func (vmm *VMM) pidGetFromName(processName string) (pid int, isError bool) {
	szProcName := vmm.bytePtrFromString(processName)
	var pdwPID uint32
	result, _, syscallError := syscall.Syscall(
		vmm.VMMDLL_PidGetFromName,
		2,
		uintptr(unsafe.Pointer(szProcName)),
		uintptr(unsafe.Pointer(&pdwPID)),
		0,
	)
	if syscallError != 0 {
		vmm.abort("VMMDLL_PidGetFromName", syscallError)
	}
	pid = int(pdwPID)
	isError = result == 0
	return
}

type VMMDLL_MAP_MODULEENTRY struct {
	vaBase        uint64
	vaEntry       uint64
	cbImageSize   uint32
	fWoW64        bool
	wszText       *byte
	_Reserved3    uint32
	_Reserved4    uint32
	wszFullName   *byte
	tp            uint32
	cbFileSizeRaw uint32
	cSection      uint32
	cEAT          uint32
	cIAT          uint32
	_Reserved2    uint32
	_Reserved1    [2]uint64
}

func (vmm *VMM) mapGetModuleFromName(pid int, moduleName string) (base uint, size int, isError bool) {
	wszModuleName := vmm.utf16PtrFromString(moduleName)
	pModuleMapEntry := VMMDLL_MAP_MODULEENTRY{}
	result, _, syscallError := syscall.Syscall6(
		vmm.VMMDLL_Map_GetModuleFromName,
		4,
		uintptr(pid),
		uintptr(unsafe.Pointer(wszModuleName)),
		uintptr(unsafe.Pointer(&pModuleMapEntry)),
		uintptr(0),
		0,
		0,
	)
	if syscallError != 0 {
		vmm.abort("VMMDLL_Map_GetModuleFromName", syscallError)
	}
	base = uint(pModuleMapEntry.vaBase)
	size = int(pModuleMapEntry.cbImageSize)
	isError = result == 0
	return
}

type MEM_SCATTER struct {
	version uint32   // MEM_SCATTER_VERSION
	f       bool     // TRUE = success data in pb, FALSE = fail or not yet read.
	qwA     uint     // address of memory to read
	pb      *byte    // buffer to hold memory contents
	cb      uint32   // size of buffer to hold memory contents.
	iStack  uint32   // internal stack pointer
	vStack  [12]uint // internal stack
}

func (vmm *VMM) memReadScatter(pid int, addressPageStart uint) {
	buffer := make([]byte, 0x1000)
	scatterHeaders := make([]*MEM_SCATTER, 1)
	scatterHeaders[0] = &MEM_SCATTER{
		version: 0xc0fe0002,
		qwA:     addressPageStart,
		cb:      0x1000,
		pb:      &buffer[0],
	}
	cpMEMs := len(scatterHeaders)
	_, _, syscallError := syscall.Syscall6(
		vmm.VMMDLL_MemReadScatter,
		4,
		uintptr(pid),
		uintptr(unsafe.Pointer(&scatterHeaders[0])),
		uintptr(cpMEMs),
		uintptr(VMMDLL_FLAG_NOCACHE),
		0,
		0,
	)
	if syscallError != 0 {
		vmm.abort("VMMDLL_MemReadScatter", syscallError)
	}
	return
}
