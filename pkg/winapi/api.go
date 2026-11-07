package winapi

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modNtdll    = syscall.NewLazyDLL("ntdll.dll")

	procWaitForDebugEvent        = modKernel32.NewProc("WaitForDebugEvent")
	procContinueDebugEvent       = modKernel32.NewProc("ContinueDebugEvent")
	procDebugActiveProcess       = modKernel32.NewProc("DebugActiveProcess")
	procDebugActiveProcessStop   = modKernel32.NewProc("DebugActiveProcessStop")
	procCreateProcessW           = modKernel32.NewProc("CreateProcessW")
	procOpenProcess              = modKernel32.NewProc("OpenProcess")
	procOpenThread               = modKernel32.NewProc("OpenThread")
	procSuspendThread            = modKernel32.NewProc("SuspendThread")
	procResumeThread             = modKernel32.NewProc("ResumeThread")
	procGetThreadContext         = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext         = modKernel32.NewProc("SetThreadContext")
	procWow64GetThreadContext    = modKernel32.NewProc("Wow64GetThreadContext")
	procWow64SetThreadContext    = modKernel32.NewProc("Wow64SetThreadContext")
	procReadProcessMemory        = modKernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory       = modKernel32.NewProc("WriteProcessMemory")
	procVirtualAllocEx           = modKernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx         = modKernel32.NewProc("VirtualProtectEx")
	procVirtualQueryEx           = modKernel32.NewProc("VirtualQueryEx")
	procFlushInstructionCache    = modKernel32.NewProc("FlushInstructionCache")
	procTerminateProcess         = modKernel32.NewProc("TerminateProcess")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32FirstW           = modKernel32.NewProc("Module32FirstW")
	procModule32NextW            = modKernel32.NewProc("Module32NextW")
	procIsWow64Process           = modKernel32.NewProc("IsWow64Process")
	procGetProcAddress           = modKernel32.NewProc("GetProcAddress")
	procGetModuleHandleW         = modKernel32.NewProc("GetModuleHandleW")
	procLoadLibraryW             = modKernel32.NewProc("LoadLibraryW")
	procLoadLibraryExW           = modKernel32.NewProc("LoadLibraryExW")
	procFreeLibrary              = modKernel32.NewProc("FreeLibrary")

	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
	procNtQueryInformationThread  = modNtdll.NewProc("NtQueryInformationThread")
)

func WaitForDebugEvent(event *DEBUG_EVENT, timeout uint32) error {
	r, _, err := procWaitForDebugEvent.Call(uintptr(unsafe.Pointer(event)), uintptr(timeout))
	if r == 0 {
		return err
	}
	return nil
}

func ContinueDebugEvent(processID, threadID, continueStatus uint32) error {
	r, _, err := procContinueDebugEvent.Call(uintptr(processID), uintptr(threadID), uintptr(continueStatus))
	if r == 0 {
		return err
	}
	return nil
}

func DebugActiveProcess(processID uint32) error {
	r, _, err := procDebugActiveProcess.Call(uintptr(processID))
	if r == 0 {
		return err
	}
	return nil
}

func DebugActiveProcessStop(processID uint32) error {
	r, _, err := procDebugActiveProcessStop.Call(uintptr(processID))
	if r == 0 {
		return err
	}
	return nil
}

func CreateProcess(appName, cmdLine string, currentDir string, flags uint32, si *syscall.StartupInfo, pi *syscall.ProcessInformation) error {
	var pApp, pCmd, pDir *uint16
	var err error
	if appName != "" {
		pApp, err = syscall.UTF16PtrFromString(appName)
		if err != nil {
			return err
		}
	}
	if cmdLine != "" {
		pCmd, err = syscall.UTF16PtrFromString(cmdLine)
		if err != nil {
			return err
		}
	}
	if currentDir != "" {
		pDir, err = syscall.UTF16PtrFromString(currentDir)
		if err != nil {
			return err
		}
	}

	r, _, err := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(pApp)),
		uintptr(unsafe.Pointer(pCmd)),
		0, 0,
		0, // bInheritHandles = FALSE
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(pDir)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if r == 0 {
		return err
	}
	return nil
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (syscall.Handle, error) {
	var inherit uintptr
	if inheritHandle {
		inherit = 1
	}
	r, _, err := procOpenProcess.Call(uintptr(desiredAccess), inherit, uintptr(processId))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func OpenThread(desiredAccess uint32, inheritHandle bool, threadId uint32) (syscall.Handle, error) {
	var inherit uintptr
	if inheritHandle {
		inherit = 1
	}
	r, _, err := procOpenThread.Call(uintptr(desiredAccess), inherit, uintptr(threadId))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func SuspendThread(hThread syscall.Handle) (uint32, error) {
	r, _, err := procSuspendThread.Call(uintptr(hThread))
	if int32(r) == -1 {
		return 0, err
	}
	return uint32(r), nil
}

func ResumeThread(hThread syscall.Handle) (uint32, error) {
	r, _, err := procResumeThread.Call(uintptr(hThread))
	if int32(r) == -1 {
		return 0, err
	}
	return uint32(r), nil
}

func GetThreadContext64(hThread syscall.Handle, ctx *CONTEXT64) error {
	storage := make([]byte, int(unsafe.Sizeof(*ctx))+15)
	offset := (16 - uintptr(unsafe.Pointer(&storage[0]))%16) % 16
	aligned := (*CONTEXT64)(unsafe.Pointer(&storage[offset]))
	*aligned = *ctx
	r, _, err := procGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(aligned)))
	*ctx = *aligned
	runtime.KeepAlive(storage)
	if r == 0 {
		return err
	}
	return nil
}

func SetThreadContext64(hThread syscall.Handle, ctx *CONTEXT64) error {
	storage := make([]byte, int(unsafe.Sizeof(*ctx))+15)
	offset := (16 - uintptr(unsafe.Pointer(&storage[0]))%16) % 16
	aligned := (*CONTEXT64)(unsafe.Pointer(&storage[offset]))
	*aligned = *ctx
	r, _, err := procSetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(aligned)))
	runtime.KeepAlive(storage)
	if r == 0 {
		return err
	}
	return nil
}

func GetThreadContext32(hThread syscall.Handle, ctx *CONTEXT32) error {
	// If running as 32-bit process, use standard GetThreadContext; if 64-bit host, use Wow64GetThreadContext
	var r uintptr
	var err error
	if unsafe.Sizeof(uintptr(0)) == 8 {
		r, _, err = procWow64GetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	} else {
		r, _, err = procGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	}
	if r == 0 {
		return err
	}
	return nil
}

func SetThreadContext32(hThread syscall.Handle, ctx *CONTEXT32) error {
	var r uintptr
	var err error
	if unsafe.Sizeof(uintptr(0)) == 8 {
		r, _, err = procWow64SetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	} else {
		r, _, err = procSetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(ctx)))
	}
	if r == 0 {
		return err
	}
	return nil
}

func ReadProcessMemory(hProcess syscall.Handle, baseAddr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var read uintptr
	r, _, err := procReadProcessMemory.Call(
		uintptr(hProcess),
		baseAddr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&read)),
	)
	if r == 0 {
		return int(read), err
	}
	if read != uintptr(len(buf)) {
		return int(read), fmt.Errorf("short process read: %d of %d bytes", read, len(buf))
	}
	return int(read), nil
}

func WriteProcessMemory(hProcess syscall.Handle, baseAddr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var written uintptr
	r, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		baseAddr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return int(written), err
	}
	if written != uintptr(len(buf)) {
		return int(written), fmt.Errorf("short process write: %d of %d bytes", written, len(buf))
	}
	return int(written), nil
}

func VirtualAllocEx(hProcess syscall.Handle, addr uintptr, size uintptr, allocType, protect uint32) (uintptr, error) {
	r, _, err := procVirtualAllocEx.Call(uintptr(hProcess), addr, size, uintptr(allocType), uintptr(protect))
	if r == 0 {
		return 0, err
	}
	return r, nil
}

func VirtualProtectEx(hProcess syscall.Handle, addr uintptr, size uintptr, newProtect uint32) (uint32, error) {
	var oldProtect uint32
	r, _, err := procVirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		size,
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return 0, err
	}
	return oldProtect, nil
}

func VirtualQueryEx(hProcess syscall.Handle, addr uintptr, mbi *MEMORY_BASIC_INFORMATION) (int, error) {
	r, _, err := procVirtualQueryEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(mbi)),
		uintptr(unsafe.Sizeof(*mbi)),
	)
	if r == 0 {
		return 0, err
	}
	return int(r), nil
}

func FlushInstructionCache(hProcess syscall.Handle, addr uintptr, size uintptr) error {
	r, _, err := procFlushInstructionCache.Call(uintptr(hProcess), addr, size)
	if r == 0 {
		return err
	}
	return nil
}

func TerminateProcess(hProcess syscall.Handle, exitCode uint32) error {
	r, _, err := procTerminateProcess.Call(uintptr(hProcess), uintptr(exitCode))
	if r == 0 {
		return err
	}
	return nil
}

func CloseHandle(h syscall.Handle) error {
	return syscall.CloseHandle(h)
}

func CreateToolhelp32Snapshot(flags uint32, processID uint32) (syscall.Handle, error) {
	r, _, err := procCreateToolhelp32Snapshot.Call(uintptr(flags), uintptr(processID))
	if syscall.Handle(r) == syscall.InvalidHandle {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func Module32First(hSnapshot syscall.Handle, me *MODULEENTRY32W) error {
	me.DwSize = uint32(unsafe.Sizeof(*me))
	r, _, err := procModule32FirstW.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(me)))
	if r == 0 {
		return err
	}
	return nil
}

func Module32Next(hSnapshot syscall.Handle, me *MODULEENTRY32W) error {
	me.DwSize = uint32(unsafe.Sizeof(*me))
	r, _, err := procModule32NextW.Call(uintptr(hSnapshot), uintptr(unsafe.Pointer(me)))
	if r == 0 {
		return err
	}
	return nil
}

func IsWow64Process(hProcess syscall.Handle) (bool, error) {
	var isWow64 int32
	r, _, err := procIsWow64Process.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&isWow64)))
	if r == 0 {
		return false, err
	}
	return isWow64 != 0, nil
}

func GetModuleHandle(name string) (syscall.Handle, error) {
	if name == "" {
		r, _, err := procGetModuleHandleW.Call(0)
		if r == 0 {
			return 0, err
		}
		return syscall.Handle(r), nil
	}
	pName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r, _, err := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(pName)))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func LoadLibrary(name string) (syscall.Handle, error) {
	pName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r, _, err := procLoadLibraryW.Call(uintptr(unsafe.Pointer(pName)))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func LoadLibraryEx(name string, flags uint32) (syscall.Handle, error) {
	pName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r, _, err := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(pName)), 0, uintptr(flags))
	if r == 0 {
		return 0, err
	}
	return syscall.Handle(r), nil
}

func FreeLibrary(hModule syscall.Handle) error {
	r, _, err := procFreeLibrary.Call(uintptr(hModule))
	if r == 0 {
		return err
	}
	return nil
}

func GetProcAddress(hModule syscall.Handle, procName string) (uintptr, error) {
	pName, err := syscall.BytePtrFromString(procName)
	if err != nil {
		return 0, err
	}
	r, _, err := procGetProcAddress.Call(uintptr(hModule), uintptr(unsafe.Pointer(pName)))
	if r == 0 {
		return 0, err
	}
	return r, nil
}

func NtQueryInformationProcess(hProcess syscall.Handle, infoClass uint32, info unsafe.Pointer, infoLen uint32, retLen *uint32) error {
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProcess),
		uintptr(infoClass),
		uintptr(info),
		uintptr(infoLen),
		uintptr(unsafe.Pointer(retLen)),
	)
	if r != 0 {
		return fmt.Errorf("NtQueryInformationProcess failed: 0x%08X", r)
	}
	return nil
}

func DebugModuleFileName(file, process syscall.Handle, base uintptr) string {
	buffer := make([]uint16, 32768)
	if file != 0 && file != syscall.InvalidHandle {
		length, _, _ := modKernel32.NewProc("GetFinalPathNameByHandleW").Call(uintptr(file), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
		if length > 0 && length < uintptr(len(buffer)) {
			return syscall.UTF16ToString(buffer[:length])
		}
	}
	length, _, _ := syscall.NewLazyDLL("psapi.dll").NewProc("GetMappedFileNameW").Call(uintptr(process), base, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if length > 0 && length < uintptr(len(buffer)) {
		return syscall.UTF16ToString(buffer[:length])
	}
	return ""
}
