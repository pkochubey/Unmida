package debugger

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"unmida/pkg/log"
	"unmida/pkg/pe"
	"unmida/pkg/utils"
	"unmida/pkg/winapi"
)

type HWBPType int

const (
	HWExecute HWBPType = 0
	HWWrite   HWBPType = 1
	HWAccess  HWBPType = 3
)

type Breakpoint struct {
	Address  uintptr
	BType    HWBPType
	Disabled bool
}

func (bp *Breakpoint) Change(addr uintptr, bType HWBPType) {
	bp.Address = addr
	bp.BType = bType
	bp.Disabled = false
}

func (bp *Breakpoint) IsSet() bool {
	return !bp.Disabled && bp.Address > 0
}

type SoftBPAction int

const (
	SbpKeepContinue SoftBPAction = iota
	SbpClearContinue
	SbpKeepContinueNoStep
)

type DebuggerCallbacks interface {
	OnDebugStart(hFile syscall.Handle, hThread syscall.Handle)
	OnAccessViolation(hThread syscall.Handle, excRec *winapi.EXCEPTION_RECORD) uint32
	OnDLLLoad(fileName string, baseAddress uintptr)
	OnHardwareBreakpoint(hThread syscall.Handle, bpa uintptr, c32 *winapi.CONTEXT32, c64 *winapi.CONTEXT64)
	OnSoftwareBreakpoint(hThread syscall.Handle, bpa uintptr) SoftBPAction
	OnUnsolicitedSoftwareBreakpoint(hThread syscall.Handle, bpa uintptr)
	OnSinglestep(bpa uintptr) uint32
}

type DebuggerCore struct {
	Callbacks DebuggerCallbacks

	Executable    string
	Parameters    string
	AttachPID     uint32
	IsDLL         bool
	Is64Bit       bool
	DLLExecutable string

	ProcessInfo           syscall.ProcessInformation
	CurrentThreadID       uint32
	ImageBase             uintptr
	HideThreadEnd         bool
	HW                    [4]Breakpoint
	Threads               map[uint32]syscall.Handle
	SoftBPs               map[uintptr]byte
	SoftBPReenable        uintptr
	mu                    sync.Mutex
	ShouldTerminate       bool
	Err                   error
	Succeeded             bool
	EventConsumed         bool
	InitialBreakpointSeen bool
	CurrentThreadHnd      syscall.Handle
}

func NewDebuggerCore(executable, parameters string, callbacks DebuggerCallbacks) *DebuggerCore {
	return &DebuggerCore{
		Executable: executable,
		Parameters: parameters,
		Callbacks:  callbacks,
		Threads:    make(map[uint32]syscall.Handle),
		SoftBPs:    make(map[uintptr]byte),
	}
}

func (d *DebuggerCore) RPM(addr uintptr, buf []byte) bool {
	_, err := winapi.ReadProcessMemory(d.ProcessInfo.Process, addr, buf)
	return err == nil
}

func (d *DebuggerCore) WriteByte(addr uintptr, val byte) bool {
	oldProt, err := winapi.VirtualProtectEx(d.ProcessInfo.Process, addr, 1, winapi.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return false
	}
	_, err = winapi.WriteProcessMemory(d.ProcessInfo.Process, addr, []byte{val})
	if err != nil {
		winapi.VirtualProtectEx(d.ProcessInfo.Process, addr, 1, oldProt)
		return false
	}
	winapi.VirtualProtectEx(d.ProcessInfo.Process, addr, 1, oldProt)
	winapi.FlushInstructionCache(d.ProcessInfo.Process, addr, 1)
	return true
}

func (d *DebuggerCore) SetBreakpoint(addr uintptr, bType HWBPType, refreshContexts bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	idx := -1
	for i := 0; i < 4; i++ {
		if d.HW[i].Address == addr {
			d.HW[i].Change(addr, bType)
			if refreshContexts {
				for _, thread := range d.Threads {
					d.UpdateDR(thread)
				}
			}
			return nil
		}
		if d.HW[i].Address == 0 {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("all hardware breakpoints in use")
	}

	d.HW[idx].Change(addr, bType)

	if refreshContexts {
		for _, hThread := range d.Threads {
			d.UpdateDR(hThread)
		}
	}
	return nil
}

func (d *DebuggerCore) DisableBreakpoint(addr uintptr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := 0; i < 4; i++ {
		if d.HW[i].Address == addr {
			d.HW[i].Disabled = true
			return true
		}
	}
	return false
}

func (d *DebuggerCore) EnableBreakpoints() {
	d.mu.Lock()
	defer d.mu.Unlock()

	needUpdate := false
	for i := 0; i < 4; i++ {
		if d.HW[i].Disabled {
			d.HW[i].Disabled = false
			needUpdate = true
		}
	}
	if needUpdate {
		for _, hThread := range d.Threads {
			d.UpdateDR(hThread)
		}
	}
}

func (d *DebuggerCore) ResetBreakpoint(addr uintptr) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := 0; i < 4; i++ {
		if d.HW[i].Address == addr {
			d.HW[i].Address = 0
			d.HW[i].Disabled = false
		}
	}
	for _, hThread := range d.Threads {
		d.UpdateDR(hThread)
	}
}

func (d *DebuggerCore) IsHWBreakpoint(addr uintptr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i := 0; i < 4; i++ {
		if d.HW[i].Address == addr {
			return true
		}
	}
	return false
}

func (d *DebuggerCore) ApplyDebugRegisters64(c *winapi.CONTEXT64) {
	mask := uint32(0)

	c.Dr0 = uint64(d.HW[0].Address)
	if d.HW[0].IsSet() {
		mask |= 1
	}

	c.Dr1 = uint64(d.HW[1].Address)
	if d.HW[1].IsSet() {
		mask |= (1 << 2)
	}

	c.Dr2 = uint64(d.HW[2].Address)
	if d.HW[2].IsSet() {
		mask |= (1 << 4)
	}

	c.Dr3 = uint64(d.HW[3].Address)
	if d.HW[3].IsSet() {
		mask |= (1 << 6)
	}

	c.Dr6 &= 0xFFFFBFFF
	c.Dr7 = uint64(mask | (uint32(d.HW[0].BType) << 16) | (uint32(d.HW[1].BType) << 20) | (uint32(d.HW[2].BType) << 24) | (uint32(d.HW[3].BType) << 28))
}

func (d *DebuggerCore) ApplyDebugRegisters32(c *winapi.CONTEXT32) {
	mask := uint32(0)

	c.Dr0 = uint32(d.HW[0].Address)
	if d.HW[0].IsSet() {
		mask |= 1
	}

	c.Dr1 = uint32(d.HW[1].Address)
	if d.HW[1].IsSet() {
		mask |= (1 << 2)
	}

	c.Dr2 = uint32(d.HW[2].Address)
	if d.HW[2].IsSet() {
		mask |= (1 << 4)
	}

	c.Dr3 = uint32(d.HW[3].Address)
	if d.HW[3].IsSet() {
		mask |= (1 << 6)
	}

	c.Dr6 &= 0xFFFFBFFF
	c.Dr7 = mask | (uint32(d.HW[0].BType) << 16) | (uint32(d.HW[1].BType) << 20) | (uint32(d.HW[2].BType) << 24) | (uint32(d.HW[3].BType) << 28)
}

func (d *DebuggerCore) UpdateDR(hThread syscall.Handle) {
	if d.Is64Bit {
		var c winapi.CONTEXT64
		c.ContextFlags = winapi.CONTEXT_DEBUG_REGISTERS_64
		if err := winapi.GetThreadContext64(hThread, &c); err == nil {
			d.ApplyDebugRegisters64(&c)
			if err := winapi.SetThreadContext64(hThread, &c); err != nil {
				d.Fail(err)
			}
		} else {
			d.Fail(fmt.Errorf("UpdateDR: GetThreadContext64: %w", err))
		}
	} else {
		var c winapi.CONTEXT32
		c.ContextFlags = winapi.CONTEXT_DEBUG_REGISTERS_32
		if err := winapi.GetThreadContext32(hThread, &c); err == nil {
			d.ApplyDebugRegisters32(&c)
			if err := winapi.SetThreadContext32(hThread, &c); err != nil {
				d.Fail(err)
			}
		} else {
			d.Fail(fmt.Errorf("UpdateDR: GetThreadContext32: %w", err))
		}
	}
}

func (d *DebuggerCore) SetSoftBP(addr uintptr) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var b [1]byte
	if !d.RPM(addr, b[:]) {
		return fmt.Errorf("read for soft bp at 0x%X failed", addr)
	}

	if orig, ok := d.SoftBPs[addr]; ok {
		if b[0] != 0xCC {
			log.Fatalf("Soft bp inconsistency at 0x%X (stored 0x%X, got 0x%X)", addr, orig, b[0])
		}
		return nil
	}

	d.SoftBPs[addr] = b[0]
	if !d.WriteByte(addr, 0xCC) {
		return fmt.Errorf("write for soft bp at 0x%X failed", addr)
	}
	return nil
}

func (d *DebuggerCore) SoftBPClear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for addr, orig := range d.SoftBPs {
		d.WriteByte(addr, orig)
	}
	d.SoftBPs = make(map[uintptr]byte)
}

func (d *DebuggerCore) PEInspect() error {
	data, err := os.ReadFile(d.Executable)
	if err != nil {
		return err
	}
	if len(data) < 0x40 {
		return fmt.Errorf("selected file is too short")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("selected file is not a valid PE")
	}
	lfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if lfanew > 0xF00 || uint64(lfanew)+24 > uint64(len(data)) {
		return fmt.Errorf("selected file has malformed PE headers")
	}

	sig := binary.LittleEndian.Uint32(data[lfanew : lfanew+4])
	if sig != 0x00004550 {
		return fmt.Errorf("PE file signature mismatch: 0x%08X", sig)
	}

	machine := binary.LittleEndian.Uint16(data[lfanew+4 : lfanew+6])
	if machine == winapi.IMAGE_FILE_MACHINE_AMD64 {
		d.Is64Bit = true
	} else if machine == winapi.IMAGE_FILE_MACHINE_I386 {
		d.Is64Bit = false
	} else {
		return fmt.Errorf("unsupported machine architecture: 0x%04X", machine)
	}

	characteristics := binary.LittleEndian.Uint16(data[lfanew+22 : lfanew+24])
	d.IsDLL = (characteristics & winapi.IMAGE_FILE_DLL) != 0

	if d.Is64Bit != (unsafe.Sizeof(uintptr(0)) == 8) {
		return fmt.Errorf("file architecture differs from Unmida; use the %d-bit version", map[bool]int{true: 64, false: 32}[d.Is64Bit])
	}
	return nil
}

func (d *DebuggerCore) MakeDLLExecutable() error {
	d.DLLExecutable = d.Executable + "MM.exe"
	data, err := os.ReadFile(d.Executable)
	if err != nil {
		return fmt.Errorf("reading DLL failed: %w", err)
	}

	lfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	// Clear IMAGE_FILE_DLL
	chars := binary.LittleEndian.Uint16(data[lfanew+22 : lfanew+24])
	chars &^= winapi.IMAGE_FILE_DLL
	binary.LittleEndian.PutUint16(data[lfanew+22:lfanew+24], chars)

	peHeader, err := pe.ParsePEHeader(data)
	if err != nil {
		return fmt.Errorf("parsing PE failed: %w", err)
	}

	// Disable "Code Integrity Image" (DllCharacteristics 0x80)
	if (peHeader.DllCharacteristics & 0x80) != 0 {
		peHeader.DllCharacteristics &^= 0x80
		// OptionalHeader DllCharacteristics offset
		dllCharsOffset := lfanew + 24 + 70
		if int(dllCharsOffset)+2 <= len(data) {
			binary.LittleEndian.PutUint16(data[dllCharsOffset:dllCharsOffset+2], peHeader.DllCharacteristics)
		}
	}

	var stub []byte
	if !peHeader.Is64Bit {
		stub = []byte{0x8B, 0x40, 0x08, 0x6A, 0x00, 0x6A, 0x01, 0x50, 0xE8, 0x00, 0x00, 0x00, 0x00}
	} else {
		stub = []byte{
			0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
			0x48, 0x8B, 0x48, 0x10, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC0,
			0xE8, 0x00, 0x00, 0x00, 0x00,
		}
	}

	epSec := peHeader.GetSectionByVA(peHeader.AddressOfEntryPoint)
	if epSec == nil {
		return fmt.Errorf("cannot find section for entrypoint")
	}

	stubOffset := int(epSec.Header.PointerToRawData+epSec.Header.SizeOfRawData) - len(stub)
	if stubOffset < 0 || stubOffset+len(stub) > len(data) {
		return fmt.Errorf("not enough room in EP section")
	}

	for i := stubOffset; i < stubOffset+len(stub); i++ {
		if data[i] != 0 {
			log.Fatalf("Not enough room in EP section (non-zero bytes present)")
			return fmt.Errorf("EP section not padded with zeroes")
		}
	}

	newEP := epSec.Header.VirtualAddress + epSec.Header.SizeOfRawData - uint32(len(stub))
	rel := int32(peHeader.AddressOfEntryPoint - (newEP + uint32(len(stub))))

	copy(data[stubOffset:], stub)
	binary.LittleEndian.PutUint32(data[stubOffset+len(stub)-4:stubOffset+len(stub)], uint32(rel))

	// Update AddressOfEntryPoint
	peHeader.AddressOfEntryPoint = newEP
	optEPPos := lfanew + 24 + 16
	binary.LittleEndian.PutUint32(data[optEPPos:optEPPos+4], newEP)

	if err := os.WriteFile(d.DLLExecutable, data, 0755); err != nil {
		return fmt.Errorf("writing modified DLL failed: %w", err)
	}

	// Switch SxS Manifest type
	f, err := os.OpenFile(d.DLLExecutable, os.O_RDWR, 0755)
	if err == nil {
		SwitchSxSManifestType(f, peHeader, 2, 1)
		f.Close()
	}

	return nil
}

func SwitchSxSManifestType(s io.ReadWriteSeeker, peHeader *pe.PEHeader, switchFrom, switchTo int) {
	rsrcDir := peHeader.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	if rsrcDir.VirtualAddress == 0 || rsrcDir.Size == 0 {
		return
	}
	rsrcSec := peHeader.GetSectionByVA(rsrcDir.VirtualAddress)
	if rsrcSec == nil {
		return
	}

	if _, err := s.Seek(int64(rsrcSec.Header.PointerToRawData+rsrcDir.VirtualAddress-rsrcSec.Header.VirtualAddress), io.SeekStart); err != nil {
		return
	}

	rsrcData := make([]byte, rsrcDir.Size)
	if _, err := io.ReadFull(s, rsrcData); err != nil {
		return
	}

	if len(rsrcData) < 16 {
		return
	}

	numNamed := binary.LittleEndian.Uint16(rsrcData[0x0C:0x0E])
	numID := binary.LittleEndian.Uint16(rsrcData[0x0E:0x10])
	if numID == 0 {
		return
	}

	offset := 0x10 + int(numNamed)*8
	manifestSubDir := uint32(0)
	for i := 0; i < int(numID); i++ {
		entryOffset := offset + i*8
		if entryOffset+8 > len(rsrcData) {
			break
		}
		typeID := binary.LittleEndian.Uint32(rsrcData[entryOffset : entryOffset+4])
		if typeID == 24 { // RT_MANIFEST
			manifestSubDir = binary.LittleEndian.Uint32(rsrcData[entryOffset+4 : entryOffset+8])
			break
		}
	}

	if manifestSubDir == 0 || (manifestSubDir>>31) != 1 {
		return
	}
	manifestSubDir &= 0x7FFFFFFF

	if int(manifestSubDir)+16 > len(rsrcData) {
		return
	}

	idOffset := int(manifestSubDir) + 0x10
	if idOffset+4 > len(rsrcData) {
		return
	}

	currID := int(binary.LittleEndian.Uint32(rsrcData[idOffset : idOffset+4]))
	if currID != switchFrom {
		return
	}

	if _, err := s.Seek(int64(rsrcSec.Header.PointerToRawData+rsrcDir.VirtualAddress-rsrcSec.Header.VirtualAddress)+int64(idOffset), io.SeekStart); err == nil {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(switchTo))
		s.Write(buf[:])
	}
}

func (d *DebuggerCore) PEExecute() error {
	if d.AttachPID != 0 {
		return winapi.DebugActiveProcess(d.AttachPID)
	}

	if err := d.PEInspect(); err != nil {
		return err
	}

	targetDir := filepath.Dir(d.Executable)

	var cmdLine string
	if d.IsDLL {
		if err := d.MakeDLLExecutable(); err != nil {
			return err
		}
		log.Infof("Debugging modified DLL: %s", d.DLLExecutable)
		cmdLine = fmt.Sprintf(`"%s"`, d.DLLExecutable)
	} else {
		cmdLine = fmt.Sprintf(`"%s" %s`, d.Executable, strings.TrimRight(d.Parameters, " "))
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = winapi.STARTF_USESHOWWINDOW
	si.ShowWindow = winapi.SW_SHOW

	flags := uint32(winapi.CREATE_DEFAULT_ERROR_MODE | winapi.CREATE_NEW_CONSOLE | winapi.NORMAL_PRIORITY_CLASS | winapi.DEBUG_PROCESS | winapi.DEBUG_ONLY_THIS_PROCESS)

	workDir := targetDir

	return winapi.CreateProcess("", cmdLine, workDir, flags, &si, &d.ProcessInfo)
}

func (d *DebuggerCore) RunDebugLoop() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer d.cleanup()
	if err := d.PEExecute(); err != nil {
		return fmt.Errorf("creating process failed: %w", err)
	}

	status := uint32(winapi.DBG_CONTINUE)
	var ev winapi.DEBUG_EVENT

	for !d.ShouldTerminate {
		if err := winapi.WaitForDebugEvent(&ev, 0xFFFFFFFF); err != nil {
			return fmt.Errorf("WaitForDebugEvent failed: %w", err)
		}

		d.CurrentThreadID = ev.DwThreadId
		hThread := d.Threads[ev.DwThreadId]
		d.CurrentThreadHnd = hThread

		switch ev.DwDebugEventCode {
		case winapi.EXCEPTION_DEBUG_EVENT:
			status = d.handleException(&ev)

		case winapi.CREATE_THREAD_DEBUG_EVENT:
			info := ev.CreateThread()
			log.Infof("[%.4d] Thread started (%p).", ev.DwThreadId, info.LpStartAddress)
			d.Threads[ev.DwThreadId] = info.HThread
			d.UpdateDR(info.HThread)
			status = winapi.DBG_CONTINUE

		case winapi.CREATE_PROCESS_DEBUG_EVENT:
			info := ev.CreateProcessInfo()
			log.Infof("Running on Windows build %d", utils.GetWindowsBuildNumber())
			log.Infof("Debug session launched (PID: %d, TID: %d)", ev.DwProcessId, ev.DwThreadId)

			d.ProcessInfo.Process = info.HProcess
			d.ProcessInfo.ProcessId = ev.DwProcessId
			d.ProcessInfo.ThreadId = ev.DwThreadId
			d.ImageBase = info.LpBaseOfImage
			d.Threads[ev.DwThreadId] = info.HThread

			var pbi winapi.PROCESS_BASIC_INFORMATION
			if err := winapi.NtQueryInformationProcess(info.HProcess, 0, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil {
				winapi.CloseHandle(info.HFile)
				return err
			}
			log.Infof("PEB: %p", unsafe.Pointer(pbi.PebBaseAddress))

			// Patch PEB.BeingDebugged (offset 2)
			var beingDebugged [1]byte
			if d.RPM(pbi.PebBaseAddress+2, beingDebugged[:]) {
				if beingDebugged[0] == 1 {
					log.Goodf("Patching PEB.BeingDebugged")
					d.WriteByte(pbi.PebBaseAddress+2, 0)
				}
			}

			// Read ImageBase from PEB: +8 on 32-bit, +16 on 64-bit
			offsetImageBase := uintptr(8)
			offsetShimData := uintptr(0x1E8)
			if d.Is64Bit {
				offsetImageBase = 16
				offsetShimData = 0x2D8
			}

			var imgBaseBuf [8]byte
			readLen := 4
			if d.Is64Bit {
				readLen = 8
			}
			if d.RPM(pbi.PebBaseAddress+offsetImageBase, imgBaseBuf[:readLen]) {
				if d.Is64Bit {
					d.ImageBase = uintptr(binary.LittleEndian.Uint64(imgBaseBuf[:8]))
				} else {
					d.ImageBase = uintptr(binary.LittleEndian.Uint32(imgBaseBuf[:4]))
				}
				log.Infof("Process Image Base: 0x%X", d.ImageBase)
			} else {
				return fmt.Errorf("reading process image base failed")
			}

			// Clear PEB.pShimData
			var shimBuf [8]byte
			if d.RPM(pbi.PebBaseAddress+offsetShimData, shimBuf[:readLen]) {
				hasShim := false
				for i := 0; i < readLen; i++ {
					if shimBuf[i] != 0 {
						hasShim = true
						break
					}
				}
				if hasShim {
					zeroes := make([]byte, readLen)
					winapi.WriteProcessMemory(info.HProcess, pbi.PebBaseAddress+offsetShimData, zeroes)
					log.Infof("Cleared PEB.pShimData to prevent apphelp hooks")
				}
			}

			if d.Callbacks != nil {
				d.Callbacks.OnDebugStart(info.HFile, info.HThread)
			}
			winapi.CloseHandle(info.HFile)
			status = winapi.DBG_CONTINUE

		case winapi.EXIT_THREAD_DEBUG_EVENT:
			info := ev.ExitThread()
			if !d.HideThreadEnd {
				log.Infof("[%.4d] Thread ended (code %d).", ev.DwThreadId, info.DwExitCode)
			}
			winapi.CloseHandle(d.Threads[ev.DwThreadId])
			delete(d.Threads, ev.DwThreadId)
			status = winapi.DBG_CONTINUE

		case winapi.EXIT_PROCESS_DEBUG_EVENT:
			info := ev.ExitProcess()
			log.Infof("Process ended (code %d).", info.DwExitCode)
			winapi.ContinueDebugEvent(ev.DwProcessId, ev.DwThreadId, winapi.DBG_CONTINUE)
			if !d.Succeeded {
				return fmt.Errorf("target exited before unpacking completed (code %d)", info.DwExitCode)
			}
			return d.Err

		case winapi.LOAD_DLL_DEBUG_EVENT:
			info := ev.LoadDll()
			dllName := winapi.DebugModuleFileName(info.HFile, d.ProcessInfo.Process, info.LpBaseOfDll)
			var lpImageName uintptr
			var pBuf [8]byte
			ptrSize := 4
			if d.Is64Bit {
				ptrSize = 8
			}
			if dllName == "" && d.RPM(info.LpImageName, pBuf[:ptrSize]) {
				if d.Is64Bit {
					lpImageName = uintptr(binary.LittleEndian.Uint64(pBuf[:8]))
				} else {
					lpImageName = uintptr(binary.LittleEndian.Uint32(pBuf[:4]))
				}
				if lpImageName != 0 {
					var wideBuf [520]byte
					if d.RPM(lpImageName, wideBuf[:]) {
						var runes []uint16
						for i := 0; i < len(wideBuf); i += 2 {
							r := binary.LittleEndian.Uint16(wideBuf[i : i+2])
							if r == 0 {
								break
							}
							runes = append(runes, r)
						}
						dllName = syscall.UTF16ToString(runes)
					}
				}
			}
			if dllName == "" {
				dllName = "?"
			}
			log.Infof("[0x%08X] Loaded %s", info.LpBaseOfDll, dllName)
			if strings.Contains(strings.ToLower(dllName), "aclayers.dll") {
				log.Fatalf("Compatibility mode screws up the unpacking process.")
				return fmt.Errorf("compatibility mode detected")
			}
			if d.Callbacks != nil {
				d.Callbacks.OnDLLLoad(dllName, info.LpBaseOfDll)
			}
			winapi.CloseHandle(info.HFile)
			status = winapi.DBG_CONTINUE

		case winapi.UNLOAD_DLL_DEBUG_EVENT:
			status = winapi.DBG_CONTINUE

		case winapi.OUTPUT_DEBUG_STRING_EVENT:
			info := ev.DebugString()
			if info.NDebugStringLength > 0 && info.NDebugStringLength < 256 {
				strBuf := make([]byte, info.NDebugStringLength)
				if d.RPM(info.LpDebugStringData, strBuf) {
					log.Infof("[Debug Str] %s", strings.TrimRight(string(strBuf), "\x00"))
				}
			}
			status = winapi.DBG_CONTINUE

		case winapi.RIP_EVENT:
			d.Fail(fmt.Errorf("system error (RIP event)"))
			status = winapi.DBG_CONTINUE
		}

		if d.EventConsumed {
			d.EventConsumed = false
		} else {
			if err := winapi.ContinueDebugEvent(ev.DwProcessId, ev.DwThreadId, status); err != nil && !d.ShouldTerminate {
				return err
			}
		}
	}

	return d.Err
}

func (d *DebuggerCore) handleException(ev *winapi.DEBUG_EVENT) uint32 {
	exc := ev.Exception()
	hThread := d.Threads[ev.DwThreadId]

	switch exc.ExceptionRecord.ExceptionCode {
	case winapi.EXCEPTION_ACCESS_VIOLATION:
		if d.Callbacks != nil {
			return d.Callbacks.OnAccessViolation(hThread, &exc.ExceptionRecord)
		}
		return winapi.DBG_EXCEPTION_NOT_HANDLED

	case winapi.EXCEPTION_BREAKPOINT:
		bpAddr := exc.ExceptionRecord.ExceptionAddress
		if _, ok := d.SoftBPs[bpAddr]; ok {
			return d.handleSoftwareBreakpoint(hThread, bpAddr)
		}
		if d.Callbacks != nil {
			d.Callbacks.OnUnsolicitedSoftwareBreakpoint(hThread, bpAddr)
		}
		if !d.InitialBreakpointSeen {
			d.InitialBreakpointSeen = true
			return winapi.DBG_CONTINUE
		}
		return winapi.DBG_EXCEPTION_NOT_HANDLED

	case winapi.EXCEPTION_SINGLE_STEP:
		return d.handleSingleStep(hThread, exc.ExceptionRecord.ExceptionAddress)

	default:
		if exc.DwFirstChance == 0 {
			log.Fatalf("Non-first-chance exception 0x%08X at 0x%p", exc.ExceptionRecord.ExceptionCode, unsafe.Pointer(exc.ExceptionRecord.ExceptionAddress))
			d.Fail(fmt.Errorf("unhandled exception 0x%08X at 0x%X", exc.ExceptionRecord.ExceptionCode, exc.ExceptionRecord.ExceptionAddress))
			return winapi.DBG_EXCEPTION_NOT_HANDLED
		}
		log.Infof("Code 0x%08X at 0x%p", exc.ExceptionRecord.ExceptionCode, unsafe.Pointer(exc.ExceptionRecord.ExceptionAddress))
		return winapi.DBG_EXCEPTION_NOT_HANDLED
	}
}

func (d *DebuggerCore) handleSoftwareBreakpoint(hThread syscall.Handle, bpAddr uintptr) uint32 {
	// Rewind IP by 1
	if d.Is64Bit {
		var c winapi.CONTEXT64
		c.ContextFlags = winapi.CONTEXT_CONTROL_64
		winapi.GetThreadContext64(hThread, &c)
		c.Rip--
		winapi.SetThreadContext64(hThread, &c)
	} else {
		var c winapi.CONTEXT32
		c.ContextFlags = winapi.CONTEXT_CONTROL_32
		winapi.GetThreadContext32(hThread, &c)
		c.Eip--
		winapi.SetThreadContext32(hThread, &c)
	}

	origByte := d.SoftBPs[bpAddr]
	d.WriteByte(bpAddr, origByte)

	action := SbpClearContinue
	if d.Callbacks != nil {
		action = d.Callbacks.OnSoftwareBreakpoint(hThread, bpAddr)
	}

	switch action {
	case SbpClearContinue:
		delete(d.SoftBPs, bpAddr)
	case SbpKeepContinue:
		d.SoftBPReenable = bpAddr
		if d.Is64Bit {
			var c winapi.CONTEXT64
			c.ContextFlags = winapi.CONTEXT_CONTROL_64
			winapi.GetThreadContext64(hThread, &c)
			c.EFlags |= 0x100
			winapi.SetThreadContext64(hThread, &c)
		} else {
			var c winapi.CONTEXT32
			c.ContextFlags = winapi.CONTEXT_CONTROL_32
			winapi.GetThreadContext32(hThread, &c)
			c.EFlags |= 0x100
			winapi.SetThreadContext32(hThread, &c)
		}
	case SbpKeepContinueNoStep:
		d.WriteByte(bpAddr, 0xCC)
	}

	return winapi.DBG_CONTINUE
}

func (d *DebuggerCore) handleSingleStep(hThread syscall.Handle, eip uintptr) uint32 {
	if d.Is64Bit {
		var c winapi.CONTEXT64
		c.ContextFlags = winapi.CONTEXT_CONTROL_64 | winapi.CONTEXT_INTEGER_64 | winapi.CONTEXT_DEBUG_REGISTERS_64
		winapi.GetThreadContext64(hThread, &c)

		// Check if bit 14 (single step execution mode) is 0 and any HWBP is set
		if ((c.Dr6>>14)&1) == 0 && (d.HW[0].IsSet() || d.HW[1].IsSet() || d.HW[2].IsSet() || d.HW[3].IsSet()) {
			var bp *Breakpoint
			switch c.Dr6 & 0xF {
			case 1:
				copyBP := d.HW[0]
				bp = &copyBP
			case 2:
				copyBP := d.HW[1]
				bp = &copyBP
			case 4:
				copyBP := d.HW[2]
				bp = &copyBP
			case 8:
				copyBP := d.HW[3]
				bp = &copyBP
			default:
				log.Fatalf("Unknown hwbp at 0x%X (Dr6: 0x%08X)", eip, c.Dr6)
				return winapi.DBG_EXCEPTION_NOT_HANDLED
			}

			if d.Callbacks != nil {
				d.Callbacks.OnHardwareBreakpoint(hThread, bp.Address, nil, &c)
			}

			if bp.BType == HWExecute && d.DisableBreakpoint(uintptr(c.Rip)) {
				d.UpdateDR(hThread)
				winapi.GetThreadContext64(hThread, &c)
				c.ContextFlags = winapi.CONTEXT_CONTROL_64
				c.EFlags |= 0x100
				winapi.SetThreadContext64(hThread, &c)
			}
			return winapi.DBG_CONTINUE
		}
	} else {
		var c winapi.CONTEXT32
		c.ContextFlags = winapi.CONTEXT_CONTROL_32 | winapi.CONTEXT_INTEGER_32 | winapi.CONTEXT_DEBUG_REGISTERS_32
		winapi.GetThreadContext32(hThread, &c)

		if ((c.Dr6>>14)&1) == 0 && (d.HW[0].IsSet() || d.HW[1].IsSet() || d.HW[2].IsSet() || d.HW[3].IsSet()) {
			var bp *Breakpoint
			switch c.Dr6 & 0xF {
			case 1:
				copyBP := d.HW[0]
				bp = &copyBP
			case 2:
				copyBP := d.HW[1]
				bp = &copyBP
			case 4:
				copyBP := d.HW[2]
				bp = &copyBP
			case 8:
				copyBP := d.HW[3]
				bp = &copyBP
			default:
				log.Fatalf("Unknown hwbp at 0x%X (Dr6: 0x%08X)", eip, c.Dr6)
				return winapi.DBG_EXCEPTION_NOT_HANDLED
			}

			if d.Callbacks != nil {
				d.Callbacks.OnHardwareBreakpoint(hThread, bp.Address, &c, nil)
			}

			if bp.BType == HWExecute && d.DisableBreakpoint(uintptr(c.Eip)) {
				d.UpdateDR(hThread)
				winapi.GetThreadContext32(hThread, &c)
				c.ContextFlags = winapi.CONTEXT_CONTROL_32
				c.EFlags |= 0x100
				winapi.SetThreadContext32(hThread, &c)
			}
			return winapi.DBG_CONTINUE
		}
	}

	if d.SoftBPReenable != 0 {
		d.WriteByte(d.SoftBPReenable, 0xCC)
		d.SoftBPReenable = 0
		return winapi.DBG_CONTINUE
	}

	if d.Callbacks != nil {
		return d.Callbacks.OnSinglestep(eip)
	}

	d.EnableBreakpoints()
	return winapi.DBG_CONTINUE
}

func (d *DebuggerCore) Fail(err error) {
	if d.Err == nil {
		d.Err = err
		log.Fatalf("%v", err)
	}
	d.ShouldTerminate = true
}

func (d *DebuggerCore) WriteMemory(addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	old, err := winapi.VirtualProtectEx(d.ProcessInfo.Process, addr, uintptr(len(data)), winapi.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return err
	}
	_, writeErr := winapi.WriteProcessMemory(d.ProcessInfo.Process, addr, data)
	_, protectErr := winapi.VirtualProtectEx(d.ProcessInfo.Process, addr, uintptr(len(data)), old)
	flushErr := winapi.FlushInstructionCache(d.ProcessInfo.Process, addr, uintptr(len(data)))
	if writeErr != nil {
		return writeErr
	}
	if protectErr != nil {
		return protectErr
	}
	return flushErr
}

func (d *DebuggerCore) cleanup() {
	if d.ProcessInfo.Process != 0 {
		if d.AttachPID == 0 {
			winapi.TerminateProcess(d.ProcessInfo.Process, 0)
		} else {
			winapi.DebugActiveProcessStop(d.AttachPID)
		}
	}
	closed := make(map[syscall.Handle]bool)
	for _, thread := range d.Threads {
		if thread != 0 && !closed[thread] {
			winapi.CloseHandle(thread)
			closed[thread] = true
		}
	}
	if d.ProcessInfo.Thread != 0 && !closed[d.ProcessInfo.Thread] {
		winapi.CloseHandle(d.ProcessInfo.Thread)
	}
	if d.ProcessInfo.Process != 0 {
		winapi.CloseHandle(d.ProcessInfo.Process)
	}
	if d.DLLExecutable != "" {
		os.Remove(d.DLLExecutable)
	}
}
