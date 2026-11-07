package themida

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"unmida/pkg/debugger"
	"unmida/pkg/dumper"
	"unmida/pkg/log"
	"unmida/pkg/pe"
	"unmida/pkg/utils"
	"unmida/pkg/winapi"
)

type EFLRecord struct {
	Address  uintptr
	Original []byte
}

type TMDebugger32 struct {
	*TMCommon
	Wow64, Compressed, BaseAccessed, NewVer, AncientVer, ThemidaV2BySections                       bool
	BaseAccessCount, AllocMemCounter                                                               int
	Base1, RepEIP, NtQIP                                                                           uintptr
	CloseHandleAPI, AllocMemAPI, AllocHeapAPI, KiFastSystemCall, NtSIT, NtQIP64, VirtualProtectAPI uintptr
	CorExeMain, CmpImgBase, MagicJump, MagicJumpV1                                                 uintptr
	IJumper, MJ1, MJ2, MJ3, MJ4                                                                    uintptr
	EFLs                                                                                           [3]EFLRecord
	GuardStart, GuardEnd                                                                           uintptr
	GuardProtection                                                                                uint32
	GuardStepping                                                                                  bool
	TLSAddressesOfCallbacks                                                                        uintptr
	TLSCounter, TLSTotal                                                                           int
}

func NewDebugger32(executable, parameters string, createData bool) (*TMDebugger32, error) {
	tm := &TMDebugger32{TMCommon: &TMCommon{CreateDataSections: createData}}
	tm.DebuggerCore = debugger.NewDebuggerCore(executable, parameters, tm)
	return tm, nil
}

func (tm *TMDebugger32) read32(addr uintptr) uint32 {
	var b [4]byte
	if !tm.RPM(addr, b[:]) {
		tm.Fail(fmt.Errorf("reading DWORD at 0x%X failed", addr))
		return 0
	}
	return binary.LittleEndian.Uint32(b[:])
}

func (tm *TMDebugger32) api(module, name string) uintptr {
	h, err := winapi.GetModuleHandle(module)
	if err != nil {
		h, err = winapi.LoadLibrary(module)
	}
	if err != nil {
		tm.Fail(err)
		return 0
	}
	address, err := winapi.GetProcAddress(h, name)
	if err != nil {
		tm.Fail(fmt.Errorf("%s!%s: %w", module, name, err))
	}
	return address
}

func (tm *TMDebugger32) bp(addr uintptr, kind debugger.HWBPType) {
	if addr == 0 {
		tm.Fail(fmt.Errorf("cannot set breakpoint at zero"))
		return
	}
	if err := tm.SetBreakpoint(addr, kind, true); err != nil {
		tm.Fail(err)
	}
}

func (tm *TMDebugger32) write(addr uintptr, data []byte) {
	if err := tm.WriteMemory(addr, data); err != nil {
		tm.Fail(fmt.Errorf("patching 0x%X: %w", addr, err))
	}
}

func (tm *TMDebugger32) OnDebugStart(hFile, hThread syscall.Handle) {
	if len(filepath.Base(tm.Executable)) >= 50 {
		log.Infof("Long filenames crash some Themida versions; recommend fewer than 50 characters")
	}
	tm.CloseHandleAPI = tm.api("kernel32.dll", "CloseHandle")
	tm.bp(tm.CloseHandleAPI, debugger.HWExecute)
	executable, err := os.Executable()
	if err != nil {
		tm.Fail(err)
		return
	}
	injector := filepath.Join(filepath.Dir(executable), "InjectorCLIx86.exe")
	if _, err := os.Stat(injector); err == nil {
		cmd := exec.Command(injector, fmt.Sprintf("pid:%d", tm.ProcessInfo.ProcessId), filepath.Join(filepath.Dir(executable), "HookLibraryx86.dll"), "nowait")
		cmd.Dir = filepath.Dir(executable)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err != nil {
			tm.Fail(err)
			return
		}
		go cmd.Wait()
		log.Goodf("Applying ScyllaHide")
	} else {
		tm.NtSIT = tm.api("ntdll.dll", "ZwSetInformationThread")
		tm.bp(tm.NtSIT, debugger.HWExecute)
		tm.Wow64, err = winapi.IsWow64Process(tm.ProcessInfo.Process)
		if err != nil {
			tm.Fail(err)
			return
		}
		if tm.Wow64 {
			tm.NtQIP64 = tm.api("ntdll.dll", "ZwQueryInformationProcess")
			tm.bp(tm.NtQIP64, debugger.HWExecute)
		} else {
			tm.KiFastSystemCall = tm.api("ntdll.dll", "KiFastSystemCall")
			if err := tm.SetSoftBP(tm.KiFastSystemCall); err != nil {
				tm.Fail(err)
				return
			}
			tm.NtQIP = uintptr(tm.read32(tm.api("ntdll.dll", "ZwQueryInformationProcess") + 1))
		}
	}
	tm.VirtualProtectAPI = tm.api("kernel32.dll", "VirtualProtect")
	tm.SleepAPI = tm.api("kernel32.dll", "Sleep")
	tm.LstrlenAPI = tm.api("kernel32.dll", "lstrlenA")
	data, err := os.ReadFile(tm.Executable)
	if err != nil {
		tm.Fail(err)
		return
	}
	header, err := pe.ParsePEHeader(data)
	if err != nil {
		tm.Fail(err)
		return
	}
	if err = tm.InitPEDetails(header); err != nil {
		tm.Fail(err)
		return
	}
	n := len(tm.PESections)
	if n >= 2 {
		tm.ThemidaV2BySections = tm.PESections[n-1].VirtualSize == 0x1000 && tm.PESections[n-1].SizeOfRawData == 0x1000 && tm.PESections[n-2].VirtualSize == 0x1000
	}
	tm.BaseOfData = uintptr(header.BaseOfData)
	tm.Compressed = tm.PESections[0].VirtualSize != tm.PESections[0].SizeOfRawData
	tm.Base1 = uintptr(tm.PESections[0].VirtualSize)
	if n > 2 {
		nameAddr := tm.ImageBase + uintptr(header.LFANew) + 24 + uintptr(header.FileHeader.SizeOfOptionalHeader) + 2*40 + 1
		tm.write(nameAddr, []byte{'p'})
	}
	tls := header.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_TLS]
	if tls.Size >= 24 {
		var b [24]byte
		if tm.RPM(tm.ImageBase+uintptr(tls.VirtualAddress), b[:]) {
			index := binary.LittleEndian.Uint32(b[8:12])
			callbacks := binary.LittleEndian.Uint32(b[12:16])
			distance := int64(callbacks) - int64(index)
			if distance > 0 && distance <= 16 {
				tm.TLSTotal = int(distance / 4)
				tm.TLSAddressesOfCallbacks = uintptr(callbacks)
				log.Infof("Expecting up to %d TLS entries", tm.TLSTotal)
			}
		}
	}
	tm.AllocMemAPI = tm.api("ntdll.dll", "ZwAllocateVirtualMemory")
	tm.AllocHeapAPI = tm.api("ntdll.dll", "RtlAllocateHeap")
}

func (tm *TMDebugger32) SelectThemidaSection(ip uintptr) error {
	for _, section := range tm.PESections {
		region := utils.MemoryRegion{Address: tm.ImageBase + uintptr(section.VirtualAddress), Size: uintptr(section.VirtualSize)}
		if region.Contains(ip) {
			tm.TMSectR = region
			tm.TMSect = make([]byte, region.Size)
			if !tm.RPM(region.Address, tm.TMSect) {
				return fmt.Errorf("reading Themida section failed")
			}
			tm.AncientVer = string(section.Name[:]) == "Themida "
			log.Infof("TMSect: 0x%X (%d bytes), ancient: %t", region.Address, region.Size, tm.AncientVer)
			return nil
		}
	}
	return fmt.Errorf("no Themida section for 0x%X", ip)
}

func (tm *TMDebugger32) finderCheck(c *winapi.CONTEXT32) bool {
	var b [2]byte
	if tm.RPM(uintptr(c.Eip), b[:]) && b == [2]byte{0xF3, 0xA4} {
		return true
	}
	target := uint32(tm.ImageBase + 0x1000 + tm.Base1 - 4)
	return c.Eax == target || c.Ebx == target || c.Ecx == target || c.Edx == target || c.Esi == target || c.Edi == target
}

func (tm *TMDebugger32) OnHardwareBreakpoint(hThread syscall.Handle, bpa uintptr, c *winapi.CONTEXT32, unused *winapi.CONTEXT64) {
	ip := uintptr(c.Eip)
	switch ip {
	case tm.CloseHandleAPI:
		ret := uintptr(tm.read32(uintptr(c.Esp)))
		if ret < tm.ImageBoundary {
			tm.ResetBreakpoint(ip)
			if tm.Compressed {
				tm.bp(tm.ImageBase+0x1000, debugger.HWAccess)
			} else {
				tm.bp(tm.AllocMemAPI, debugger.HWExecute)
			}
		}
	case tm.AllocMemAPI:
		frame := tm.read32(uintptr(c.Ebp))
		distance := int64(frame) - int64(c.Ebp)
		var ret uintptr
		if distance > -0x40 && distance < 0x40 {
			ret = uintptr(tm.read32(uintptr(frame) + 4))
		} else {
			ret = uintptr(tm.read32(uintptr(c.Ebp) + 4))
		}
		log.Infof("AllocMem called from 0x%X", ret)
		if ret > tm.ImageBase && ret < tm.ImageBoundary {
			tm.AllocMemCounter++
			required := 5
			if tm.Compressed {
				required = 4
			}
			if tm.AllocMemCounter == required {
				tm.ResetBreakpoint(tm.AllocMemAPI)
				if tm.ThemidaV3 {
					tm.InstallCodeSectionGuard(winapi.PAGE_NOACCESS)
				} else {
					if err := tm.SelectThemidaSection(ret); err != nil {
						tm.Fail(err)
						return
					}
					tm.TMIATFix2()
				}
			}
		}
	case tm.CmpImgBase:
		tm.ResetBreakpoint(ip)
		tm.MagicJump = tm.find("4B0F84????0000", ip)
		if tm.MagicJump == 0 {
			tm.Fail(fmt.Errorf("magic jumps not found"))
			return
		}
		tm.bp(tm.MagicJump, debugger.HWExecute)
	case tm.MagicJump:
		tm.ResetBreakpoint(ip)
		tm.TMIATFix4()
	case tm.MJ1:
		tm.ResetBreakpoint(ip)
		tm.TMIATFix5()
	case tm.MagicJumpV1:
		tm.ResetBreakpoint(ip)
		tm.TMIATFixV1(ip)
	case tm.AllocHeapAPI:
		log.Infof("Special IAT fix unavailable; continuing with code section tracing")
		tm.ResetBreakpoint(ip)
		tm.SoftBPClear()
		tm.InstallCodeSectionGuard(winapi.PAGE_NOACCESS)
	case tm.VirtualProtectAPI:
		tm.InstallCodeSectionGuard(winapi.PAGE_NOACCESS)
	case tm.NtSIT:
		ret := tm.read32(uintptr(c.Esp))
		if uintptr(ret) < tm.ImageBoundary && tm.read32(uintptr(c.Esp)+8) == 17 {
			c.Esp += 20
			c.Eip = ret
			c.Eax = winapi.STATUS_SUCCESS
			c.ContextFlags = winapi.CONTEXT_CONTROL_32 | winapi.CONTEXT_INTEGER_32
			if err := winapi.SetThreadContext32(hThread, c); err != nil {
				tm.Fail(err)
			}
			log.Goodf("Ignoring NtSetInformationThread(ThreadHideFromDebugger)")
		}
	case tm.NtQIP64:
		ret := tm.read32(uintptr(c.Esp))
		infoClass := tm.read32(uintptr(c.Esp) + 8)
		if infoClass == 7 || infoClass == 30 {
			result := uintptr(tm.read32(uintptr(c.Esp) + 12))
			tm.write(result, make([]byte, 4))
			c.Esp += 24
			c.Eip = ret
			c.Eax = winapi.STATUS_SUCCESS
			if infoClass == 30 {
				c.Eax = winapi.STATUS_PORT_NOT_SET
			}
			c.ContextFlags = winapi.CONTEXT_CONTROL_32 | winapi.CONTEXT_INTEGER_32
			if err := winapi.SetThreadContext32(hThread, c); err != nil {
				tm.Fail(err)
			}
			log.Goodf("Faking process debug information (%d)", infoClass)
		}
	default:
		if bpa != tm.ImageBase+0x1000 {
			log.Infof("Accessed 0x%X from 0x%X", bpa, ip)
			return
		}
		tm.BaseAccessCount++
		if !tm.BaseAccessed {
			tm.ResetBreakpoint(bpa)
			tm.bp(bpa, debugger.HWWrite)
			tm.BaseAccessed = true
		} else if tm.finderCheck(c) {
			tm.ResetBreakpoint(bpa)
			tm.bp(tm.AllocMemAPI, debugger.HWExecute)
			tm.RepEIP = ip
		} else if tm.BaseAccessCount == 3 && !tm.ThemidaV2BySections {
			tm.ThemidaV3 = true
			log.Infof("Assuming Themida v3")
			if err := tm.SelectThemidaSection(ip); err != nil {
				tm.Fail(err)
				return
			}
			tm.ResetBreakpoint(bpa)
			tm.bp(tm.AllocMemAPI, debugger.HWExecute)
		}
	}
}

func (tm *TMDebugger32) InstallCodeSectionGuard(protection uint32) {
	tm.GuardStart = tm.ImageBase + uintptr(tm.PESections[0].VirtualAddress)
	tm.GuardEnd = tm.ImageBase + tm.BaseOfData
	tm.GuardProtection = protection
	if tm.GuardEnd <= tm.GuardStart {
		tm.Fail(fmt.Errorf("invalid code section boundary"))
		return
	}
	if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, protection); err != nil {
		tm.Fail(err)
		return
	}
	if !tm.ThemidaV3 && !tm.IsHWBreakpoint(tm.VirtualProtectAPI) {
		tm.bp(tm.VirtualProtectAPI, debugger.HWExecute)
	}
}

func (tm *TMDebugger32) OnSinglestep(bpa uintptr) uint32 {
	if tm.GuardStepping {
		if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, tm.GuardProtection); err != nil {
			tm.Fail(err)
		}
		tm.GuardStepping = false
	}
	tm.EnableBreakpoints()
	return winapi.DBG_CONTINUE
}

func (tm *TMDebugger32) OnAccessViolation(hThread syscall.Handle, exc *winapi.EXCEPTION_RECORD) uint32 {
	address := exc.ExceptionInformation[1]
	if tm.GuardStart == 0 || address < tm.GuardStart || address >= tm.GuardEnd {
		return winapi.DBG_EXCEPTION_NOT_HANDLED
	}
	if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, winapi.PAGE_EXECUTE_READWRITE); err != nil {
		tm.Fail(err)
		return winapi.DBG_EXCEPTION_NOT_HANDLED
	}
	var c winapi.CONTEXT32
	c.ContextFlags = winapi.CONTEXT_CONTROL_32
	if err := winapi.GetThreadContext32(hThread, &c); err != nil {
		tm.Fail(err)
		return winapi.DBG_EXCEPTION_NOT_HANDLED
	}
	if exc.ExceptionAddress > tm.GuardEnd {
		tm.GuardAddrs = append(tm.GuardAddrs, address)
		tm.GuardStepping = true
		c.EFlags |= 0x100
		if err := winapi.SetThreadContext32(hThread, &c); err != nil {
			tm.Fail(err)
		}
		return winapi.DBG_CONTINUE
	}
	if tm.TLSTotal > 0 && tm.TLSCounter < tm.TLSTotal {
		ret := uintptr(tm.read32(uintptr(c.Esp)))
		args := [3]uint32{tm.read32(uintptr(c.Esp) + 4), tm.read32(uintptr(c.Esp) + 8), tm.read32(uintptr(c.Esp) + 12)}
		if tm.TMSectR.Contains(ret) && !tm.IsTMExceptionHandler(ret) && args[0]&0xFFF == 0 && args[1] <= 3 {
			tm.TLSCounter++
			log.Goodf("TLS %d: 0x%X", tm.TLSCounter, exc.ExceptionAddress)
			c.Eip = uint32(ret)
			c.Esp += 16
			if err := winapi.SetThreadContext32(hThread, &c); err != nil {
				tm.Fail(err)
			}
			tm.InstallCodeSectionGuard(tm.GuardProtection)
			return winapi.DBG_CONTINUE
		}
	}
	oep := exc.ExceptionAddress
	oep = tm.RestoreStolenOEPForMSVC6(hThread, oep)
	if tm.IsDLL && tm.MajorLinkerVersion == 9 {
		oep = tm.RestoreStolenOEPForMSVC9DLL(oep)
	}
	tm.CheckVirtualizedOEP(oep)
	if !tm.AncientVer {
		ret := uintptr(tm.read32(uintptr(c.Esp)))
		if tm.TMSectR.Contains(ret) && !tm.IsTMExceptionHandler(ret) {
			oep = tm.TryFindCorrectOEP(oep)
		}
	}
	if tm.Err == nil {
		tm.FinishUnpacking(oep)
	}
	return winapi.DBG_CONTINUE
}

func (tm *TMDebugger32) OnDLLLoad(name string, base uintptr) {
	if !strings.EqualFold(filepath.Base(name), "mscoree.dll") {
		return
	}
	h, err := winapi.LoadLibrary("mscoree.dll")
	if err != nil {
		tm.Fail(err)
		return
	}
	defer winapi.FreeLibrary(h)
	if uintptr(h) != base {
		tm.Fail(fmt.Errorf("mscoree.dll loaded at a different base than target"))
		return
	}
	tm.CorExeMain, err = winapi.GetProcAddress(h, "_CorExeMain")
	if err == nil {
		err = tm.SetSoftBP(tm.CorExeMain)
	}
	if err != nil {
		tm.Fail(err)
	}
}

func (tm *TMDebugger32) OnUnsolicitedSoftwareBreakpoint(hThread syscall.Handle, bpa uintptr) {
	log.Infof("Unsolicited breakpoint at 0x%X", bpa)
}

func (tm *TMDebugger32) OnSoftwareBreakpoint(hThread syscall.Handle, bpa uintptr) debugger.SoftBPAction {
	var c winapi.CONTEXT32
	c.ContextFlags = winapi.CONTEXT_FULL_32
	if err := winapi.GetThreadContext32(hThread, &c); err != nil {
		tm.Fail(err)
		return debugger.SbpClearContinue
	}
	if !tm.Wow64 && bpa == tm.KiFastSystemCall {
		infoClass := tm.read32(uintptr(c.Esp) + 12)
		if uintptr(c.Eax) == tm.NtQIP && (infoClass == 7 || infoClass == 30) {
			ret := tm.read32(uintptr(c.Esp))
			result := uintptr(tm.read32(uintptr(c.Esp) + 16))
			tm.write(result, make([]byte, 4))
			c.Esp += 4
			c.Eip = ret
			c.Eax = winapi.STATUS_SUCCESS
			if infoClass == 30 {
				c.Eax = winapi.STATUS_PORT_NOT_SET
			}
		} else {
			c.Edx = c.Esp
			c.Eip = uint32(tm.KiFastSystemCall + 2)
		}
		if err := winapi.SetThreadContext32(hThread, &c); err != nil {
			tm.Fail(err)
		}
		return debugger.SbpKeepContinueNoStep
	}
	if bpa == tm.CorExeMain {
		out := dumper.ChangeFileExt(tm.Executable, "U"+filepath.Ext(tm.Executable))
		dotnet := dumper.NewDumperDotnet(tm.ProcessInfo.Process, tm.ImageBase)
		if err := dotnet.DumpToFile(out); err != nil {
			tm.Fail(err)
		} else {
			tm.Succeeded = true
			tm.ShouldTerminate = true
			tm.HideThreadEnd = true
			log.Goodf(".NET process dumped to %s", dotnet.OutputFile)
		}
		return debugger.SbpClearContinue
	}
	if !tm.NewVer {
		bases := tm.moduleBases()
		if c.Eax != bases[0] && c.Eax != bases[1] && c.Eax != bases[2] {
			if !tm.IsHWBreakpoint(tm.AllocHeapAPI) {
				tm.bp(tm.AllocHeapAPI, debugger.HWExecute)
			}
			return debugger.SbpKeepContinue
		}
		tm.SoftBPClear()
		tm.installOldIATPatch(uintptr(c.Eip), bases)
	} else {
		for i := range tm.EFLs {
			if tm.EFLs[i].Address == 0 {
				if tm.InstallEFLPatch(bpa, &c, &tm.EFLs[i]) {
					return debugger.SbpClearContinue
				}
				break
			}
		}
		tm.SoftBPClear()
	}
	protection := uint32(winapi.PAGE_READONLY)
	if tm.AncientVer {
		protection = winapi.PAGE_NOACCESS
	}
	tm.InstallCodeSectionGuard(protection)
	return debugger.SbpClearContinue
}
