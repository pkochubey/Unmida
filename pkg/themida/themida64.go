package themida

import (
	"bytes"
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

type TMDebugger64 struct {
	*TMCommon

	CloseHandleAPI  uintptr
	VirtualAllocAPI uintptr
	CorExeMain      uintptr

	GuardStart    uintptr
	GuardEnd      uintptr
	GuardStepping bool
	TMGuard       bool
	TraceMSVCOEP  bool

	MSVCInitCookie uintptr
	MSVCOEP        uintptr

	TLSCounter int
	TLSTotal   int
}

func NewDebugger64(executable, parameters string, createData bool) (*TMDebugger64, error) {
	appDir := filepath.Dir(mustExecutablePath())
	for _, name := range []string{"InjectorCLIx64.exe", "HookLibraryx64.dll", "scylla_hide.ini"} {
		if _, err := os.Stat(filepath.Join(appDir, name)); err != nil {
			return nil, fmt.Errorf("64-bit unpacking requires %s next to Unmida: %w", name, err)
		}
	}
	tm := &TMDebugger64{
		TMCommon: &TMCommon{
			CreateDataSections: createData,
			ThemidaV3:          true,
		},
	}
	tm.TMCommon.DebuggerCore = debugger.NewDebuggerCore(executable, parameters, tm)
	tm.Is64Bit = true
	return tm, nil
}

func (tm *TMDebugger64) InImageBounds(addr uintptr) bool {
	return addr >= tm.ImageBase && addr < tm.ImageBoundary
}

func (tm *TMDebugger64) SelectThemidaSection(addr uintptr) error {
	for _, sec := range tm.PESections {
		secStart := tm.ImageBase + uintptr(sec.VirtualAddress)
		secEnd := secStart + uintptr(sec.VirtualSize)
		if addr >= secStart && addr < secEnd {
			tm.TMSectR = utils.MemoryRegion{
				Address: secStart,
				Size:    uintptr(sec.VirtualSize),
			}
			tm.TMSect = make([]byte, sec.VirtualSize)
			if !tm.RPM(secStart, tm.TMSect) {
				tm.TMSect = nil
				return fmt.Errorf("RPM for Themida section failed")
			}
			log.Infof("TMSect: 0x%X (%d bytes)", tm.TMSectR.Address, tm.TMSectR.Size)
			return nil
		}
	}
	return fmt.Errorf("unable to find section for 0x%X", addr)
}

func (tm *TMDebugger64) OnDebugStart(hFile syscall.Handle, hThread syscall.Handle) {
	appDir := filepath.Dir(mustExecutablePath())
	injectorPath := filepath.Join(appDir, "InjectorCLIx64.exe")
	hookLibPath := filepath.Join(appDir, "HookLibraryx64.dll")

	if _, err := os.Stat(injectorPath); err == nil {
		ts, _ := utils.GetPETimestamp(injectorPath)
		if ts < 0x6484FEF9 {
			tm.Fail(fmt.Errorf("InjectorCLIx64 is older than the required fix"))
			return
		}
		log.Goodf("Applying ScyllaHide")
		cmd := exec.Command(injectorPath, fmt.Sprintf("pid:%d", tm.ProcessInfo.ProcessId), hookLibPath, "nowait")
		cmd.Dir = appDir
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err != nil {
			tm.Fail(err)
			return
		}
		go cmd.Wait()
	} else {
		tm.Fail(fmt.Errorf("ScyllaHide is mandatory for Themida64 (InjectorCLIx64.exe not found)"))
		return
	}

	k32, _ := winapi.GetModuleHandle("kernel32.dll")
	tm.VirtualAllocAPI, _ = winapi.GetProcAddress(k32, "VirtualAlloc")
	tm.SleepAPI, _ = winapi.GetProcAddress(k32, "Sleep")
	tm.LstrlenAPI, _ = winapi.GetProcAddress(k32, "lstrlenA")

	tm.tmInit()
}

func (tm *TMDebugger64) tmInit() {
	data, err := os.ReadFile(tm.Executable)
	if err != nil {
		tm.Fail(fmt.Errorf("Reading executable failed: %v", err))
		return
	}
	peHeader, err := pe.ParsePEHeader(data)
	if err != nil {
		tm.Fail(fmt.Errorf("Parsing PE header failed: %v", err))
		return
	}

	if err := tm.InitPEDetails(peHeader); err != nil {
		tm.Fail(fmt.Errorf("%v", err))
		return
	}

	firstSec := peHeader.Sections[0]
	tm.BaseOfData = uintptr(firstSec.Header.VirtualAddress + peHeader.SizeOfCode)

	// PE Header Antidump fix
	if len(peHeader.Sections) > 2 && peHeader.Sections[2].Header.Name[1] == 'i' {
		sec2NameOff := int(peHeader.LFANew) + 24 + int(peHeader.FileHeader.SizeOfOptionalHeader) + 2*40 + 1
		targetAddr := tm.ImageBase + uintptr(sec2NameOff)
		winapi.VirtualProtectEx(tm.ProcessInfo.Process, targetAddr, 1, winapi.PAGE_READWRITE)
		tm.WriteByte(targetAddr, 'p')
	}

	secName := firstSec.Header.SectionName()
	if secName == ".text" {
		log.Goodf("Text section not encrypted/compressed, installing page guard")
		tm.InstallCodeSectionGuard()
	} else {
		k32, _ := winapi.GetModuleHandle("kernel32.dll")
		tm.CloseHandleAPI, _ = winapi.GetProcAddress(k32, "CloseHandle")
		if err := tm.SetBreakpoint(tm.CloseHandleAPI, debugger.HWExecute, true); err != nil {
			tm.Fail(err)
		}
	}

	tlsDir := peHeader.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_TLS]
	if tlsDir.Size > 0 {
		var tlsBuf [40]byte
		if tm.RPM(tm.ImageBase+uintptr(tlsDir.VirtualAddress), tlsBuf[:]) {
			addrOfCallbacks := uintptr(binary.LittleEndian.Uint64(tlsBuf[24:32]))
			tlsDist := int64(tm.ImageBase+uintptr(tlsDir.VirtualAddress)) - int64(addrOfCallbacks)
			if tlsDist > 0 && tlsDist <= int64(8*(4+1)) {
				tm.TLSTotal = int(tlsDist/8) - 1
				log.Infof("[MSVC] Expecting %d TLS entries", tm.TLSTotal)
			}
		}
	}
}

func (tm *TMDebugger64) InstallCodeSectionGuard() {
	tm.GuardStart = tm.ImageBase + uintptr(tm.PESections[0].VirtualAddress)
	tm.GuardEnd = tm.ImageBase + tm.BaseOfData
	if tm.GuardEnd <= tm.GuardStart {
		tm.Fail(fmt.Errorf("invalid 64-bit code boundary"))
		return
	}
	if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, winapi.PAGE_NOACCESS); err != nil {
		tm.Fail(err)
	}
}

func (tm *TMDebugger64) IsGuardedAddress(addr uintptr) bool {
	if tm.GuardStart == 0 {
		return false
	}
	return addr >= tm.GuardStart && addr < tm.GuardEnd
}

func (tm *TMDebugger64) OnAccessViolation(hThread syscall.Handle, excRec *winapi.EXCEPTION_RECORD) uint32 {
	faultAddr := excRec.ExceptionInformation[1]
	if tm.IsGuardedAddress(faultAddr) {
		return tm.ProcessGuardedAccess(hThread, excRec)
	}
	return winapi.DBG_EXCEPTION_NOT_HANDLED
}

func (tm *TMDebugger64) ProcessGuardedAccess(hThread syscall.Handle, excRec *winapi.EXCEPTION_RECORD) uint32 {
	flag := byte(excRec.ExceptionInformation[0])
	addr := excRec.ExceptionInformation[1]
	pc := excRec.ExceptionAddress

	log.Infof("[Guard] %s 0x%X", utils.AccessViolationFlagToStr(flag), addr)

	if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, winapi.PAGE_EXECUTE_READWRITE); err != nil {
		tm.Fail(err)
		return winapi.DBG_EXCEPTION_NOT_HANDLED
	}

	if tm.TMGuard {
		tm.TMGuard = false
		tm.InstallCodeSectionGuard()
	} else if !tm.InImageBounds(pc) {
		tm.GuardStepping = true
	} else if pc > tm.GuardEnd {
		if tm.TMSectR.Address == 0 {
			if err := tm.SelectThemidaSection(pc); err != nil {
				tm.Fail(err)
				return winapi.DBG_EXCEPTION_NOT_HANDLED
			}
		}
		tm.GuardAddrs = append(tm.GuardAddrs, addr)
		tm.GuardStepping = true
	} else if flag == 8 && tm.TLSTotal > 0 && tm.TLSCounter < tm.TLSTotal {
		tm.TLSCounter++
		log.Goodf("TLS %d: 0x%08X", tm.TLSCounter, pc)
		tm.GuardStart = tm.TMSectR.Address
		tm.GuardEnd = tm.ImageBoundary
		tm.TMGuard = true
		if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, winapi.PAGE_READWRITE); err != nil {
			tm.Fail(err)
			return winapi.DBG_EXCEPTION_NOT_HANDLED
		}
	} else if tm.TraceMSVCOEP {
		tm.WriteMSVCOEP(pc)
		if tm.Err == nil {
			tm.FinishUnpacking(tm.MSVCOEP)
		}
	} else {
		oep := pc
		tm.CheckVirtualizedOEP(oep)

		var c winapi.CONTEXT64
		c.ContextFlags = winapi.CONTEXT_CONTROL_64
		if err := winapi.GetThreadContext64(hThread, &c); err == nil {
			var retBuf [8]byte
			tm.RPM(uintptr(c.Rsp), retBuf[:])
			retAddr := uintptr(binary.LittleEndian.Uint64(retBuf[:]))

			if tm.TMSectR.Contains(retAddr) {
				log.Infof("Return address points into Themida section: 0x%09X", retAddr)
				oep = tm.TryFindCorrectOEP(oep)

				if tm.TraceMSVCOEP {
					tm.MSVCOEP = oep
					c.Rip = uint64(retAddr)
					c.Rsp += 8
					winapi.SetThreadContext64(hThread, &c)
					tm.InstallCodeSectionGuard()
					return winapi.DBG_CONTINUE
				}
			} else {
				log.Goodf("OEP: 0x%08X", oep)
			}
		} else {
			tm.Fail(fmt.Errorf("GetThreadContext64 failed for further OEP check: %v", err))
		}

		if tm.Err == nil {
			tm.FinishUnpacking(oep)
		}
	}

	if tm.GuardStepping {
		var c winapi.CONTEXT64
		c.ContextFlags = winapi.CONTEXT_CONTROL_64
		if err := winapi.GetThreadContext64(hThread, &c); err == nil {
			c.EFlags |= 0x100
			winapi.SetThreadContext64(hThread, &c)
		}
	}

	return winapi.DBG_CONTINUE
}

func (tm *TMDebugger64) TryFindCorrectOEP(hitAddr uintptr) uintptr {
	if tm.MajorLinkerVersion != 9 && tm.MajorLinkerVersion != 10 &&
		tm.MajorLinkerVersion != 11 && tm.MajorLinkerVersion != 12 && tm.MajorLinkerVersion != 14 {
		tm.Fail(fmt.Errorf("Don't know what to do about OEP for this compiler. Your target likely won't run."))
		return hitAddr
	}

	textLen := int(tm.BaseOfData - uintptr(tm.PESections[0].VirtualAddress))
	textBuf := make([]byte, textLen)
	textStart := tm.ImageBase + uintptr(tm.PESections[0].VirtualAddress)

	if tm.RPM(textStart, textBuf) {
		scanFor := uint32(hitAddr - textStart)
		for i := 0; i <= textLen-10; i++ {
			if textBuf[i] == 0xE8 && textBuf[i+5] == 0xE9 {
				rel := binary.LittleEndian.Uint32(textBuf[i+1 : i+5])
				if rel+uint32(i)+5 == scanFor {
					oep := textStart + uintptr(i)
					log.Goodf("Found suitable real OEP 0x%09X", oep)
					return oep
				}
			}
		}
	}

	if len(tm.GuardAddrs) >= 2 && tm.GuardAddrs[len(tm.GuardAddrs)-1] == tm.GuardAddrs[len(tm.GuardAddrs)-2]+1 {
		tm.MSVCInitCookie = hitAddr
		tm.TraceMSVCOEP = true
		return tm.GuardAddrs[len(tm.GuardAddrs)-2]
	}

	tm.Fail(fmt.Errorf("real OEP not found"))
	return hitAddr
}

func (tm *TMDebugger64) WriteMSVCOEP(crtStartup uintptr) {
	// sub rsp, 28h
	// call msvcInitCookie
	// add rsp, 28h
	// jmp crtStartup
	subRsp := uint32(0x28EC8348)
	callRel := int32(tm.MSVCInitCookie - (tm.MSVCOEP + 4) - 5)
	addRsp := uint32(0x28C48348)
	jmpRel := int32(crtStartup - (tm.MSVCOEP + 4 + 5 + 4) - 5)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, subRsp)
	buf.WriteByte(0xE8)
	binary.Write(buf, binary.LittleEndian, callRel)
	binary.Write(buf, binary.LittleEndian, addRsp)
	buf.WriteByte(0xE9)
	binary.Write(buf, binary.LittleEndian, jmpRel)

	if err := tm.WriteMemory(tm.MSVCOEP, buf.Bytes()); err != nil {
		tm.Fail(err)
		return
	}

	log.Goodf("Virtualized MSVC9+ OEP restored: 0x%X", tm.MSVCOEP)
}

func (tm *TMDebugger64) FinishUnpacking(oep uintptr) {
	dmp := dumper.NewDumper(tm.ProcessInfo.Process, tm.ProcessInfo.ProcessId, tm.Executable, tm.ImageBase, oep, tm.Is64Bit)

	iat, err := tm.DetermineIATAddress(oep, dmp)
	if err != nil {
		tm.Fail(fmt.Errorf("DetermineIATAddress error: %v", err))
		return
	}
	log.Goodf("IAT: 0x%08X", iat)

	if err := tm.TraceImports(iat, dmp); err != nil {
		tm.Fail(fmt.Errorf("TraceImports error: %v", err))
		return
	}

	dmp.IAT = iat
	peHdr, err := dmp.Process()
	if err != nil {
		tm.Fail(fmt.Errorf("Dumper Process error: %v", err))
		return
	}

	outFN := dumper.ChangeFileExt(tm.Executable, "U"+filepath.Ext(tm.Executable))
	if err := dmp.DumpToFile(outFN, peHdr, tm.IsDLL); err != nil {
		tm.Fail(fmt.Errorf("DumpToFile error: %v", err))
		return
	}

	outFN = dmp.OutputFile
	tm.Succeeded = true
	tm.HideThreadEnd = true
	winapi.TerminateProcess(tm.ProcessInfo.Process, 0)
	tm.ShouldTerminate = true

	log.Goodf("Operation completed successfully. Output saved to: %s", outFN)
}

func (tm *TMDebugger64) OnHardwareBreakpoint(hThread syscall.Handle, bpa uintptr, c32 *winapi.CONTEXT32, c64 *winapi.CONTEXT64) {
	rip := uintptr(c64.Rip)

	if rip == tm.CloseHandleAPI {
		var buf [8]byte
		tm.RPM(uintptr(c64.Rsp), buf[:])
		retAddr := uintptr(binary.LittleEndian.Uint64(buf[:]))
		log.Infof("CloseHandle called from 0x%X", retAddr)

		if tm.InImageBounds(retAddr) {
			tm.ResetBreakpoint(tm.CloseHandleAPI)
			if err := tm.SetBreakpoint(tm.ImageBase+0x1000, debugger.HWWrite, true); err != nil {
				tm.Fail(err)
			}
		}
	} else if rip == tm.VirtualAllocAPI {
		var buf [8]byte
		tm.RPM(uintptr(c64.Rsp), buf[:])
		retAddr := uintptr(binary.LittleEndian.Uint64(buf[:]))
		log.Infof("AllocMem called from 0x%X", retAddr)

		if tm.InImageBounds(retAddr) {
			tm.ResetBreakpoint(tm.VirtualAllocAPI)
			tm.InstallCodeSectionGuard()
		}
	} else if bpa == tm.ImageBase+0x1000 {
		log.Goodf("Wrote to .text base from 0x%X", rip)
		if tm.TMSectR.Address == 0 {
			if err := tm.SelectThemidaSection(rip); err != nil {
				tm.Fail(err)
				return
			}
		}
		tm.ResetBreakpoint(tm.ImageBase + 0x1000)
		if err := tm.SetBreakpoint(tm.VirtualAllocAPI, debugger.HWExecute, true); err != nil {
			tm.Fail(err)
		}
	} else {
		log.Infof("Accessed 0x%X from 0x%X", bpa, rip)
	}
}

func (tm *TMDebugger64) OnSoftwareBreakpoint(hThread syscall.Handle, bpa uintptr) debugger.SoftBPAction {
	if bpa == tm.CorExeMain {
		dDotnet := dumper.NewDumperDotnet(tm.ProcessInfo.Process, tm.ImageBase)
		outFN := dumper.ChangeFileExt(tm.Executable, "U"+filepath.Ext(tm.Executable))
		if err := dDotnet.DumpToFile(outFN); err != nil {
			tm.Fail(err)
			return debugger.SbpClearContinue
		}
		log.Goodf(".NET process dumped to %s", dDotnet.OutputFile)

		tm.Succeeded = true
		tm.HideThreadEnd = true
		winapi.TerminateProcess(tm.ProcessInfo.Process, 0)
		tm.ShouldTerminate = true
		return debugger.SbpClearContinue
	}

	tm.Fail(fmt.Errorf("Unexpected SoftBP at 0x%X", bpa))
	return debugger.SbpClearContinue
}

func (tm *TMDebugger64) OnSinglestep(bpa uintptr) uint32 {
	if tm.GuardStepping {
		if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, winapi.PAGE_NOACCESS); err != nil {
			tm.Fail(err)
		}
		tm.GuardStepping = false
		return winapi.DBG_CONTINUE
	}
	tm.EnableBreakpoints()
	return winapi.DBG_CONTINUE
}

func (tm *TMDebugger64) OnDLLLoad(fileName string, baseAddress uintptr) {
	if strings.Contains(strings.ToLower(fileName), "mscoree.dll") {
		log.Infof("This might be a .NET program - setting _CorExeMain BP")
		hCorEE, err := winapi.LoadLibrary("mscoree.dll")
		if err == nil {
			defer winapi.FreeLibrary(hCorEE)
		}
		if err == nil && uintptr(hCorEE) == baseAddress {
			tm.CorExeMain, err = winapi.GetProcAddress(hCorEE, "_CorExeMain")
			if err == nil {
				err = tm.SetSoftBP(tm.CorExeMain)
			}
			if err != nil {
				tm.Fail(err)
			}
		} else {
			tm.Fail(fmt.Errorf("mscoree.dll was loaded at different base than in target!"))
		}
	}
}

func (tm *TMDebugger64) OnUnsolicitedSoftwareBreakpoint(hThread syscall.Handle, bpa uintptr) {
	log.Infof("Unsolicited int32/int3 at 0x%X", bpa)
}

func mustExecutablePath() string {
	path, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return path
}
