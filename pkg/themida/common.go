package themida

import (
	"encoding/binary"
	"fmt"

	"unmida/pkg/debugger"
	"unmida/pkg/disasm"
	"unmida/pkg/dumper"
	"unmida/pkg/log"
	"unmida/pkg/pe"
	"unmida/pkg/tracer"
	"unmida/pkg/utils"
	"unmida/pkg/winapi"
)

type TMCommon struct {
	*debugger.DebuggerCore

	CreateDataSections bool
	BaseOfData         uintptr
	ImageBoundary      uintptr
	PESections         []pe.ImageSectionHeader
	MajorLinkerVersion byte

	TMSect  []byte
	TMSectR utils.MemoryRegion

	ThemidaV3 bool
	IsVMOEP   bool

	GuardAddrs []uintptr

	TracedAPI    uintptr
	SleepAPI     uintptr
	LstrlenAPI   uintptr
	TraceStartSP uintptr
	TraceInVM    bool
}

func (tm *TMCommon) InitPEDetails(header *pe.PEHeader) error {
	tm.PESections = make([]pe.ImageSectionHeader, len(header.Sections))
	for i, s := range header.Sections {
		tm.PESections[i] = s.Header
	}

	if len(tm.PESections) > 0 {
		firstSecEnd := uint32(tm.PESections[0].VirtualAddress + tm.PESections[0].VirtualSize)
		if header.AddressOfEntryPoint < firstSecEnd {
			return fmt.Errorf("the selected binary does not seem to be packed (entrypoint is in .text section)")
		}
	}

	tm.ImageBoundary = tm.ImageBase + uintptr(header.SizeOfImage)
	log.Infof("Image boundary: 0x%X", tm.ImageBoundary)

	tm.MajorLinkerVersion = header.MajorLinkerVersion
	log.Infof("Image linker: %d.%d", header.MajorLinkerVersion, header.MinorLinkerVersion)
	return nil
}

func (tm *TMCommon) CheckVirtualizedOEP(oep uintptr) {
	var code [5]byte
	if !tm.RPM(oep, code[:]) {
		return
	}
	if code[0] != 0xE9 {
		return
	}
	displ := int32(binary.LittleEndian.Uint32(code[1:5]))
	target := uintptr(int64(oep) + 5 + int64(displ))

	if !tm.TMSectR.Contains(target) {
		return
	}

	tm.IsVMOEP = true
	log.Infof("OEP is virtualized (!): jmp 0x%X", target)
}

func findDelphiCall(codeDump []byte) uint32 {
	counter := 0
	for i := 0; i < len(codeDump)-6; i++ {
		// 0xFF 0x25: jmp dword ptr [...]
		if codeDump[i] == 0xFF && codeDump[i+1] == 0x25 {
			counter++
			if counter == 3 {
				return uint32(i)
			}
		}
	}
	return 0
}

func findGoBuildIdEnd(codeDump []byte) uint32 {
	for i := 0; i < len(codeDump)-2; i++ {
		// 0x20 0xFF: marks end of Go build ID
		if codeDump[i] == 0x20 && codeDump[i+1] == 0xFF {
			return uint32(i + 2)
		}
	}
	return 0
}

func (tm *TMCommon) DetermineIATAddress(oep uintptr, dmp *dumper.Dumper) (uintptr, error) {
	if len(tm.PESections) == 0 {
		return 0, fmt.Errorf("no PE sections found")
	}

	if tm.BaseOfData <= uintptr(tm.PESections[0].VirtualAddress) {
		return 0, fmt.Errorf("invalid BaseOfData")
	}
	dataSectionIndex := -1
	for i, s := range tm.PESections {
		if tm.BaseOfData >= uintptr(s.VirtualAddress) && tm.BaseOfData < uintptr(s.VirtualAddress)+uintptr(s.VirtualSize) {
			dataSectionIndex = i
			break
		}
	}

	if dataSectionIndex < 0 {
		return 0, fmt.Errorf("BaseOfData is outside sections")
	}
	textBase := tm.ImageBase + uintptr(tm.PESections[0].VirtualAddress)
	codeSize := tm.BaseOfData - uintptr(tm.PESections[0].VirtualAddress)
	dataSec := tm.PESections[dataSectionIndex]
	dataSize := uintptr(dataSec.VirtualSize) - (tm.BaseOfData - uintptr(dataSec.VirtualAddress))

	log.Infof("Text base: 0x%08X, code size: 0x%X, data size: 0x%X", textBase, codeSize, dataSize)

	codeDump := make([]byte, codeSize)
	if !tm.RPM(textBase, codeDump) {
		return 0, fmt.Errorf("DetermineIATAddress: RPM code failed")
	}

	numInstr := 0

	var findCallOrJmpPtr func(addr uintptr, ignoreBoundary bool) uintptr
	findCallOrJmpPtr = func(addr uintptr, ignoreBoundary bool) uintptr {
		for (numInstr < 200) || (ignoreBoundary && addr < textBase+codeSize) {
			numInstr++
			relOff := int(addr - textBase)
			if relOff < 0 || relOff >= len(codeDump) {
				return 0
			}

			ins, err := disasm.DecodeInstruction(codeDump[relOff:], tm.Is64Bit, uint64(addr))
			if err != nil || ins == nil {
				addr++
				continue
			}

			// Check call [addr] or jmp [addr] (FF 15 or FF 25)
			if ins.Opcode == 0xFF && (ins.Reg == 2 || ins.Reg == 4) && ins.HasDisplacement && (ins.AbsoluteMemory || ins.RIPRelative) {
				iatPtr := uintptr(uint32(ins.Displacement))
				if ins.RIPRelative {
					// RIP-relative in 64-bit
					iatPtr = uintptr(int64(addr) + int64(ins.Length) + ins.Displacement)
				}
				log.Infof("Found 0x%08X : call/jmp ptr [0x%08X]", ins.VirtualAddr, iatPtr)

				var thePtr uintptr
				var ptrBuf [8]byte
				ptrLen := 4
				if tm.Is64Bit {
					ptrLen = 8
				}
				if !tm.RPM(iatPtr, ptrBuf[:ptrLen]) {
					return iatPtr
				}
				if tm.Is64Bit {
					thePtr = uintptr(binary.LittleEndian.Uint64(ptrBuf[:8]))
				} else {
					thePtr = uintptr(binary.LittleEndian.Uint32(ptrBuf[:4]))
				}
				if thePtr > textBase+codeSize {
					return iatPtr
				}
			}

			// Direct call: E8
			if ins.Opcode == 0xE8 && !ignoreBoundary {
				target := uintptr(ins.AddrValue)
				if target < textBase || target >= textBase+codeSize {
					return 0
				}
				res := findCallOrJmpPtr(target, false)
				if res != 0 {
					return res
				}
			}

			// Return
			if ins.IsRet && !ignoreBoundary {
				return 0
			}

			if ins.Length > 0 {
				addr += uintptr(ins.Length)
			} else {
				addr++
			}
		}
		return 0
	}

	findGoAPICall := func(addr uintptr) uintptr {
		for addr < textBase+codeSize {
			relOff := int(addr - textBase)
			if relOff < 0 || relOff >= len(codeDump) {
				break
			}
			ins, err := disasm.DecodeInstruction(codeDump[relOff:], tm.Is64Bit, uint64(addr))
			if err != nil || ins == nil {
				addr++
				continue
			}

			if tm.Is64Bit {
				// mov rax, [addr] (8B ...) followed by mov [rsp], rax (48 89 04 24)
				if ins.Length == 7 && ins.Opcode == 0x8B && relOff+11 <= len(codeDump) {
					next4 := binary.LittleEndian.Uint32(codeDump[relOff+7 : relOff+11])
					if next4 == 0x24048948 {
						iatPtr := uintptr(int64(addr) + 7 + ins.Displacement)
						var thePtrBuf [8]byte
						if tm.RPM(iatPtr, thePtrBuf[:]) {
							thePtr := uintptr(binary.LittleEndian.Uint64(thePtrBuf[:]))
							if dmp.IsAPIAddress(thePtr) {
								return iatPtr
							}
						}
					}
				}
			} else {
				// mov eax, [addr] (8B ...) followed by mov [esp], eax (89 04 24)
				if ins.Length == 6 && ins.Opcode == 0x8B && relOff+10 <= len(codeDump) {
					next3 := binary.LittleEndian.Uint32(codeDump[relOff+6 : relOff+10])
					if (next3 & 0x00FFFFFF) == 0x00240489 {
						iatPtr := uintptr(uint32(ins.Displacement))
						var thePtrBuf [4]byte
						if tm.RPM(iatPtr, thePtrBuf[:]) {
							thePtr := uintptr(binary.LittleEndian.Uint32(thePtrBuf[:]))
							if dmp.IsAPIAddress(thePtr) {
								return iatPtr
							}
						}
					}
				}
			}

			if ins.Length > 0 {
				addr += uintptr(ins.Length)
			} else {
				addr++
			}
		}
		return 0
	}

	scanData := func(toFind uintptr) (uintptr, error) {
		startOffset := textBase + codeSize
		scanSize := dataSize
		dataSect := make([]byte, scanSize)
		if !tm.RPM(startOffset, dataSect) {
			return 0, fmt.Errorf("scanData RPM failed")
		}

		ptrSize := 4
		if tm.Is64Bit {
			ptrSize = 8
		}

		for i := 0; i+ptrSize <= len(dataSect); i += ptrSize {
			var val uintptr
			if tm.Is64Bit {
				val = uintptr(binary.LittleEndian.Uint64(dataSect[i : i+8]))
			} else {
				val = uintptr(binary.LittleEndian.Uint32(dataSect[i : i+4]))
			}
			if val == toFind {
				return startOffset + uintptr(i), nil
			}
		}

		// Fallback: scan text section as well
		codeScan := make([]byte, codeSize)
		if tm.RPM(textBase, codeScan) {
			for i := 0; i+ptrSize <= len(codeScan); i += ptrSize {
				var val uintptr
				if tm.Is64Bit {
					val = uintptr(binary.LittleEndian.Uint64(codeScan[i : i+8]))
				} else {
					val = uintptr(binary.LittleEndian.Uint32(codeScan[i : i+4]))
				}
				if val == toFind {
					return textBase + uintptr(i), nil
				}
			}
		}

		return 0, fmt.Errorf("unable to find API in section")
	}

	var iatRef uintptr
	if len(codeDump) >= 4 && binary.LittleEndian.Uint32(codeDump[:4]) == 0x6F4720FF { // \xFF Go
		iatRef = findGoAPICall(textBase + uintptr(findGoBuildIdEnd(codeDump)))
	} else if !tm.IsVMOEP {
		iatRef = findCallOrJmpPtr(oep, false)
	} else {
		delphiOffset := 6
		if tm.Is64Bit {
			delphiOffset = 10
		}
		if len(codeDump) >= delphiOffset+4 &&
			(binary.LittleEndian.Uint32(codeDump[delphiOffset:delphiOffset+4]) == 0x6C6F6F42 || // 'Bool'
				binary.LittleEndian.Uint32(codeDump[6:10]) == 0x65747942) { // 'Byte'
			iatRef = findCallOrJmpPtr(textBase+uintptr(findDelphiCall(codeDump)), true)
		} else {
			iatRef = findCallOrJmpPtr(textBase, true)
		}
	}

	if iatRef == 0 {
		log.Infof("No IAT reference found via reference search")
		if len(tm.GuardAddrs) > 0 {
			firstGuard := tm.GuardAddrs[0]
			var site [6]byte
			tm.RPM(firstGuard, site[:])
			var target uintptr
			if site[0] == 0xE8 || site[0] == 0xE9 {
				displ := int32(binary.LittleEndian.Uint32(site[1:5]))
				target = uintptr(int64(firstGuard) + 5 + int64(displ))
			} else if site[1] == 0xE8 || site[1] == 0xE9 {
				displ := int32(binary.LittleEndian.Uint32(site[2:6]))
				target = uintptr(int64(firstGuard) + 6 + int64(displ))
			} else {
				return 0, fmt.Errorf("first guard addr is not call/jmp")
			}
			log.Infof("First guard addr 0x%08X yielded API 0x%08X", firstGuard, target)
			var err error
			iatRef, err = scanData(target)
			if err != nil {
				return 0, err
			}
		} else {
			return 0, fmt.Errorf("found no way to obtain IAT reference")
		}
	}

	log.Goodf("First IAT ref: 0x%08X", iatRef)

	// Seek backwards to find the beginning of the IAT
	ptrSize := 4
	if tm.Is64Bit {
		ptrSize = 8
	}
	iatReadCount := 512
	iatBufSize := iatReadCount * ptrSize
	if iatRef < tm.ImageBase+uintptr(ptrSize) {
		return 0, fmt.Errorf("IAT reference is outside image")
	}
	if available := int((iatRef-tm.ImageBase)/uintptr(ptrSize)) + 1; available < iatReadCount {
		iatReadCount = available
		iatBufSize = iatReadCount * ptrSize
	}
	readStart := iatRef - uintptr(iatBufSize-ptrSize)

	iatData := make([]byte, iatBufSize)
	if !tm.RPM(readStart, iatData) {
		return 0, fmt.Errorf("reading IAT backwards failed")
	}

	seeker := iatRef
	var startIAT uintptr
	consecutiveZeroes := 0

	for i := iatReadCount - 1; i >= 0; i-- {
		var val uintptr
		if tm.Is64Bit {
			val = uintptr(binary.LittleEndian.Uint64(iatData[i*8 : (i+1)*8]))
		} else {
			val = uintptr(binary.LittleEndian.Uint32(iatData[i*4 : (i+1)*4]))
		}

		if val == 0 {
			consecutiveZeroes++
			if consecutiveZeroes > 64 {
				break
			}
		} else if dmp.IsAPIAddress(val) || (tm.ThemidaV3 && tm.TMSectR.Contains(val)) {
			startIAT = seeker
			consecutiveZeroes = 0
		} else {
			log.Infof("Ending IAT start search at 0x%X because pointer is 0x%X", seeker, val)
			break
		}

		seeker -= uintptr(ptrSize)
	}

	if startIAT == 0 {
		return 0, fmt.Errorf("IAT assertion failed")
	}

	return startIAT, nil
}

func (tm *TMCommon) TraceImports(iat uintptr, dmp *dumper.Dumper) error {
	ptrSize := 4
	if tm.Is64Bit {
		ptrSize = 8
	}
	slotCount := 5120
	iatData := make([]byte, slotCount*ptrSize)
	if !tm.RPM(iat, iatData) {
		return fmt.Errorf("TraceImports RPM failed")
	}

	didSetExitProcess := false
	trashCounter := 0

	k32, _ := winapi.GetModuleHandle("kernel32.dll")
	exitProcessAddr, err := winapi.GetProcAddress(k32, "ExitProcess")
	if err != nil {
		return err
	}

	for i := 0; i < slotCount; i++ {
		var slotVal uintptr
		if tm.Is64Bit {
			slotVal = uintptr(binary.LittleEndian.Uint64(iatData[i*8 : (i+1)*8]))
		} else {
			slotVal = uintptr(binary.LittleEndian.Uint32(iatData[i*4 : (i+1)*4]))
		}

		if tm.TMSectR.Contains(slotVal) {
			log.Infof("Trace: 0x%08X [0x%08X]", slotVal, iat+uintptr(i*ptrSize))
			trashCounter = 0

			hThread := tm.Threads[tm.CurrentThreadID]
			if tm.Is64Bit {
				var c winapi.CONTEXT64
				c.ContextFlags = winapi.CONTEXT_CONTROL_64
				if err := winapi.GetThreadContext64(hThread, &c); err != nil {
					return err
				}
				tm.TraceStartSP = uintptr(c.Rsp)
			} else {
				var c winapi.CONTEXT32
				c.ContextFlags = winapi.CONTEXT_CONTROL_32
				if err := winapi.GetThreadContext32(hThread, &c); err != nil {
					return err
				}
				tm.TraceStartSP = uintptr(c.Esp)
			}

			tm.TracedAPI = 0
			tm.TraceInVM = false

			predicate := func(tr *tracer.Tracer, c32 *winapi.CONTEXT32, c64 *winapi.CONTEXT64) bool {
				return tm.TraceIsAtAPI(tr, c32, c64)
			}

			tr := tracer.NewTracer(tm.ProcessInfo.ProcessId, tm.CurrentThreadID, hThread, tm.Is64Bit, predicate)
			if err := tr.Trace(slotVal, 500000); err != nil {
				tm.EventConsumed = !tr.Pending
				return err
			}
			tm.EventConsumed = !tr.Pending

			if tm.TraceInVM {
				if !didSetExitProcess {
					didSetExitProcess = true
					if tm.Is64Bit {
						binary.LittleEndian.PutUint64(iatData[i*8:(i+1)*8], uint64(exitProcessAddr))
					} else {
						binary.LittleEndian.PutUint32(iatData[i*4:(i+1)*4], uint32(exitProcessAddr))
					}
					log.Infof("Setting API to ExitProcess")
				} else {
					return fmt.Errorf("unable to determine IAT address for 0x%X", iat+uintptr(i*ptrSize))
				}
			} else if tm.TracedAPI != 0 {
				log.Infof("-> 0x%08X", tm.TracedAPI)
				if tm.TracedAPI < 0x10000 || (tm.TracedAPI >= tm.ImageBase && tm.TracedAPI < tm.ImageBoundary) {
					log.Infof("Discarding result & aborting IAT tracing")
					break
				}
				if tm.Is64Bit {
					binary.LittleEndian.PutUint64(iatData[i*8:(i+1)*8], uint64(tm.TracedAPI))
				} else {
					binary.LittleEndian.PutUint32(iatData[i*4:(i+1)*4], uint32(tm.TracedAPI))
				}
			} else {
				return fmt.Errorf("import tracing failed")
			}
		} else if slotVal == 0 || !dmp.IsAPIAddress(slotVal) {
			trashCounter++
			if trashCounter > 64 {
				break
			}
		} else {
			trashCounter = 0
		}
	}

	if err := tm.WriteMemory(iat, iatData); err != nil {
		return fmt.Errorf("writing resolved IAT: %w", err)
	}

	return nil
}

func (tm *TMCommon) TraceIsAtAPI(tr *tracer.Tracer, c32 *winapi.CONTEXT32, c64 *winapi.CONTEXT64) bool {
	var ip, sp uintptr
	if tm.Is64Bit {
		ip = uintptr(c64.Rip)
		sp = uintptr(c64.Rsp)
	} else {
		ip = uintptr(c32.Eip)
		sp = uintptr(c32.Esp)
	}

	if tr.Counter > 100 && tr.Counter < 5000 {
		var insnData [4]byte
		if tm.RPM(ip, insnData[:]) {
			val := binary.LittleEndian.Uint32(insnData[:])
			if tm.Is64Bit && val == 0x0CB10FF0 { // lock cmpxchg [rbx+rbp], ecx
				tm.TraceInVM = true
				log.Infof("Trace ran into Themida VM, stopping")
				return true
			} else if !tm.Is64Bit && val == 0x4CB10FF0 { // lock cmpxchg [ebp+ebx+0], ecx
				tm.TraceInVM = true
				log.Infof("Trace ran into Themida VM, stopping")
				return true
			}
		}
	}

	// Fake calls to Sleep / lstrlen
	if sp < tm.TraceStartSP && (ip == tm.SleepAPI || ip == tm.LstrlenAPI) {
		log.Infof("Skipping anti-trace API at 0x%X", ip)
		if tm.Is64Bit {
			var retAddr [8]byte
			if !tm.RPM(sp, retAddr[:]) {
				return false
			}
			c64.Rsp += 8
			c64.Rip = binary.LittleEndian.Uint64(retAddr[:])
		} else {
			var retAddr [4]byte
			if !tm.RPM(sp, retAddr[:]) {
				return false
			}
			c32.Esp += 8
			c32.Eip = binary.LittleEndian.Uint32(retAddr[:])
		}
	}

	if tm.Is64Bit {
		ip = uintptr(c64.Rip)
		sp = uintptr(c64.Rsp)
	} else {
		ip = uintptr(c32.Eip)
		sp = uintptr(c32.Esp)
	}
	res := !tm.TMSectR.Contains(ip)
	if res && sp < tm.TraceStartSP {
		log.Infof("Warning: Might have encountered new fake API at 0x%X", ip)
		res = false
	}

	if res {
		tm.TracedAPI = ip
	}
	return res
}
