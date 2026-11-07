package themida

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"syscall"

	"unmida/pkg/antidump"
	"unmida/pkg/dumper"
	"unmida/pkg/log"
	"unmida/pkg/patcher"
	"unmida/pkg/winapi"
)

func (tm *TMDebugger32) IsTMExceptionHandler(addr uintptr) bool {
	var data [64]byte
	if !tm.RPM(addr, data[:]) {
		return false
	}
	return bytes.Contains(data[:], []byte{0x8B, 0x83, 0xB8, 0x00})
}

func (tm *TMDebugger32) RestoreStolenOEPForMSVC6(thread syscall.Handle, oep uintptr) uintptr {
	var check [3]byte
	if !tm.RPM(oep, check[:2]) || check[0] != 0x8A || check[1] != 0xD4 {
		return oep
	}
	restore := []byte{0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0x64, 0xA1, 0, 0, 0, 0, 0x50, 0x64, 0x89, 0x25, 0, 0, 0, 0, 0x83, 0xEC, 0x58, 0x53, 0x56, 0x57, 0x89, 0x65, 0xE8, 0xFF, 0x15, 0, 0, 0, 0, 0x33, 0xD2}
	if oep < uintptr(len(restore)+3) || !tm.RPM(oep-uintptr(len(restore))-3, check[:]) || (check[0] != 0xC2 && check[2] != 0xC3) {
		tm.Fail(fmt.Errorf("stolen MSVC6 OEP gap mismatch"))
		return oep
	}
	versionAPI := tm.api("kernel32.dll", "GetVersion")
	iat := tm.ImageBase + tm.BaseOfData
	var iatData [512 * 4]byte
	if !tm.RPM(iat, iatData[:]) {
		tm.Fail(fmt.Errorf("reading MSVC6 IAT failed"))
		return oep
	}
	found := false
	for i := 0; i < 512; i++ {
		if uintptr(binary.LittleEndian.Uint32(iatData[i*4:])) == versionAPI {
			binary.LittleEndian.PutUint32(restore[len(restore)-6:], uint32(iat+uintptr(i*4)))
			found = true
			break
		}
	}
	if !found {
		tm.Fail(fmt.Errorf("GetVersion not found in MSVC6 IAT"))
		return oep
	}
	var c winapi.CONTEXT32
	c.ContextFlags = winapi.CONTEXT_INTEGER_32 | winapi.CONTEXT_CONTROL_32
	if err := winapi.GetThreadContext32(thread, &c); err != nil {
		tm.Fail(err)
		return oep
	}
	if c.Esp != c.Ebp-0x74 {
		tm.Fail(fmt.Errorf("MSVC6 stack frame mismatch"))
		return oep
	}
	var stack [8]byte
	if !tm.RPM(uintptr(c.Ebp)-12, stack[:]) {
		tm.Fail(fmt.Errorf("reading MSVC6 exception frame failed"))
		return oep
	}
	copy(restore[6:10], stack[4:8])
	copy(restore[11:15], stack[0:4])
	oep -= uintptr(len(restore))
	tm.write(oep, restore)
	log.Goodf("Restored MSVC6 OEP: 0x%X", oep)
	return oep
}

func (tm *TMDebugger32) RestoreStolenOEPForMSVC9DLL(oep uintptr) uintptr {
	var first [1]byte
	if !tm.RPM(oep, first[:]) || first[0] != 0xE8 || oep < 11 {
		return oep
	}
	if !tm.RPM(oep-11, first[:]) || first[0] != 0xE9 {
		return oep
	}
	oep -= 11
	tm.write(oep, []byte{0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x0C, 0x01, 0x75, 0x05})
	log.Goodf("Restored MSVC9 DLL OEP: 0x%X", oep)
	return oep
}

func (tm *TMDebugger32) TryFindCorrectOEP(oep uintptr) uintptr {
	switch tm.MajorLinkerVersion {
	case 9, 10, 11, 12, 14:
	default:
		tm.Fail(fmt.Errorf("cannot restore stolen OEP for linker %d", tm.MajorLinkerVersion))
		return oep
	}
	start := tm.ImageBase + uintptr(tm.PESections[0].VirtualAddress)
	if tm.BaseOfData <= uintptr(tm.PESections[0].VirtualAddress) {
		tm.Fail(fmt.Errorf("invalid text boundary"))
		return oep
	}
	data := make([]byte, tm.BaseOfData-uintptr(tm.PESections[0].VirtualAddress))
	if !tm.RPM(start, data) {
		tm.Fail(fmt.Errorf("reading text for OEP search failed"))
		return oep
	}
	for i := 0; i+10 <= len(data); i++ {
		if data[i] == 0xE8 && data[i+5] == 0xE9 && uint32(start)+uint32(i)+5+binary.LittleEndian.Uint32(data[i+1:]) == uint32(oep) {
			log.Goodf("Found real OEP: 0x%X", start+uintptr(i))
			return start + uintptr(i)
		}
	}
	tm.Fail(fmt.Errorf("real OEP not found"))
	return oep
}

func (tm *TMDebugger32) FixupAPICallSites(iat uintptr) error {
	if len(tm.GuardAddrs) == 0 {
		return nil
	}
	sort.Slice(tm.GuardAddrs, func(i, j int) bool { return tm.GuardAddrs[i] < tm.GuardAddrs[j] })
	sites := []uintptr{tm.GuardAddrs[0]}
	for _, addr := range tm.GuardAddrs[1:] {
		if addr-sites[len(sites)-1] >= 6 {
			sites = append(sites, addr)
		}
	}
	data := make([]byte, 5120*4)
	if !tm.RPM(iat, data) {
		return fmt.Errorf("reading IAT for call site repair failed")
	}
	slots := make(map[uint32]uint32)
	for i := 0; i < len(data); i += 4 {
		slots[binary.LittleEndian.Uint32(data[i:])] = uint32(iat) + uint32(i)
	}
	for _, addr := range sites {
		var site [6]byte
		if !tm.RPM(addr, site[:]) {
			return fmt.Errorf("reading call site 0x%X failed", addr)
		}
		opcodeOffset := -1
		if site[0] == 0xE8 || site[0] == 0xE9 {
			opcodeOffset = 0
		} else if site[1] == 0xE8 || site[1] == 0xE9 {
			opcodeOffset = 1
		}
		if opcodeOffset < 0 {
			if site[0] == 0xFF && (site[1] == 0x15 || site[1] == 0x25) {
				continue
			}
			return fmt.Errorf("unknown call site at 0x%X", addr)
		}
		target := uint32(addr) + uint32(opcodeOffset) + 5 + binary.LittleEndian.Uint32(site[opcodeOffset+1:])
		slot, ok := slots[target]
		if !ok {
			return fmt.Errorf("call site 0x%X target 0x%X is not in IAT", addr, target)
		}
		jump := site[opcodeOffset] == 0xE9
		site[0], site[1] = 0xFF, 0x15
		if jump {
			site[1] = 0x25
		}
		binary.LittleEndian.PutUint32(site[2:], slot)
		if err := tm.WriteMemory(addr, site[:]); err != nil {
			return err
		}
	}
	log.Goodf("Restored %d API call sites", len(sites))
	return nil
}

func (tm *TMDebugger32) FinishUnpacking(oep uintptr) {
	for _, record := range tm.EFLs {
		if record.Address != 0 {
			tm.write(record.Address, record.Original)
		}
	}
	if tm.Err != nil {
		return
	}
	dump := dumper.NewDumper(tm.ProcessInfo.Process, tm.ProcessInfo.ProcessId, tm.Executable, tm.ImageBase, oep, false)
	iat, err := tm.DetermineIATAddress(oep, dump)
	if err != nil {
		tm.Fail(err)
		return
	}
	log.Goodf("IAT: 0x%X", iat)
	if tm.ThemidaV3 {
		if err = tm.TraceImports(iat, dump); err != nil {
			tm.Fail(err)
			return
		}
	}
	if err = tm.FixupAPICallSites(iat); err != nil {
		tm.Fail(err)
		return
	}
	if tm.IsVMOEP && tm.ThemidaV3 {
		if err = antidump.NewAntiDumpFixer(tm.ProcessInfo.Process, tm.ImageBase).RedirectOEP(oep, iat); err != nil {
			tm.Fail(err)
			return
		}
	}
	dump.IAT = iat
	header, err := dump.Process()
	if err != nil {
		tm.Fail(err)
		return
	}
	out := dumper.ChangeFileExt(tm.Executable, "U"+filepath.Ext(tm.Executable))
	if err = dump.DumpToFile(out, header, tm.IsDLL); err != nil {
		tm.Fail(err)
		return
	}
	out = dump.OutputFile
	if tm.CreateDataSections {
		patch, err := patcher.NewPatcher(out)
		if err == nil {
			err = patch.ProcessMkData()
		}
		if err != nil {
			tm.Fail(err)
			return
		}
	}
	tm.HideThreadEnd = true
	tm.Succeeded = true
	tm.ShouldTerminate = true
	log.Goodf("Operation completed successfully. Output saved to: %s", out)
}
