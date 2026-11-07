package themida

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/arch/x86/x86asm"
	"unmida/pkg/debugger"
	"unmida/pkg/disasm"
	"unmida/pkg/log"
	"unmida/pkg/utils"
	"unmida/pkg/winapi"
)

func (tm *TMDebugger32) find(pattern string, start uintptr) uintptr {
	if start == 0 {
		start = tm.TMSectR.Address
	}
	if start < tm.TMSectR.Address || start-tm.TMSectR.Address >= uintptr(len(tm.TMSect)) {
		return 0
	}
	offset := start - tm.TMSectR.Address
	found := utils.FindDynamic(pattern, tm.TMSect[offset:])
	if found < 0 {
		return 0
	}
	return start + uintptr(found)
}

func (tm *TMDebugger32) requirePattern(pattern string, start uintptr) uintptr {
	address := tm.find(pattern, start)
	if address == 0 {
		tm.Fail(fmt.Errorf("Themida pattern %s not found", pattern))
	}
	return address
}

func (tm *TMDebugger32) sectionBytes(addr uintptr, length int) []byte {
	if addr < tm.TMSectR.Address || length < 0 {
		tm.Fail(fmt.Errorf("invalid Themida section address 0x%X", addr))
		return nil
	}
	offset := addr - tm.TMSectR.Address
	if offset > uintptr(len(tm.TMSect)) || uintptr(length) > uintptr(len(tm.TMSect))-offset {
		tm.Fail(fmt.Errorf("Themida section read out of bounds at 0x%X", addr))
		return nil
	}
	return tm.TMSect[offset : offset+uintptr(length)]
}

func (tm *TMDebugger32) section32(addr uintptr) uint32 {
	data := tm.sectionBytes(addr, 4)
	if data == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(data)
}

func (tm *TMDebugger32) TMIATFix2() {
	compare := tm.find("74??8B8D????????8B093B8D????????7410", 0)
	if compare == 0 {
		first := tm.requirePattern("3D000001000F83", 0)
		if tm.Err != nil {
			return
		}
		tm.MagicJumpV1 = tm.requirePattern("3B8D????????0F84????0000", first)
		if tm.Err == nil {
			tm.bp(tm.MagicJumpV1, debugger.HWExecute)
		}
	} else {
		tm.CmpImgBase = compare
		tm.bp(compare, debugger.HWExecute)
	}
}

func (tm *TMDebugger32) subtraction(start uintptr) uintptr {
	address := tm.find("2BD90F84", start)
	if address == 0 {
		address = tm.find("29CB0F84", start)
	}
	if address == 0 {
		tm.Fail(fmt.Errorf("IAT subtraction pattern not found"))
	}
	return address
}

func (tm *TMDebugger32) TMIATFix4() {
	tm.requirePattern("83F8500F82", 0)
	compare := tm.requirePattern("3985????????0F84", 0)
	if tm.Err != nil {
		return
	}
	tm.IJumper = compare + 6
	tm.MJ2 = tm.subtraction(compare)
	if tm.Err != nil {
		return
	}
	target := uint32(tm.MJ2+8) + tm.section32(tm.MJ2+4)
	tm.MJ3 = tm.subtraction(tm.MJ2 + 1)
	if tm.Err != nil {
		return
	}
	if uint32(tm.MJ3+8)+tm.section32(tm.MJ3+4) != target {
		tm.Fail(fmt.Errorf("old magic jump: targets differ"))
		return
	}
	tm.MJ4 = tm.subtraction(tm.MJ3 + 1)
	if tm.Err != nil {
		return
	}
	for address := tm.MJ2; address >= tm.TMSectR.Address; address-- {
		data := tm.sectionBytes(address, 6)
		if data == nil {
			return
		}
		if data[0] == 0x0F && data[1] == 0x84 && uint32(address+6)+binary.LittleEndian.Uint32(data[2:]) == target {
			tm.MJ1 = address
			break
		}
		if address == tm.TMSectR.Address {
			break
		}
	}
	if tm.MJ1 == 0 {
		tm.Fail(fmt.Errorf("first magic jump not found"))
		return
	}
	tm.NewVer = ((tm.sectionBytes(tm.MJ1-1, 1)[0] == 0x4B && tm.sectionBytes(tm.MJ2, 1)[0] == 0x2B && tm.sectionBytes(tm.MJ3, 1)[0] == 0x2B && tm.sectionBytes(tm.MJ4, 1)[0] == 0x2B) || tm.sectionBytes(tm.MJ2, 1)[0] == 0x29)
	if tm.find("68????????E9??????FF68????????E9??????FF68????????E9??????FF", 0) != 0 {
		tm.NewVer = false
	}
	if tm.find("68????????68????????E9??????FF68????????68????????E9??????FF", 0) != 0 {
		tm.NewVer = true
	}
	log.Infof("Newer Themida IAT variant: %t", tm.NewVer)
	address := tm.find("3BC89CE9", 0)
	if address != 0 {
		for address != 0 {
			if err := tm.SetSoftBP(address + 3); err != nil {
				tm.Fail(err)
				return
			}
			address = tm.find("3BC89CE9", address+3)
		}
	} else {
		start := tm.TMSectR.Address
		for {
			address = tm.find("39??9C", start)
			if address == 0 {
				break
			}
			start = address + 1
			if address > tm.TMSectR.Address && tm.sectionBytes(address-1, 1)[0] == 0x66 {
				continue
			}
			offset := address - tm.TMSectR.Address
			ins, err := disasm.DecodeInstruction(tm.TMSect[offset:], false, uint64(address))
			if err == nil && ins.Length == 2 && address <= tm.MJ1 {
				if err = tm.SetSoftBP(address + 3); err != nil {
					tm.Fail(err)
					return
				}
			}
		}
	}
	tm.InstallCodeSectionGuard(winapi.PAGE_READONLY)
	tm.bp(tm.MJ1, debugger.HWExecute)
}

func (tm *TMDebugger32) TMIATFix5() {
	tm.write(tm.IJumper, []byte{0x90, 0xE9})
	nops := bytes.Repeat([]byte{0x90}, 6)
	for _, address := range []uintptr{tm.MJ1, tm.MJ2 + 2, tm.MJ3 + 2, tm.MJ4 + 2} {
		tm.write(address, nops)
	}
	log.Goodf("IAT jumper patched at 0x%X", tm.IJumper)
}

func (tm *TMDebugger32) TMIATFixV1(first uintptr) {
	second := tm.requirePattern("3B8D????????0F84????0000", first+12)
	if tm.Err != nil {
		return
	}
	third := tm.requirePattern("3B8D????????0F84????0000", second+12)
	tm.IJumper = tm.requirePattern("3985????????0F84", 0)
	if tm.Err != nil {
		return
	}
	tm.write(tm.IJumper+6, []byte{0x90, 0xE9})
	for _, address := range []uintptr{first + 6, second + 6, third + 6} {
		tm.write(address, bytes.Repeat([]byte{0x90}, 6))
	}
	tm.GuardStart = tm.ImageBase + uintptr(tm.PESections[0].VirtualAddress)
	tm.GuardEnd = tm.ImageBase + 0x100000
	if tm.GuardEnd > tm.ImageBoundary {
		tm.GuardEnd = tm.ImageBoundary
	}
	tm.GuardProtection = winapi.PAGE_NOACCESS
	if _, err := winapi.VirtualProtectEx(tm.ProcessInfo.Process, tm.GuardStart, tm.GuardEnd-tm.GuardStart, tm.GuardProtection); err != nil {
		tm.Fail(err)
	}
}

func (tm *TMDebugger32) moduleBases() [3]uint32 {
	var bases [3]uint32
	for i, name := range []string{"kernel32.dll", "user32.dll", "advapi32.dll"} {
		h, err := winapi.GetModuleHandle(name)
		if err != nil {
			h, err = winapi.LoadLibrary(name)
		}
		if err != nil {
			tm.Fail(err)
			return bases
		}
		bases[i] = uint32(h)
	}
	return bases
}

func jump32(from, to uintptr) []byte {
	b := []byte{0xE9, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[1:], uint32(to)-uint32(from)-5)
	return b
}

func (tm *TMDebugger32) installOldIATPatch(ip uintptr, bases [3]uint32) {
	target := uintptr(uint32(ip+5) + tm.section32(ip+1))
	if tm.Err != nil {
		return
	}
	destination, err := winapi.VirtualAllocEx(tm.ProcessInfo.Process, 0, 128, winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_EXECUTE_READWRITE)
	if err != nil {
		tm.Fail(err)
		return
	}
	data := make([]byte, 41)
	binary.LittleEndian.PutUint16(data[0:], 0xF881)
	binary.LittleEndian.PutUint32(data[2:], bases[0])
	binary.LittleEndian.PutUint32(data[6:], 0xF8811574)
	binary.LittleEndian.PutUint32(data[10:], bases[2])
	binary.LittleEndian.PutUint32(data[14:], 0xF8810D74)
	binary.LittleEndian.PutUint32(data[18:], bases[1])
	binary.LittleEndian.PutUint16(data[22:], 0x0574)
	copy(data[24:], jump32(destination+24, target))
	binary.LittleEndian.PutUint64(data[29:], 0xE9000002872404C7)
	binary.LittleEndian.PutUint32(data[37:], uint32(target)-uint32(destination+36)-5)
	tm.write(destination, data)
	tm.write(ip, jump32(ip, destination))
	log.Goodf("Special IAT patch written at 0x%X", ip)
}

func (tm *TMDebugger32) InstallEFLPatch(ip uintptr, c *winapi.CONTEXT32, record *EFLRecord) bool {
	bases := tm.moduleBases()
	if tm.Err != nil {
		return false
	}
	registers := []uint32{c.Eax, c.Ecx, c.Edx, c.Ebx, c.Esp, c.Ebp, c.Esi, c.Edi}
	register := -1
	for _, base := range bases {
		for i, value := range registers {
			if i != 4 && value == base {
				register = i
				break
			}
		}
		if register >= 0 {
			break
		}
	}
	if register < 0 {
		return false
	}
	if !tm.TMSectR.Contains(ip) {
		tm.Fail(fmt.Errorf("EFL patch outside Themida section"))
		return false
	}
	offset := ip - tm.TMSectR.Address
	total := 0
	for total < 5 {
		ins, err := disasm.DecodeInstruction(tm.TMSect[offset+uintptr(total):], false, uint64(ip)+uint64(total))
		if err != nil {
			tm.Fail(err)
			return false
		}
		if ins.IsJmp || ins.IsCall || ins.IsRet {
			tm.Fail(fmt.Errorf("EFL patch would relocate control flow at 0x%X", ip+uintptr(total)))
			return false
		}
		for _, arg := range ins.Decoded.Args {
			if _, ok := arg.(x86asm.Rel); ok {
				tm.Fail(fmt.Errorf("EFL patch contains relative operand"))
				return false
			}
		}
		total += ins.Length
	}
	if 55+total+5 > 128 {
		tm.Fail(fmt.Errorf("EFL patch exceeds allocation"))
		return false
	}
	destination, err := winapi.VirtualAllocEx(tm.ProcessInfo.Process, 0, 128, winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_EXECUTE_READWRITE)
	if err != nil {
		tm.Fail(err)
		return false
	}
	data := bytes.Repeat([]byte{0x90}, 128)
	for i, base := range bases {
		at := i * 8
		data[at], data[at+1] = 0x81, 0xF8+byte(register)
		binary.LittleEndian.PutUint32(data[at+2:], base)
		data[at+6], data[at+7] = 0x74, byte(0x28-i*8)
	}
	data[24], data[25] = 0xEB, 0x1D
	binary.LittleEndian.PutUint64(data[48:], 0x90000002462404C7)
	original := tm.sectionBytes(ip, total)
	if original == nil {
		return false
	}
	copy(data[55:], original)
	copy(data[55+total:], jump32(destination+55+uintptr(total), ip+uintptr(total)))
	tm.write(destination, data)
	tm.write(ip, jump32(ip, destination))
	var preceding [6]byte
	if ip >= 9 && tm.RPM(ip-9, preceding[:]) && preceding[0] == 0x0F && (preceding[1] == 0x84 || preceding[1] == 0x85) {
		displacement := binary.LittleEndian.Uint32(preceding[2:])
		if displacement >= 4 && displacement <= 7 {
			binary.LittleEndian.PutUint32(preceding[2:], uint32(destination+55)+displacement-3-uint32(ip-9)-6)
			tm.write(ip-7, preceding[2:])
		}
	}
	if tm.Err != nil {
		return false
	}
	record.Address = ip
	record.Original = append([]byte(nil), original...)
	log.Goodf("EFL patch at 0x%X", ip)
	return true
}
