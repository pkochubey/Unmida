package antidump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unmida/pkg/log"
	"unmida/pkg/winapi"
	"syscall"
)

type AntiDumpFixer struct {
	hProcess  syscall.Handle
	imageBase uintptr
}

func NewAntiDumpFixer(hProcess syscall.Handle, imageBase uintptr) *AntiDumpFixer {
	return &AntiDumpFixer{
		hProcess:  hProcess,
		imageBase: imageBase,
	}
}

func (a *AntiDumpFixer) RedirectOEP(oep, iat uintptr) error {
	var displBuf [4]byte
	if _, err := winapi.ReadProcessMemory(a.hProcess, oep+1, displBuf[:]); err != nil {
		return fmt.Errorf("AntiDumpFixer: failed to read displacement from OEP+1: %v", err)
	}
	displ := binary.LittleEndian.Uint32(displBuf[:])

	k32, err := winapi.GetModuleHandle("kernel32.dll")
	if err != nil {
		return fmt.Errorf("AntiDumpFixer: failed to get kernel32 handle: %v", err)
	}
	vprotectAddr, err := winapi.GetProcAddress(k32, "VirtualProtect")
	if err != nil {
		return fmt.Errorf("AntiDumpFixer: failed to find VirtualProtect: %v", err)
	}

	var iatData [512 * 4]byte
	if _, err := winapi.ReadProcessMemory(a.hProcess, iat, iatData[:]); err != nil {
		return fmt.Errorf("AntiDumpFixer: failed to read IAT: %v", err)
	}

	var vprotectIAT uint32
	for i := 0; i < 512; i++ {
		addr := binary.LittleEndian.Uint32(iatData[i*4 : (i+1)*4])
		if uintptr(addr) == vprotectAddr {
			vprotectIAT = uint32(iat + uintptr(i*4))
			break
		}
	}

	if vprotectIAT == 0 {
		return fmt.Errorf("VirtualProtect not found in IAT")
	}

	var lfaNewBuf [4]byte
	if _, err := winapi.ReadProcessMemory(a.hProcess, a.imageBase+0x3C, lfaNewBuf[:]); err != nil {
		return fmt.Errorf("ReadProcessMemory failed for lfaNew: %v", err)
	}
	lfaNew := binary.LittleEndian.Uint32(lfaNewBuf[:])

	var epBuf [4]byte
	if _, err := winapi.ReadProcessMemory(a.hProcess, a.imageBase+uintptr(lfaNew)+0x28, epBuf[:]); err != nil {
		return fmt.Errorf("ReadProcessMemory failed for AddressOfEntryPoint: %v", err)
	}
	entrypoint := binary.LittleEndian.Uint32(epBuf[:])
	optHdrEntrypoint := uint32(a.imageBase + uintptr(lfaNew) + 0x28)

	pushArgs1 := []byte{0x6A, 0x00, 0x54, 0x6A, 0x04, 0x68, 0x00, 0x04, 0x00, 0x00, 0x68}
	pushArgs2 := []byte{0x54, 0xFF, 0x74, 0x24, 0x04, 0x68, 0x00, 0x04, 0x00, 0x00, 0x68}

	// Calculate size of new code
	// pushArgs1 (11) + pushImgBase1 (4) + callInstr1 (2) + vpAddr1 (4)
	// + movInstr (2) + optHdrEP (4) + entrypoint (4)
	// + pushArgs2 (11) + pushImgBase2 (4) + callInstr2 (2) + vpAddr2 (4) + pop (1)
	// + jmp (1) + jmpDispl (4)
	// Total = 11+4+2+4 + 2+4+4 + 11+4+2+4+1 + 1+4 = 58 bytes
	codeLen := uint32(58)
	jmpDispl := displ - (codeLen - 5)

	buf := new(bytes.Buffer)
	buf.Write(pushArgs1)
	binary.Write(buf, binary.LittleEndian, uint32(a.imageBase))
	binary.Write(buf, binary.LittleEndian, uint16(0x15FF))
	binary.Write(buf, binary.LittleEndian, vprotectIAT)

	binary.Write(buf, binary.LittleEndian, uint16(0x05C7))
	binary.Write(buf, binary.LittleEndian, optHdrEntrypoint)
	binary.Write(buf, binary.LittleEndian, entrypoint)

	buf.Write(pushArgs2)
	binary.Write(buf, binary.LittleEndian, uint32(a.imageBase))
	binary.Write(buf, binary.LittleEndian, uint16(0x15FF))
	binary.Write(buf, binary.LittleEndian, vprotectIAT)
	buf.WriteByte(0x58) // pop eax

	buf.WriteByte(0xE9)
	binary.Write(buf, binary.LittleEndian, jmpDispl)

	newCode := buf.Bytes()
	if len(newCode) != int(codeLen) {
		return fmt.Errorf("anti-dump stub length mismatch")
	}
	old, err := winapi.VirtualProtectEx(a.hProcess, oep, uintptr(len(newCode)), winapi.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return err
	}
	_, writeErr := winapi.WriteProcessMemory(a.hProcess, oep, newCode)
	_, protectErr := winapi.VirtualProtectEx(a.hProcess, oep, uintptr(len(newCode)), old)
	if writeErr != nil {
		return writeErr
	}
	if protectErr != nil {
		return protectErr
	}
	if err := winapi.FlushInstructionCache(a.hProcess, oep, uintptr(len(newCode))); err != nil {
		return err
	}
	log.Goodf("Installed VM anti-dump (PE header) mitigation at OEP")
	return nil
}
