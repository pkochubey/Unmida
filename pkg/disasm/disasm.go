package disasm

import (
	"fmt"
	"golang.org/x/arch/x86/x86asm"
)

type Instruction struct {
	Length                      int
	Opcode, Opcode2             byte
	IsTwoByte                   bool
	HasModRM                    bool
	ModRM, Mod, Reg, RM         byte
	HasSIB                      bool
	SIB                         byte
	HasDisplacement             bool
	Displacement                int64
	HasImmediate                bool
	Immediate                   uint64
	ImmSize                     int
	IsCall, IsJmp, IsRet        bool
	RIPRelative, AbsoluteMemory bool
	AddrValue, VirtualAddr      uint64
	Decoded                     x86asm.Inst
}

func DecodeInstruction(data []byte, is64Bit bool, virtAddr uint64) (*Instruction, error) {
	mode := 32
	if is64Bit {
		mode = 64
	}
	decoded, err := x86asm.Decode(data, mode)
	if err != nil {
		return nil, err
	}
	if decoded.Len == 0 || decoded.Op == 0 {
		return nil, fmt.Errorf("invalid instruction at 0x%X", virtAddr)
	}
	ins := &Instruction{Length: decoded.Len, VirtualAddr: virtAddr, Decoded: decoded}
	pos := 0
	for pos < decoded.Len {
		b := data[pos]
		if b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
			b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 ||
			(is64Bit && b >= 0x40 && b <= 0x4F) {
			pos++
			continue
		}
		break
	}
	if pos >= decoded.Len {
		return nil, fmt.Errorf("instruction contains only prefixes")
	}
	ins.Opcode = data[pos]
	pos++
	if ins.Opcode == 0x0F && pos < decoded.Len {
		ins.IsTwoByte = true
		ins.Opcode2 = data[pos]
		pos++
	}
	if pos < decoded.Len {
		ins.ModRM = data[pos]
		ins.Mod, ins.Reg, ins.RM = ins.ModRM>>6, (ins.ModRM>>3)&7, ins.ModRM&7
	}
	ins.IsCall = decoded.Op == x86asm.CALL || decoded.Op == x86asm.LCALL
	ins.IsRet = decoded.Op == x86asm.RET || decoded.Op == x86asm.LRET
	ins.IsJmp = decoded.Op == x86asm.JMP || decoded.Op == x86asm.LJMP
	for _, arg := range decoded.Args {
		switch value := arg.(type) {
		case x86asm.Mem:
			ins.HasModRM = ins.Opcode != 0xA0 && ins.Opcode != 0xA1 && ins.Opcode != 0xA2 && ins.Opcode != 0xA3
			ins.HasDisplacement = true
			ins.Displacement = value.Disp
			ins.RIPRelative = value.Base == x86asm.RIP || value.Base == x86asm.EIP
			ins.AbsoluteMemory = value.Base == 0 && value.Index == 0
			ins.HasSIB = ins.HasModRM && ins.Mod != 3 && ins.RM == 4 && decoded.AddrSize != 16
			if ins.HasSIB && pos+1 < decoded.Len {
				ins.SIB = data[pos+1]
			}
		case x86asm.Imm:
			ins.HasImmediate = true
			ins.Immediate = uint64(value)
		case x86asm.Rel:
			ins.HasImmediate = true
			ins.Immediate = uint64(value)
			ins.ImmSize = decoded.PCRel
			ins.AddrValue = uint64(int64(virtAddr) + int64(decoded.Len) + int64(value))
			if !is64Bit {
				ins.AddrValue = uint64(uint32(ins.AddrValue))
			}
			if !ins.IsCall {
				ins.IsJmp = true
			}
		}
	}
	return ins, nil
}
