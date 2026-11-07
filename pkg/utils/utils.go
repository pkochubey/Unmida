package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	ntdll         = syscall.NewLazyDLL("ntdll.dll")
	procRtlGetVer = ntdll.NewProc("RtlGetVersion")
)

type RTL_OSVERSIONINFOW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
}

// MemoryRegion represents a memory range [Address, Address+Size).
type MemoryRegion struct {
	Address uintptr
	Size    uintptr
}

func (m MemoryRegion) Contains(addr uintptr) bool {
	return addr >= m.Address && addr < m.Address+m.Size
}

func AccessViolationFlagToStr(flag byte) string {
	switch flag {
	case 0:
		return "Read"
	case 1:
		return "Write"
	case 8:
		return "Execute"
	default:
		return fmt.Sprintf("%d", flag)
	}
}

type patternElem struct {
	val        byte
	isWildcard bool
}

// ParsePattern parses a hex pattern where '?' represents wildcard nibbles.
func parsePattern(pattern string) ([]patternElem, error) {
	clean := strings.ReplaceAll(pattern, " ", "")
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("invalid pattern length: %d", len(clean))
	}
	elems := make([]patternElem, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		pair := clean[i : i+2]
		if pair == "??" {
			elems[i/2] = patternElem{isWildcard: true}
		} else {
			b, err := hex.DecodeString(pair)
			if err != nil {
				return nil, fmt.Errorf("invalid hex in pattern '%s': %w", pair, err)
			}
			elems[i/2] = patternElem{val: b[0], isWildcard: false}
		}
	}
	return elems, nil
}

// FindDynamic searches for a pattern containing wildcards '?' in buf.
// Returns the offset in buf, or -1 if not found.
func FindDynamic(pattern string, buf []byte) int {
	elems, err := parsePattern(pattern)
	if err != nil || len(elems) == 0 || len(buf) < len(elems) {
		return -1
	}

	max := len(buf) - len(elems)
	for i := 0; i <= max; i++ {
		match := true
		for j := 0; j < len(elems); j++ {
			if !elems[j].isWildcard && buf[i+j] != elems[j].val {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// FindStatic searches for an exact hex pattern in buf.
// Returns the offset in buf, or -1 if not found.
func FindStatic(pattern string, buf []byte) int {
	clean := strings.ReplaceAll(pattern, " ", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) == 0 || len(buf) < len(b) {
		return -1
	}

	max := len(buf) - len(b)
	for i := 0; i <= max; i++ {
		match := true
		for j := 0; j < len(b); j++ {
			if buf[i+j] != b[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// GetWindowsBuildNumber returns the Windows build number using RtlGetVersion.
func GetWindowsBuildNumber() uint32 {
	var info RTL_OSVERSIONINFOW
	info.OSVersionInfoSize = uint32(unsafe.Sizeof(info))
	r, _, _ := procRtlGetVer.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return info.BuildNumber
	}
	return 0
}

// GetPETimestamp returns the TimeDateStamp from the PE header of the given file.
func GetPETimestamp(filename string) (uint32, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var header [0x1000]byte
	n, err := f.Read(header[:])
	if err != nil || n < 0x40 {
		return 0, fmt.Errorf("unable to read PE header: %w", err)
	}

	// DOS header magic "MZ"
	if header[0] != 'M' || header[1] != 'Z' {
		return 0, fmt.Errorf("not a valid PE DOS header")
	}

	lfanew := binary.LittleEndian.Uint32(header[0x3C:0x40])
	if lfanew > 0xF00 || int(lfanew)+24 > n {
		return 0, fmt.Errorf("invalid lfanew offset: 0x%X", lfanew)
	}

	// NT signature "PE\0\0"
	ntSig := binary.LittleEndian.Uint32(header[lfanew : lfanew+4])
	if ntSig != 0x00004550 {
		return 0, fmt.Errorf("invalid PE signature: 0x%X", ntSig)
	}

	// FileHeader is at lfanew + 4, TimeDateStamp is at offset +4 inside FileHeader (i.e. lfanew + 8)
	ts := binary.LittleEndian.Uint32(header[lfanew+8 : lfanew+12])
	return ts, nil
}
