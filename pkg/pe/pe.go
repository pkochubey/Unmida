package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unmida/pkg/log"
)

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

func (s *ImageSectionHeader) SectionName() string {
	idx := bytes.IndexByte(s.Name[:], 0)
	if idx == -1 {
		return string(s.Name[:])
	}
	return string(s.Name[:idx])
}

type PESection struct {
	Header ImageSectionHeader
	Data   []byte
}

func (s *PESection) Rename(newName string) {
	var b [8]byte
	copy(b[:], []byte(newName))
	s.Header.Name = b
}

type PEHeader struct {
	Is64Bit bool
	LFANew  uint32

	FileHeader ImageFileHeader

	// Optional Header fields (unified)
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // 32-bit only
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory

	Sections []*PESection
	DumpSize uint32
}

func ParsePEHeader(data []byte) (*PEHeader, error) {
	if len(data) < 0x40 {
		return nil, fmt.Errorf("data too short for DOS header")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("invalid DOS signature")
	}

	pe := &PEHeader{}
	pe.LFANew = binary.LittleEndian.Uint32(data[0x3C:0x40])
	if uint64(pe.LFANew)+24 > uint64(len(data)) {
		return nil, fmt.Errorf("invalid LFANew: 0x%X", pe.LFANew)
	}

	sig := binary.LittleEndian.Uint32(data[pe.LFANew : pe.LFANew+4])
	if sig != 0x00004550 {
		return nil, fmt.Errorf("invalid NT signature: 0x%X", sig)
	}

	fhOffset := pe.LFANew + 4
	fhReader := bytes.NewReader(data[fhOffset : fhOffset+20])
	if err := binary.Read(fhReader, binary.LittleEndian, &pe.FileHeader); err != nil {
		return nil, fmt.Errorf("failed reading FileHeader: %w", err)
	}

	optOffset := fhOffset + 20
	optEnd := uint64(optOffset) + uint64(pe.FileHeader.SizeOfOptionalHeader)
	if pe.FileHeader.SizeOfOptionalHeader < 2 || optEnd > uint64(len(data)) {
		return nil, fmt.Errorf("truncated optional header")
	}
	magic := binary.LittleEndian.Uint16(data[optOffset : optOffset+2])
	pe.Magic = magic
	minimum := uint16(96)
	if magic == 0x20B {
		minimum = 112
	}
	if pe.FileHeader.SizeOfOptionalHeader < minimum {
		return nil, fmt.Errorf("optional header is too short")
	}

	if magic == 0x20B { // PE32+ (64-bit)
		pe.Is64Bit = true
		pe.MajorLinkerVersion = data[optOffset+2]
		pe.MinorLinkerVersion = data[optOffset+3]
		pe.SizeOfCode = binary.LittleEndian.Uint32(data[optOffset+4 : optOffset+8])
		pe.SizeOfInitializedData = binary.LittleEndian.Uint32(data[optOffset+8 : optOffset+12])
		pe.SizeOfUninitializedData = binary.LittleEndian.Uint32(data[optOffset+12 : optOffset+16])
		pe.AddressOfEntryPoint = binary.LittleEndian.Uint32(data[optOffset+16 : optOffset+20])
		pe.BaseOfCode = binary.LittleEndian.Uint32(data[optOffset+20 : optOffset+24])

		pe.ImageBase = binary.LittleEndian.Uint64(data[optOffset+24 : optOffset+32])
		pe.SectionAlignment = binary.LittleEndian.Uint32(data[optOffset+32 : optOffset+36])
		pe.FileAlignment = binary.LittleEndian.Uint32(data[optOffset+36 : optOffset+40])
		pe.MajorOperatingSystemVersion = binary.LittleEndian.Uint16(data[optOffset+40 : optOffset+42])
		pe.MinorOperatingSystemVersion = binary.LittleEndian.Uint16(data[optOffset+42 : optOffset+44])
		pe.MajorImageVersion = binary.LittleEndian.Uint16(data[optOffset+44 : optOffset+46])
		pe.MinorImageVersion = binary.LittleEndian.Uint16(data[optOffset+46 : optOffset+48])
		pe.MajorSubsystemVersion = binary.LittleEndian.Uint16(data[optOffset+48 : optOffset+50])
		pe.MinorSubsystemVersion = binary.LittleEndian.Uint16(data[optOffset+50 : optOffset+52])
		pe.Win32VersionValue = binary.LittleEndian.Uint32(data[optOffset+52 : optOffset+56])
		pe.SizeOfImage = binary.LittleEndian.Uint32(data[optOffset+56 : optOffset+60])
		pe.SizeOfHeaders = binary.LittleEndian.Uint32(data[optOffset+60 : optOffset+64])
		pe.CheckSum = binary.LittleEndian.Uint32(data[optOffset+64 : optOffset+68])
		pe.Subsystem = binary.LittleEndian.Uint16(data[optOffset+68 : optOffset+70])
		pe.DllCharacteristics = binary.LittleEndian.Uint16(data[optOffset+70 : optOffset+72])
		pe.SizeOfStackReserve = binary.LittleEndian.Uint64(data[optOffset+72 : optOffset+80])
		pe.SizeOfStackCommit = binary.LittleEndian.Uint64(data[optOffset+80 : optOffset+88])
		pe.SizeOfHeapReserve = binary.LittleEndian.Uint64(data[optOffset+88 : optOffset+96])
		pe.SizeOfHeapCommit = binary.LittleEndian.Uint64(data[optOffset+96 : optOffset+104])
		pe.LoaderFlags = binary.LittleEndian.Uint32(data[optOffset+104 : optOffset+108])
		pe.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(data[optOffset+108 : optOffset+112])

		ddOffset := optOffset + 112
		for i := 0; i < 16 && uint32(i) < pe.NumberOfRvaAndSizes; i++ {
			if uint64(ddOffset)+8 <= optEnd {
				pe.DataDirectory[i].VirtualAddress = binary.LittleEndian.Uint32(data[ddOffset : ddOffset+4])
				pe.DataDirectory[i].Size = binary.LittleEndian.Uint32(data[ddOffset+4 : ddOffset+8])
				ddOffset += 8
			}
		}
	} else if magic == 0x10B { // PE32 (32-bit)
		pe.Is64Bit = false
		pe.MajorLinkerVersion = data[optOffset+2]
		pe.MinorLinkerVersion = data[optOffset+3]
		pe.SizeOfCode = binary.LittleEndian.Uint32(data[optOffset+4 : optOffset+8])
		pe.SizeOfInitializedData = binary.LittleEndian.Uint32(data[optOffset+8 : optOffset+12])
		pe.SizeOfUninitializedData = binary.LittleEndian.Uint32(data[optOffset+12 : optOffset+16])
		pe.AddressOfEntryPoint = binary.LittleEndian.Uint32(data[optOffset+16 : optOffset+20])
		pe.BaseOfCode = binary.LittleEndian.Uint32(data[optOffset+20 : optOffset+24])
		pe.BaseOfData = binary.LittleEndian.Uint32(data[optOffset+24 : optOffset+28])

		pe.ImageBase = uint64(binary.LittleEndian.Uint32(data[optOffset+28 : optOffset+32]))
		pe.SectionAlignment = binary.LittleEndian.Uint32(data[optOffset+32 : optOffset+36])
		pe.FileAlignment = binary.LittleEndian.Uint32(data[optOffset+36 : optOffset+40])
		pe.MajorOperatingSystemVersion = binary.LittleEndian.Uint16(data[optOffset+40 : optOffset+42])
		pe.MinorOperatingSystemVersion = binary.LittleEndian.Uint16(data[optOffset+42 : optOffset+44])
		pe.MajorImageVersion = binary.LittleEndian.Uint16(data[optOffset+44 : optOffset+46])
		pe.MinorImageVersion = binary.LittleEndian.Uint16(data[optOffset+46 : optOffset+48])
		pe.MajorSubsystemVersion = binary.LittleEndian.Uint16(data[optOffset+48 : optOffset+50])
		pe.MinorSubsystemVersion = binary.LittleEndian.Uint16(data[optOffset+50 : optOffset+52])
		pe.Win32VersionValue = binary.LittleEndian.Uint32(data[optOffset+52 : optOffset+56])
		pe.SizeOfImage = binary.LittleEndian.Uint32(data[optOffset+56 : optOffset+60])
		pe.SizeOfHeaders = binary.LittleEndian.Uint32(data[optOffset+60 : optOffset+64])
		pe.CheckSum = binary.LittleEndian.Uint32(data[optOffset+64 : optOffset+68])
		pe.Subsystem = binary.LittleEndian.Uint16(data[optOffset+68 : optOffset+70])
		pe.DllCharacteristics = binary.LittleEndian.Uint16(data[optOffset+70 : optOffset+72])
		pe.SizeOfStackReserve = uint64(binary.LittleEndian.Uint32(data[optOffset+72 : optOffset+76]))
		pe.SizeOfStackCommit = uint64(binary.LittleEndian.Uint32(data[optOffset+76 : optOffset+80]))
		pe.SizeOfHeapReserve = uint64(binary.LittleEndian.Uint32(data[optOffset+80 : optOffset+84]))
		pe.SizeOfHeapCommit = uint64(binary.LittleEndian.Uint32(data[optOffset+84 : optOffset+88]))
		pe.LoaderFlags = binary.LittleEndian.Uint32(data[optOffset+88 : optOffset+92])
		pe.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(data[optOffset+92 : optOffset+96])

		ddOffset := optOffset + 96
		for i := 0; i < 16 && uint32(i) < pe.NumberOfRvaAndSizes; i++ {
			if uint64(ddOffset)+8 <= optEnd {
				pe.DataDirectory[i].VirtualAddress = binary.LittleEndian.Uint32(data[ddOffset : ddOffset+4])
				pe.DataDirectory[i].Size = binary.LittleEndian.Uint32(data[ddOffset+4 : ddOffset+8])
				ddOffset += 8
			}
		}
	} else {
		return nil, fmt.Errorf("unsupported OptionalHeader Magic: 0x%X", magic)
	}

	pe.DumpSize = pe.SizeOfImage
	if pe.SectionAlignment == 0 || pe.FileAlignment == 0 || pe.SizeOfImage == 0 {
		return nil, fmt.Errorf("invalid PE alignment or image size")
	}
	if pe.FileHeader.NumberOfSections == 0 || optEnd+uint64(pe.FileHeader.NumberOfSections)*40 > uint64(len(data)) {
		return nil, fmt.Errorf("missing or truncated section table")
	}

	sectOffset := optOffset + uint32(pe.FileHeader.SizeOfOptionalHeader)
	pe.Sections = make([]*PESection, pe.FileHeader.NumberOfSections)
	for i := 0; i < int(pe.FileHeader.NumberOfSections); i++ {
		sReader := bytes.NewReader(data[sectOffset : sectOffset+40])
		sec := &PESection{}
		if err := binary.Read(sReader, binary.LittleEndian, &sec.Header); err != nil {
			return nil, fmt.Errorf("failed reading section %d: %w", i, err)
		}
		pe.Sections[i] = sec
		sectOffset += 40
	}

	return pe, nil
}

func (pe *PEHeader) SectionAlign(v *uint32) {
	delta := *v % pe.SectionAlignment
	if delta > 0 {
		*v += pe.SectionAlignment - delta
	}
}

func (pe *PEHeader) FileAlign(v *uint32) {
	delta := *v % pe.FileAlignment
	if delta > 0 {
		*v += pe.FileAlignment - delta
	}
}

func (pe *PEHeader) CreateSection(name string, size uint32) *PESection {
	var prev *ImageSectionHeader
	if len(pe.Sections) > 0 {
		prev = &pe.Sections[len(pe.Sections)-1].Header
	}

	sec := &PESection{}
	sec.Rename(name)

	sec.Header.VirtualSize = size
	if prev != nil {
		sec.Header.VirtualAddress = prev.VirtualAddress + prev.VirtualSize
	} else {
		sec.Header.VirtualAddress = 0x1000
	}
	pe.SectionAlign(&sec.Header.VirtualAddress)
	sec.Header.PointerToRawData = pe.SizeOfImage
	sec.Header.SizeOfRawData = size
	sec.Header.Characteristics = 0x40000000 | 0x00000040 // IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA

	pe.SizeOfImage += size
	pe.Sections = append(pe.Sections, sec)
	return sec
}

func (pe *PEHeader) DeleteSection(idx int) {
	if idx < 0 || idx >= len(pe.Sections) {
		return
	}
	isLast := idx == len(pe.Sections)-1
	var sz uint32
	if isLast {
		sz = pe.SizeOfImage - pe.Sections[idx].Header.SizeOfRawData
	} else {
		sz = pe.Sections[idx+1].Header.PointerToRawData - pe.Sections[idx].Header.PointerToRawData
	}

	for i := len(pe.Sections) - 1; i > idx; i-- {
		pe.Sections[i].Header.PointerToRawData -= sz
	}
	if idx > 0 {
		pe.Sections[idx-1].Header.VirtualSize += pe.Sections[idx].Header.VirtualSize
		pe.SectionAlign(&pe.Sections[idx-1].Header.VirtualSize)
	}

	pe.Sections = append(pe.Sections[:idx], pe.Sections[idx+1:]...)
	pe.FileHeader.NumberOfSections--
}

func (pe *PEHeader) GetSectionByVA(va uint32) *PESection {
	for _, s := range pe.Sections {
		if va >= s.Header.VirtualAddress && uint64(va)-uint64(s.Header.VirtualAddress) < uint64(s.Header.VirtualSize) {
			return s
		}
	}
	return nil
}

func (pe *PEHeader) ConvertOffsetToRVAVector(offset uint64) uint64 {
	for _, s := range pe.Sections {
		rawStart := uint64(s.Header.PointerToRawData)
		rawEnd := rawStart + uint64(s.Header.SizeOfRawData)
		if offset >= rawStart && offset < rawEnd {
			return (offset - rawStart) + uint64(s.Header.VirtualAddress)
		}
	}
	return 0
}

func (pe *PEHeader) Sanitize() {
	for _, s := range pe.Sections {
		s.Header.PointerToRawData = s.Header.VirtualAddress
		s.Header.SizeOfRawData = s.Header.VirtualSize
	}
	if len(pe.Sections) > 0 {
		pe.SizeOfHeaders = pe.Sections[0].Header.PointerToRawData
		// Must have write access in code section (in case .text and .data were merged)
		pe.Sections[0].Header.Characteristics |= 0x80000000 // IMAGE_SCN_MEM_WRITE
	}
}

func (pe *PEHeader) TrimHugeSections(buf []byte, iatRawAddr *uint32) uint32 {
	currentSize := uint32(len(buf))
	var totalDelta uint32
	count := min(int(pe.FileHeader.NumberOfSections), len(pe.Sections))
	for i := 0; i < count; i++ {
		section := pe.Sections[i]
		start := section.Header.PointerToRawData
		rawSize := section.Header.SizeOfRawData
		if uint64(start)+uint64(rawSize) > uint64(currentSize) {
			continue
		}
		zeroStart := rawSize
		for zeroStart >= 4 && binary.LittleEndian.Uint32(buf[start+zeroStart-4:start+zeroStart]) == 0 {
			zeroStart -= 4
		}
		if rawSize-zeroStart <= 1024*1024 {
			continue
		}
		end := currentSize
		if i+1 < len(pe.Sections) {
			end = pe.Sections[i+1].Header.PointerToRawData
		}
		if end < start || end > currentSize {
			continue
		}
		newSize := zeroStart
		pe.FileAlign(&newSize)
		oldSize := end - start
		if newSize >= oldSize {
			continue
		}
		delta := oldSize - newSize
		copy(buf[start+newSize:currentSize-delta], buf[end:currentSize])
		currentSize -= delta
		totalDelta += delta
		section.Header.SizeOfRawData = newSize
		for j := i + 1; j < len(pe.Sections); j++ {
			pe.Sections[j].Header.PointerToRawData -= delta
		}
		if *iatRawAddr >= end {
			*iatRawAddr -= delta
		}
		log.Infof("Reducing section [%s]: 0x%X -> 0x%X", section.Header.SectionName(), oldSize, newSize)
	}
	return totalDelta
}

func (pe *PEHeader) SerializeNTHeaders() ([]byte, error) {
	buf := new(bytes.Buffer)
	// Signature
	binary.Write(buf, binary.LittleEndian, uint32(0x00004550))
	// FileHeader
	binary.Write(buf, binary.LittleEndian, pe.FileHeader)

	// OptionalHeader
	if pe.Is64Bit {
		binary.Write(buf, binary.LittleEndian, pe.Magic)
		buf.WriteByte(pe.MajorLinkerVersion)
		buf.WriteByte(pe.MinorLinkerVersion)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfCode)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfInitializedData)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfUninitializedData)
		binary.Write(buf, binary.LittleEndian, pe.AddressOfEntryPoint)
		binary.Write(buf, binary.LittleEndian, pe.BaseOfCode)

		binary.Write(buf, binary.LittleEndian, pe.ImageBase)
		binary.Write(buf, binary.LittleEndian, pe.SectionAlignment)
		binary.Write(buf, binary.LittleEndian, pe.FileAlignment)
		binary.Write(buf, binary.LittleEndian, pe.MajorOperatingSystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.MinorOperatingSystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.MajorImageVersion)
		binary.Write(buf, binary.LittleEndian, pe.MinorImageVersion)
		binary.Write(buf, binary.LittleEndian, pe.MajorSubsystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.MinorSubsystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.Win32VersionValue)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfImage)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfHeaders)
		binary.Write(buf, binary.LittleEndian, pe.CheckSum)
		binary.Write(buf, binary.LittleEndian, pe.Subsystem)
		binary.Write(buf, binary.LittleEndian, pe.DllCharacteristics)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfStackReserve)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfStackCommit)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfHeapReserve)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfHeapCommit)
		binary.Write(buf, binary.LittleEndian, pe.LoaderFlags)
		binary.Write(buf, binary.LittleEndian, pe.NumberOfRvaAndSizes)
		for i := 0; i < 16; i++ {
			binary.Write(buf, binary.LittleEndian, pe.DataDirectory[i])
		}
	} else {
		binary.Write(buf, binary.LittleEndian, pe.Magic)
		buf.WriteByte(pe.MajorLinkerVersion)
		buf.WriteByte(pe.MinorLinkerVersion)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfCode)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfInitializedData)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfUninitializedData)
		binary.Write(buf, binary.LittleEndian, pe.AddressOfEntryPoint)
		binary.Write(buf, binary.LittleEndian, pe.BaseOfCode)
		binary.Write(buf, binary.LittleEndian, pe.BaseOfData)

		binary.Write(buf, binary.LittleEndian, uint32(pe.ImageBase))
		binary.Write(buf, binary.LittleEndian, pe.SectionAlignment)
		binary.Write(buf, binary.LittleEndian, pe.FileAlignment)
		binary.Write(buf, binary.LittleEndian, pe.MajorOperatingSystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.MinorOperatingSystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.MajorImageVersion)
		binary.Write(buf, binary.LittleEndian, pe.MinorImageVersion)
		binary.Write(buf, binary.LittleEndian, pe.MajorSubsystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.MinorSubsystemVersion)
		binary.Write(buf, binary.LittleEndian, pe.Win32VersionValue)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfImage)
		binary.Write(buf, binary.LittleEndian, pe.SizeOfHeaders)
		binary.Write(buf, binary.LittleEndian, pe.CheckSum)
		binary.Write(buf, binary.LittleEndian, pe.Subsystem)
		binary.Write(buf, binary.LittleEndian, pe.DllCharacteristics)
		binary.Write(buf, binary.LittleEndian, uint32(pe.SizeOfStackReserve))
		binary.Write(buf, binary.LittleEndian, uint32(pe.SizeOfStackCommit))
		binary.Write(buf, binary.LittleEndian, uint32(pe.SizeOfHeapReserve))
		binary.Write(buf, binary.LittleEndian, uint32(pe.SizeOfHeapCommit))
		binary.Write(buf, binary.LittleEndian, pe.LoaderFlags)
		binary.Write(buf, binary.LittleEndian, pe.NumberOfRvaAndSizes)
		for i := 0; i < 16; i++ {
			binary.Write(buf, binary.LittleEndian, pe.DataDirectory[i])
		}
	}
	return buf.Bytes(), nil
}

func (pe *PEHeader) SaveToStream(s io.WriteSeeker) error {
	pe.FileHeader.NumberOfSections = uint16(len(pe.Sections))
	pe.FileHeader.SizeOfOptionalHeader = 224
	if pe.Is64Bit {
		pe.FileHeader.SizeOfOptionalHeader = 240
	}
	pe.NumberOfRvaAndSizes = 16
	headerEnd := uint64(pe.LFANew) + 24 + uint64(pe.FileHeader.SizeOfOptionalHeader) + uint64(len(pe.Sections))*40
	firstRaw := uint64(pe.SizeOfHeaders)
	for _, section := range pe.Sections {
		if section.Header.SizeOfRawData != 0 && uint64(section.Header.PointerToRawData) < firstRaw {
			firstRaw = uint64(section.Header.PointerToRawData)
		}
	}
	if headerEnd > firstRaw {
		return fmt.Errorf("section table does not fit in PE headers")
	}
	if _, err := s.Seek(int64(pe.LFANew), io.SeekStart); err != nil {
		return err
	}
	ntBytes, err := pe.SerializeNTHeaders()
	if err != nil {
		return err
	}
	if _, err := s.Write(ntBytes); err != nil {
		return err
	}

	for _, sec := range pe.Sections {
		if err := binary.Write(s, binary.LittleEndian, sec.Header); err != nil {
			return err
		}
	}

	// Zero out leftovers
	zeroes := make([]byte, min(uint64(0x200), firstRaw-headerEnd))
	if _, err := s.Write(zeroes); err != nil {
		return err
	}
	return nil
}
