package patcher

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"unmida/pkg/dumper"
	"unmida/pkg/log"
	"unmida/pkg/pe"
	"unmida/pkg/utils"
	"unmida/pkg/winapi"
)

type Patcher struct {
	FileName string
	Data     []byte
	PE       *pe.PEHeader
}

func NewPatcher(fileName string) (*Patcher, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	peHeader, err := pe.ParsePEHeader(data)
	if err != nil {
		return nil, err
	}
	return &Patcher{
		FileName: fileName,
		Data:     data,
		PE:       peHeader,
	}, nil
}

func (p *Patcher) ProcessShrink() error {
	if err := p.shrinkPE(); err != nil {
		return err
	}
	p.shrinkExportSect()

	return p.save()
}

func (p *Patcher) shrinkPE() error {
	firstRaw := p.PE.Sections[0].Header.PointerToRawData
	if uint64(firstRaw) > uint64(len(p.Data)) {
		return fmt.Errorf("invalid first section offset")
	}
	data := bytes.NewBuffer(append([]byte(nil), p.Data[:firstRaw]...))
	sections := make([]*pe.PESection, 0, len(p.PE.Sections))
	for i, section := range p.PE.Sections {
		referenced := false
		for directoryIndex, directory := range p.PE.DataDirectory {
			if directoryIndex == winapi.IMAGE_DIRECTORY_ENTRY_SECURITY || directory.VirtualAddress == 0 || directory.Size == 0 {
				continue
			}
			if uint64(directory.VirtualAddress) >= uint64(section.Header.VirtualAddress) && uint64(directory.VirtualAddress)+uint64(directory.Size) <= uint64(section.Header.VirtualAddress)+uint64(section.Header.VirtualSize) {
				referenced = true
				break
			}
		}
		keep := i == 0 || referenced || section.Header.SectionName() == ".data" || section.Header.SectionName() == ".rdata"
		if !keep {
			if len(sections) != 0 {
				previous := sections[len(sections)-1]
				end := uint64(section.Header.VirtualAddress) + uint64(section.Header.VirtualSize)
				if end > uint64(previous.Header.VirtualAddress) && end <= 0xFFFFFFFF {
					previous.Header.VirtualSize = uint32(end) - previous.Header.VirtualAddress
					p.PE.SectionAlign(&previous.Header.VirtualSize)
				}
			}
			continue
		}
		start := uint64(section.Header.PointerToRawData)
		end := start + uint64(section.Header.SizeOfRawData)
		if i+1 < len(p.PE.Sections) && uint64(p.PE.Sections[i+1].Header.PointerToRawData) >= end {
			end = uint64(p.PE.Sections[i+1].Header.PointerToRawData)
		}
		if i == len(p.PE.Sections)-1 {
			end = uint64(len(p.Data))
		}
		if start > end || end > uint64(len(p.Data)) {
			return fmt.Errorf("invalid section data for %s", section.Header.SectionName())
		}
		section.Header.PointerToRawData = uint32(data.Len())
		data.Write(p.Data[start:end])
		sections = append(sections, section)
	}
	p.PE.Sections = sections
	p.PE.FileHeader.NumberOfSections = uint16(len(sections))
	p.PE.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_SECURITY] = pe.ImageDataDirectory{}
	p.Data = data.Bytes()
	return nil
}

func (p *Patcher) shrinkExportSect() {
	exportDir := &p.PE.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return
	}
	ehSec := p.PE.GetSectionByVA(exportDir.VirtualAddress)
	if ehSec == nil {
		return
	}
	eh := &ehSec.Header

	pBase := int(eh.PointerToRawData)
	pExp := pBase + int(exportDir.VirtualAddress-eh.VirtualAddress)

	if exportDir.Size < 40 || exportDir.Size > 0x1000 || eh.SizeOfRawData < 0x1000 || pExp < 0 || uint64(pExp)+uint64(exportDir.Size) > uint64(len(p.Data)) || uint64(pBase)+uint64(eh.SizeOfRawData) > uint64(len(p.Data)) {
		return
	}

	copy(p.Data[pBase:pBase+int(exportDir.Size)], p.Data[pExp:pExp+int(exportDir.Size)])
	if pBase+0x1000 <= len(p.Data) {
		for j := pBase + int(exportDir.Size); j < pBase+0x1000; j++ {
			p.Data[j] = 0
		}
	}
	exportDir.VirtualAddress = eh.VirtualAddress

	diff := uint32(pExp - pBase)
	// Update export directory struct in place
	// Name: offset 0x0C
	// AddressOfFunctions: offset 0x1C
	// AddressOfNames: offset 0x20
	// AddressOfNameOrdinals: offset 0x24
	nameRVA := binary.LittleEndian.Uint32(p.Data[pBase+0x0C : pBase+0x10])
	binary.LittleEndian.PutUint32(p.Data[pBase+0x0C:pBase+0x10], nameRVA-diff)

	funcsRVA := binary.LittleEndian.Uint32(p.Data[pBase+0x1C : pBase+0x20])
	binary.LittleEndian.PutUint32(p.Data[pBase+0x1C:pBase+0x20], funcsRVA-diff)

	namesRVA := binary.LittleEndian.Uint32(p.Data[pBase+0x20 : pBase+0x24])
	binary.LittleEndian.PutUint32(p.Data[pBase+0x20:pBase+0x24], namesRVA-diff)

	ordsRVA := binary.LittleEndian.Uint32(p.Data[pBase+0x24 : pBase+0x28])
	binary.LittleEndian.PutUint32(p.Data[pBase+0x24:pBase+0x28], ordsRVA-diff)

	numNames := binary.LittleEndian.Uint32(p.Data[pBase+0x18 : pBase+0x1C])
	namesTableOff := pBase + int(namesRVA-diff-eh.VirtualAddress)

	for i := uint32(0); i < numNames; i++ {
		off := namesTableOff + int(i*4)
		if off >= pBase && off+4 <= pBase+int(exportDir.Size) {
			nRVA := binary.LittleEndian.Uint32(p.Data[off : off+4])
			binary.LittleEndian.PutUint32(p.Data[off:off+4], nRVA-diff)
		}
	}

	count := binary.LittleEndian.Uint32(p.Data[pBase+20 : pBase+24])
	functionOffset := pBase + int(funcsRVA-diff-eh.VirtualAddress)
	oldExportStart := exportDir.VirtualAddress + diff
	for i := uint32(0); i < count; i++ {
		offset := functionOffset + int(i)*4
		if offset < pBase || offset+4 > pBase+int(exportDir.Size) {
			break
		}
		value := binary.LittleEndian.Uint32(p.Data[offset : offset+4])
		if value >= oldExportStart && uint64(value) < uint64(oldExportStart)+uint64(exportDir.Size) {
			binary.LittleEndian.PutUint32(p.Data[offset:offset+4], value-diff)
		}
	}

	sizeDiff := eh.SizeOfRawData - 0x1000
	eh.SizeOfRawData -= sizeDiff

	for i := 0; i < len(p.PE.Sections); i++ {
		if p.PE.Sections[i].Header.VirtualAddress > eh.VirtualAddress {
			p.PE.Sections[i].Header.PointerToRawData -= sizeDiff
		}
	}

	ehSec.Rename(".export")
	eh.Characteristics &^= (winapi.IMAGE_SCN_MEM_WRITE | winapi.IMAGE_SCN_MEM_EXECUTE)

	// Truncate stream
	newData := new(bytes.Buffer)
	newData.Write(p.Data[:eh.PointerToRawData+0x1000])
	remainderStart := int(eh.PointerToRawData + 0x1000 + sizeDiff)
	if remainderStart <= len(p.Data) {
		newData.Write(p.Data[remainderStart:])
	}
	p.Data = newData.Bytes()
}

func (p *Patcher) ProcessMkData() error {
	lower := strings.ToLower(p.FileName)
	posMS := strings.LastIndex(lower, "maplestory")
	if posMS >= 0 && strings.Index(lower[posMS:], ".exe") < 20 {
		if err := p.mapleCreateDataSections(); err != nil {
			return err
		}
	} else if p.PE.MajorLinkerVersion == 14 { // MSVC 2015+
		if err := p.msvcCreateDataSections(); err != nil {
			return err
		}
	} else {
		log.Infof("Data section creation not available for this compiler.")
		return nil
	}

	return p.save()
}

func (p *Patcher) mapleCreateDataSections() error {
	if len(p.PE.Sections) < 2 {
		return fmt.Errorf("data section creation requires at least two sections")
	}
	mem := p.Data
	dataStart := -1

	if len(mem) > 0x2000000 {
		off := utils.FindStatic("10000000200000004000000060000000", mem[0x2000000:])
		if off >= 0 {
			dataStart = 0x2000000 + off
		}
	}

	if dataStart == -1 {
		if p.PE.MajorLinkerVersion == 6 {
			dataStart = p.findDataStartMSVC6()
			if dataStart == -1 {
				return fmt.Errorf("data section not found")
			}
		} else {
			baseSearch := 0xB00000 - 0x400000
			if len(mem) > baseSearch {
				d1 := utils.FindStatic("2E3F41565F636F6D5F6572726F724040", mem[baseSearch:])
				dTW := utils.FindStatic("2E3F41563F245A4C69737440554D4150494E464F4043416374696F6E4672616D6540404040", mem[baseSearch:])
				if dTW >= 0 && (d1 < 0 || dTW < d1) {
					d1 = dTW
				}
				if d1 < 0 {
					return fmt.Errorf("data section not found")
				}
				dataStart = d1 + (baseSearch - 8)
				if (dataStart&0xFFF) == 0xB4 || (dataStart&0xFFF) == 0xF8 || (dataStart&0xFFF) == 0xFC {
					dataStart &= ^0xFFF
				}
				log.Infof("Old executable")
			}
		}
	}

	if dataStart == -1 || (dataStart&0xFFF) != 0 {
		return fmt.Errorf("data section bytes found, but not aligned: 0x%X", dataStart)
	}

	log.Goodf(".data section at 0x%08X (VA 0x%08X)", dataStart, dataStart+0x400000)

	// Add 2 sections: .rdata and .data
	p.PE.Sections = append(p.PE.Sections, &pe.PESection{}, &pe.PESection{})
	for i := len(p.PE.Sections) - 1; i >= 3; i-- {
		p.PE.Sections[i] = p.PE.Sections[i-2]
	}

	zEnd := 0
	zSize := 0
	lock := false
	limit := int(p.PE.Sections[3].Header.PointerToRawData)
	if limit < dataStart || limit > len(mem) {
		return fmt.Errorf("invalid data section range")
	}

	for a := limit - 1; a >= dataStart; a-- {
		if mem[a] == 0 {
			if zSize == 0 {
				zEnd = a + 1
			}
			zSize++
			if zSize > 0x2000 {
				lock = true
			}
		} else {
			if lock {
				break
			}
			zSize = 0
		}
	}

	if zSize == 0 {
		return fmt.Errorf("data section doesn't contain zeroes")
	}

	if (zEnd & 0xFFF) == 1 {
		zEnd--
		zSize--
	}
	if (zEnd & 0xFFF) != 0 {
		return fmt.Errorf("real .data section end not found (got 0x%X with size 0x%X)", zEnd, zSize)
	}

	gfidsSize := limit - zEnd

	// .data at index 2
	dataSize := uint32(limit - dataStart - gfidsSize)
	secData := &pe.PESection{}
	secData.Rename(".data")
	secData.Header.VirtualSize = dataSize
	secData.Header.VirtualAddress = uint32(dataStart)
	secData.Header.PointerToRawData = uint32(dataStart)
	secData.Header.SizeOfRawData = dataSize - uint32(zSize)
	secData.Header.Characteristics = winapi.IMAGE_SCN_MEM_READ | winapi.IMAGE_SCN_MEM_WRITE | winapi.IMAGE_SCN_CNT_INITIALIZED_DATA
	p.PE.Sections[2] = secData

	// .rdata at index 1
	rdataStart := p.PE.BaseOfData
	rdataSize := uint32(dataStart) - rdataStart
	secRData := &pe.PESection{}
	secRData.Rename(".rdata")
	secRData.Header.VirtualSize = rdataSize
	secRData.Header.VirtualAddress = rdataStart
	secRData.Header.PointerToRawData = rdataStart
	secRData.Header.SizeOfRawData = rdataSize
	secRData.Header.Characteristics = winapi.IMAGE_SCN_MEM_READ | winapi.IMAGE_SCN_CNT_INITIALIZED_DATA
	p.PE.Sections[1] = secRData

	// .gfids / .vmp
	if gfidsSize != 0 {
		p.PE.Sections = append(p.PE.Sections, &pe.PESection{})
		for i := len(p.PE.Sections) - 1; i >= 4; i-- {
			p.PE.Sections[i] = p.PE.Sections[i-1]
		}
		secGfids := &pe.PESection{}
		if p.PE.MajorLinkerVersion >= 14 {
			secGfids.Rename(".gfids")
		} else {
			secGfids.Rename(".vmp")
		}
		secGfids.Header.VirtualSize = uint32(gfidsSize)
		secGfids.Header.VirtualAddress = uint32(zEnd)
		secGfids.Header.PointerToRawData = uint32(zEnd)
		secGfids.Header.SizeOfRawData = uint32(gfidsSize)
		secGfids.Header.Characteristics = winapi.IMAGE_SCN_MEM_READ | winapi.IMAGE_SCN_MEM_WRITE | winapi.IMAGE_SCN_CNT_INITIALIZED_DATA
		p.PE.Sections[3] = secGfids

		p.PE.FileHeader.NumberOfSections += 3
	} else {
		if p.PE.MajorLinkerVersion >= 14 {
			log.Fatalf(".gfids not found")
		}
		p.PE.FileHeader.NumberOfSections += 2
	}

	p.PE.Sections[0].Header.VirtualSize -= (rdataSize + dataSize + uint32(gfidsSize))
	p.PE.Sections[0].Header.SizeOfRawData -= (rdataSize + dataSize + uint32(gfidsSize))
	p.PE.Sections[0].Rename(".text")
	p.PE.Sections[0].Header.Characteristics &^= winapi.IMAGE_SCN_MEM_WRITE

	return nil
}

func (p *Patcher) findDataStartMSVC6() int {
	if len(p.Data) <= 0x100000 {
		return -1
	}
	off := utils.FindDynamic("68????????68??????00E8????????83C410C3", p.Data[0x100000:])
	if off < 0 {
		return -1
	}
	cinitCode := 0x100000 + off
	res := binary.LittleEndian.Uint32(p.Data[cinitCode+6 : cinitCode+10])
	if (res & 0xFFF) != 0 {
		return -1
	}
	return int(res - uint32(p.PE.ImageBase))
}

func (p *Patcher) findDynTLSMSVC14() (uint32, bool) {
	if len(p.Data) <= 0x1000 {
		return 0, false
	}
	off := utils.FindDynamic("8BF033FF393E74??56E8", p.Data[0x1000:])
	if off < 0 {
		log.Infof("DynTLS code sequence not found.")
		return 0, false
	}

	codePtr := 0x1000 + off
	if p.Data[codePtr-5] != 0xE8 {
		log.Infof("DynTLS code sequence mismatch.")
		return 0, false
	}

	relCall := int32(binary.LittleEndian.Uint32(p.Data[codePtr-4 : codePtr]))
	getPtrFunc := codePtr + int(relCall)
	if getPtrFunc < 0 || getPtrFunc >= len(p.Data) {
		return 0, false
	}

	if p.Data[getPtrFunc] == 0xE9 {
		if getPtrFunc+5 > len(p.Data) {
			return 0, false
		} // jmp indirection
		relJmp := int32(binary.LittleEndian.Uint32(p.Data[getPtrFunc+1 : getPtrFunc+5]))
		getPtrFunc = getPtrFunc + int(relJmp) + 5
	}

	if getPtrFunc < 0 || getPtrFunc+5 > len(p.Data) || p.Data[getPtrFunc] != 0xB8 {
		log.Infof("DynTLS call analysis failed.")
		return 0, false
	}

	val := binary.LittleEndian.Uint32(p.Data[getPtrFunc+1 : getPtrFunc+5])
	dynTLSInit := val - uint32(p.PE.ImageBase)

	if uint64(dynTLSInit)+4 <= uint64(len(p.Data)) {
		targetVal := binary.LittleEndian.Uint32(p.Data[dynTLSInit : dynTLSInit+4])
		log.Infof("[MSVC] dyn_tls_init at 0x%08X", targetVal)
		if targetVal == 0 {
			dynTLSInit = 0
		}
	}

	return dynTLSInit, true
}

func (p *Patcher) msvcCreateDataSections() error {
	baseOfData := p.PE.BaseOfData
	firstSec := p.PE.Sections[0]
	if len(p.PE.Sections) < 2 {
		return fmt.Errorf("data section creation requires at least two sections")
	}

	if baseOfData > firstSec.Header.VirtualAddress &&
		baseOfData < firstSec.Header.VirtualAddress+firstSec.Header.VirtualSize &&
		(baseOfData&0xFFF) == 0 {

		dynTLS, ok := p.findDynTLSMSVC14()
		if !ok {
			return nil
		}

		var dataStart uint32
		if dynTLS != 0 {
			dataStart = (dynTLS + 0x1000) & ^uint32(0xFFF)
		} else {
			dataStart = baseOfData + 0x1000
			log.Infof("Setting .rdata size to just 1000 (no reference point for actual size)")
		}

		if dataStart >= p.PE.Sections[1].Header.PointerToRawData {
			return fmt.Errorf("data section start exceeds merged section")
		}
		p.PE.Sections = append(p.PE.Sections, &pe.PESection{}, &pe.PESection{})
		for i := len(p.PE.Sections) - 1; i >= 3; i-- {
			p.PE.Sections[i] = p.PE.Sections[i-2]
		}
		p.PE.FileHeader.NumberOfSections += 2

		// .data at index 2
		dataSize := p.PE.Sections[3].Header.PointerToRawData - dataStart
		secData := &pe.PESection{}
		secData.Rename(".data")
		secData.Header.VirtualSize = dataSize
		secData.Header.VirtualAddress = dataStart
		secData.Header.PointerToRawData = dataStart
		secData.Header.SizeOfRawData = dataSize
		secData.Header.Characteristics = winapi.IMAGE_SCN_MEM_READ | winapi.IMAGE_SCN_MEM_WRITE | winapi.IMAGE_SCN_CNT_INITIALIZED_DATA
		p.PE.Sections[2] = secData

		// .rdata at index 1
		rdataStart := baseOfData
		rdataSize := dataStart - rdataStart
		secRData := &pe.PESection{}
		secRData.Rename(".rdata")
		secRData.Header.VirtualSize = rdataSize
		secRData.Header.VirtualAddress = rdataStart
		secRData.Header.PointerToRawData = rdataStart
		secRData.Header.SizeOfRawData = rdataSize
		secRData.Header.Characteristics = winapi.IMAGE_SCN_MEM_READ | winapi.IMAGE_SCN_CNT_INITIALIZED_DATA
		p.PE.Sections[1] = secRData

		p.PE.Sections[0].Header.VirtualSize -= (rdataSize + dataSize)
		p.PE.Sections[0].Header.SizeOfRawData -= (rdataSize + dataSize)

		log.Infof(".text : 0x%08X ~ 0x%08X", p.PE.Sections[0].Header.VirtualAddress, p.PE.Sections[0].Header.VirtualAddress+p.PE.Sections[0].Header.VirtualSize)
		log.Infof(".rdata: 0x%08X ~ 0x%08X", p.PE.Sections[1].Header.VirtualAddress, p.PE.Sections[1].Header.VirtualAddress+p.PE.Sections[1].Header.VirtualSize)
		log.Infof(".data : 0x%08X ~ 0x%08X", p.PE.Sections[2].Header.VirtualAddress, p.PE.Sections[2].Header.VirtualAddress+p.PE.Sections[2].Header.VirtualSize)
	} else {
		log.Infof("Assuming sections are not merged.")
	}

	p.PE.Sections[0].Rename(".text")
	p.PE.Sections[0].Header.Characteristics &^= winapi.IMAGE_SCN_MEM_WRITE

	return nil
}

func DumpProcessCode(pid uint32, fileName string) error {
	hProcess, err := winapi.OpenProcess(winapi.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess failed for PID %d: %w", pid, err)
	}
	defer winapi.CloseHandle(hProcess)

	patch, err := NewPatcher(fileName)
	if err != nil {
		return err
	}

	if patch.PE.Is64Bit {
		return fmt.Errorf("process code dumping requires PE32")
	}
	section := patch.PE.Sections[0].Header
	codeSize := section.VirtualSize
	if patch.PE.BaseOfData > section.VirtualAddress {
		codeSize = patch.PE.BaseOfData - section.VirtualAddress
	}
	if uint64(section.PointerToRawData)+uint64(codeSize) > uint64(len(patch.Data)) {
		return fmt.Errorf("code exceeds file section")
	}
	snapshot, err := winapi.CreateToolhelp32Snapshot(winapi.TH32CS_SNAPMODULE|winapi.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return err
	}
	defer winapi.CloseHandle(snapshot)
	var module winapi.MODULEENTRY32W
	if err := winapi.Module32First(snapshot, &module); err != nil {
		return err
	}
	startAddr := module.ModBaseAddr + uintptr(section.VirtualAddress)
	size := uintptr(codeSize)

	buf := make([]byte, size)
	if _, err := winapi.ReadProcessMemory(hProcess, startAddr, buf); err != nil {
		return fmt.Errorf("ReadProcessMemory failed: %w", err)
	}

	rawStart := int(patch.PE.Sections[0].Header.PointerToRawData)
	if rawStart+int(size) > len(patch.Data) {
		return fmt.Errorf("buffer overflow writing process code")
	}

	copy(patch.Data[rawStart:rawStart+int(size)], buf)

	outPath := dumper.ChangeFileExt(fileName, ".novm.exe")
	if err := os.WriteFile(outPath, patch.Data, 0755); err != nil {
		return fmt.Errorf("writing output file failed: %w", err)
	}

	log.Goodf("Dumped 0x%X bytes to %s", size, filepath.Base(outPath))
	return nil
}

func (p *Patcher) save() error {
	file, err := os.CreateTemp(filepath.Dir(p.FileName), ".unmida-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()
	if _, err = file.Write(p.Data); err != nil {
		return err
	}
	if err = p.PE.SaveToStream(file); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, p.FileName); err != nil {
		return err
	}
	log.Goodf("Saved %s", p.FileName)
	return nil
}
