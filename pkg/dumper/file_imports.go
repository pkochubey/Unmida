package dumper

import (
	"encoding/binary"
	"unmida/pkg/pe"
	"unmida/pkg/winapi"
	"os"
	"strings"
)

func fileRVA(header *pe.PEHeader, data []byte, rva uint32, size uint32) []byte {
	var offset uint64
	if rva < header.SizeOfHeaders {
		offset = uint64(rva)
	} else {
		found := false
		for _, section := range header.Sections {
			h := section.Header
			if rva >= h.VirtualAddress && uint64(rva)-uint64(h.VirtualAddress)+uint64(size) <= uint64(h.SizeOfRawData) {
				offset = uint64(h.PointerToRawData) + uint64(rva) - uint64(h.VirtualAddress)
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	if offset+uint64(size) > uint64(len(data)) {
		return nil
	}
	return data[offset : offset+uint64(size)]
}

func fileString(header *pe.PEHeader, data []byte, rva uint32) string {
	bytes := make([]byte, 0, 64)
	for i := uint32(0); i < 4096; i++ {
		if rva+i < rva {
			return ""
		}
		current := fileRVA(header, data, rva+i, 1)
		if current == nil {
			return ""
		}
		if current[0] == 0 {
			return string(bytes)
		}
		bytes = append(bytes, current[0])
	}
	return ""
}

func (d *Dumper) collectUser32Forwards(module *RemoteModule, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	header, err := pe.ParsePEHeader(data)
	if err != nil {
		return
	}
	directory := header.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if directory.VirtualAddress == 0 {
		return
	}
	exports := fileRVA(header, data, directory.VirtualAddress, 40)
	if exports == nil {
		return
	}
	count := binary.LittleEndian.Uint32(exports[20:24])
	table := binary.LittleEndian.Uint32(exports[28:32])
	if uint64(count)*4 > uint64(len(data)) {
		return
	}
	for i := uint32(0); i < count; i++ {
		entry := fileRVA(header, data, table+i*4, 4)
		if entry == nil {
			return
		}
		address := binary.LittleEndian.Uint32(entry)
		if address > directory.VirtualAddress && uint64(address) < uint64(directory.VirtualAddress)+uint64(directory.Size) {
			name := fileString(header, data, address)
			if name != "" && !strings.Contains(name, ".#") {
				module.Forwards = append(module.Forwards, Forward{Key: name})
			}
		}
	}
}
