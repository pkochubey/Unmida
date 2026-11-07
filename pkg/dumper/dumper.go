package dumper

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"unmida/pkg/debugger"
	"unmida/pkg/log"
	"unmida/pkg/onecoreuap"
	"unmida/pkg/pe"
	"unmida/pkg/winapi"
)

const maxIATSize = 5120 * 8 // up to 5K imports

var forwardPreferences = []string{
	"kernel32.dll", // prioritize over kernelbase/ntdll
	"ole32.dll",    // prioritize over combase
	"advapi32.dll", // prioritize over cryptbase
	"netapi32.dll", // prioritize over netutils
	"comdlg32.dll", // prioritize over shlwapi
	"crypt32.dll",  // prioritize over dpapi
	"gdi32.dll",    // prioritize over gdi32full
	"dbghelp.dll",  // prioritize over dbgcore
	"setupapi.dll", // prioritize over cfgmgr32
}

func preferenceScore(name string) int {
	score := 0
	lower := strings.ToLower(name)
	for _, p := range forwardPreferences {
		if lower == p {
			score++
		}
	}
	return score
}

type Forward struct {
	Key   string
	Value uintptr
}

type RemoteModule struct {
	Base         uintptr
	EndOff       uintptr
	Name         string
	ExportTbl    map[uintptr]string
	ExportByName map[string]uintptr
	Forwards     []Forward
}

type ForwardOrigin struct {
	SourceModule  *RemoteModule
	SourceAddress uintptr
}

type ImportThunk struct {
	Module    *RemoteModule
	Name      string
	Addresses []int // indices into IAT slots
}

type OriginalImport struct {
	DLLName  string
	FuncName string
}

type ResolutionCandidate struct {
	Address uintptr
	Module  *RemoteModule
}

type IATSlot struct {
	OriginalValue   uint64
	Candidates      []ResolutionCandidate
	ChosenCandidate int
	IsZero          bool
}

type Dumper struct {
	OutputFile      string
	ProcessHandle   syscall.Handle
	ProcessID       uint32
	OriginalFile    string
	ImageBase       uintptr
	OEP             uintptr
	IAT             uintptr
	Is64Bit         bool
	PtrSize         int
	AllModules      []*RemoteModule
	Forwards        map[uintptr][]ForwardOrigin
	IATImage        []byte
	OriginalImports []OriginalImport
}

func NewDumper(hProcess syscall.Handle, pid uint32, origFile string, imageBase, oep uintptr, is64Bit bool) *Dumper {
	ptrSize := 4
	if is64Bit {
		ptrSize = 8
	}
	d := &Dumper{
		ProcessHandle: hProcess,
		ProcessID:     pid,
		OriginalFile:  origFile,
		ImageBase:     imageBase,
		OEP:           oep,
		Is64Bit:       is64Bit,
		PtrSize:       ptrSize,
		Forwards:      make(map[uintptr][]ForwardOrigin),
	}
	d.OriginalImports = d.getOriginalImports(origFile)
	return d
}

func (d *Dumper) RPM(addr uintptr, buf []byte) bool {
	_, err := winapi.ReadProcessMemory(d.ProcessHandle, addr, buf)
	return err == nil
}

func (d *Dumper) IsAPIAddress(addr uintptr) bool {
	if d.AllModules == nil {
		if err := d.TakeModuleSnapshot(); err != nil {
			log.Fatalf("TakeModuleSnapshot error: %v", err)
			return false
		}
	}
	for _, rm := range d.AllModules {
		if addr >= rm.Base && addr < rm.EndOff {
			if _, ok := rm.ExportTbl[addr]; ok {
				return true
			}
		}
	}
	return false
}

func (d *Dumper) GetRemoteModule(name string) *RemoteModule {
	lower := strings.ToLower(name)
	for _, rm := range d.AllModules {
		if rm.Name == lower {
			return rm
		}
	}
	return nil
}

func (d *Dumper) GetRemoteModuleByBase(base uintptr) *RemoteModule {
	for _, rm := range d.AllModules {
		if rm.Base == base {
			return rm
		}
	}
	return nil
}

func (d *Dumper) TakeModuleSnapshot() error {
	d.AllModules = nil
	d.Forwards = make(map[uintptr][]ForwardOrigin)

	flags := uint32(winapi.TH32CS_SNAPMODULE | winapi.TH32CS_SNAPMODULE32)
	hSnap, err := winapi.CreateToolhelp32Snapshot(flags, d.ProcessID)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer winapi.CloseHandle(hSnap)

	var me winapi.MODULEENTRY32W
	if err := winapi.Module32First(hSnap, &me); err != nil {
		return fmt.Errorf("Module32First failed: %w", err)
	}

	for {
		if me.ModBaseAddr != d.ImageBase {
			modName := syscall.UTF16ToString(me.SzModule[:])
			rm := &RemoteModule{
				Base:         me.ModBaseAddr,
				EndOff:       me.ModBaseAddr + uintptr(me.ModBaseSize),
				Name:         strings.ToLower(modName),
				ExportTbl:    make(map[uintptr]string),
				ExportByName: make(map[string]uintptr),
			}
			d.gatherModuleExportsFromRemoteProcess(rm)
			if !d.Is64Bit && rm.Name == "user32.dll" {
				d.collectUser32Forwards(rm, syscall.UTF16ToString(me.SzExePath[:]))
			}
			d.AllModules = append(d.AllModules, rm)
		}
		if err := winapi.Module32Next(hSnap, &me); err != nil {
			break
		}
	}

	for _, rm := range d.AllModules {
		d.resolveForwards(rm)
	}

	return nil
}

func (d *Dumper) gatherModuleExportsFromRemoteProcess(rm *RemoteModule) {
	var head [0x1000]byte
	if !d.RPM(rm.Base, head[:]) {
		return
	}
	if head[0] != 'M' || head[1] != 'Z' {
		return
	}
	lfanew := binary.LittleEndian.Uint32(head[0x3C:0x40])
	if int(lfanew)+0x88 > len(head) {
		return
	}

	sig := binary.LittleEndian.Uint32(head[lfanew : lfanew+4])
	if sig != 0x00004550 {
		return
	}

	magic := binary.LittleEndian.Uint16(head[lfanew+24 : lfanew+26])
	var expRVA, expSize uint32
	if magic == 0x20B { // PE64
		// Export table data directory is at OptionalHeader + 112 (offset lfanew + 24 + 112 = lfanew + 136)
		expOffset := lfanew + 24 + 112
		if int(expOffset)+8 <= len(head) {
			expRVA = binary.LittleEndian.Uint32(head[expOffset : expOffset+4])
			expSize = binary.LittleEndian.Uint32(head[expOffset+4 : expOffset+8])
		}
	} else if magic == 0x10B { // PE32
		expOffset := lfanew + 24 + 96
		if int(expOffset)+8 <= len(head) {
			expRVA = binary.LittleEndian.Uint32(head[expOffset : expOffset+4])
			expSize = binary.LittleEndian.Uint32(head[expOffset+4 : expOffset+8])
		}
	}

	if expRVA == 0 || expSize < 40 || uint64(expRVA)+uint64(expSize) > uint64(rm.EndOff-rm.Base) {
		return
	}

	expBuf := make([]byte, expSize)
	if !d.RPM(rm.Base+uintptr(expRVA), expBuf) {
		return
	}

	numFuncs := binary.LittleEndian.Uint32(expBuf[0x14:0x18])
	numNames := binary.LittleEndian.Uint32(expBuf[0x18:0x1C])
	addrOfFuncsRVA := binary.LittleEndian.Uint32(expBuf[0x1C:0x20])
	addrOfNamesRVA := binary.LittleEndian.Uint32(expBuf[0x20:0x24])
	addrOfOrdinalsRVA := binary.LittleEndian.Uint32(expBuf[0x24:0x28])
	baseOrdinal := binary.LittleEndian.Uint32(expBuf[0x10:0x14])

	if uint64(numFuncs)*4 > uint64(len(expBuf)) || uint64(numNames)*4 > uint64(len(expBuf)) {
		return
	}
	named := make([]bool, numFuncs)

	for i := uint32(0); i < numNames; i++ {
		ordRelOff := (addrOfOrdinalsRVA - expRVA) + i*2
		nameRelOff := (addrOfNamesRVA - expRVA) + i*4

		if uint64(ordRelOff)+2 > uint64(len(expBuf)) || uint64(nameRelOff)+4 > uint64(len(expBuf)) {
			break
		}

		funcIndex := binary.LittleEndian.Uint16(expBuf[ordRelOff : ordRelOff+2])
		if uint32(funcIndex) >= numFuncs {
			continue
		}
		nameRVA := binary.LittleEndian.Uint32(expBuf[nameRelOff : nameRelOff+4])

		if int(funcIndex) < len(named) {
			named[funcIndex] = true
		}

		nameStrOff := nameRVA - expRVA
		var nameBytes []byte
		if uint64(nameStrOff) < uint64(len(expBuf)) {
			for j := int(nameStrOff); j < len(expBuf); j++ {
				if expBuf[j] == 0 {
					break
				}
				nameBytes = append(nameBytes, expBuf[j])
			}
		}

		funcRelOff := (addrOfFuncsRVA - expRVA) + uint32(funcIndex)*4
		if uint64(funcRelOff)+4 <= uint64(len(expBuf)) {
			funcRVA := binary.LittleEndian.Uint32(expBuf[funcRelOff : funcRelOff+4])
			if len(nameBytes) > 0 && funcRVA != 0 {
				rm.ExportTbl[rm.Base+uintptr(funcRVA)] = string(nameBytes)
				rm.ExportByName[string(nameBytes)] = rm.Base + uintptr(funcRVA)
			}
		}
	}

	for i := uint32(0); i < numFuncs; i++ {
		funcRelOff := (addrOfFuncsRVA - expRVA) + i*4
		if uint64(funcRelOff)+4 > uint64(len(expBuf)) {
			break
		}
		funcRVA := binary.LittleEndian.Uint32(expBuf[funcRelOff : funcRelOff+4])
		if funcRVA == 0 {
			continue
		}
		funcAddr := rm.Base + uintptr(funcRVA)

		if !named[i] {
			rm.ExportTbl[funcAddr] = "#" + strconv.Itoa(int(baseOrdinal+i))
		}
		rm.ExportByName["#"+strconv.Itoa(int(baseOrdinal+i))] = funcAddr

		// Check if forwarder
		if funcRVA > expRVA && funcRVA < expRVA+expSize {
			fwdOff := funcRVA - expRVA
			var fwdBytes []byte
			for j := int(fwdOff); j < len(expBuf); j++ {
				if expBuf[j] == 0 {
					break
				}
				fwdBytes = append(fwdBytes, expBuf[j])
			}
			fwdStr := string(fwdBytes)
			if fwdStr != "" {
				rm.Forwards = append(rm.Forwards, Forward{Key: fwdStr, Value: funcAddr})
			}
		}
	}
}

func (d *Dumper) forwardModule(name string) *RemoteModule {
	if !strings.HasSuffix(strings.ToLower(name), ".dll") {
		name += ".dll"
	}
	if module := d.GetRemoteModule(name); module != nil {
		return module
	}
	lower := strings.ToLower(name)
	if !strings.HasPrefix(lower, "api-ms-win-") && !strings.HasPrefix(lower, "ext-ms-win-") {
		return nil
	}
	handle, err := winapi.GetModuleHandle(name)
	if err != nil {
		handle, err = winapi.LoadLibrary(name)
		if err != nil {
			return nil
		}
		defer winapi.FreeLibrary(handle)
	}
	return d.GetRemoteModuleByBase(uintptr(handle))
}

func (d *Dumper) finalExport(module *RemoteModule, name string, depth int) uintptr {
	if module == nil || depth > 16 {
		return 0
	}
	address := module.ExportByName[name]
	if address == 0 {
		return 0
	}
	for _, forward := range module.Forwards {
		if forward.Value == address {
			split := strings.LastIndexByte(forward.Key, '.')
			if split < 1 {
				return 0
			}
			return d.finalExport(d.forwardModule(forward.Key[:split]), forward.Key[split+1:], depth+1)
		}
	}
	return address
}

func (d *Dumper) resolveForwards(module *RemoteModule) {
	for _, forward := range module.Forwards {
		split := strings.LastIndexByte(forward.Key, '.')
		if split < 1 {
			continue
		}
		address := d.finalExport(d.forwardModule(forward.Key[:split]), forward.Key[split+1:], 0)
		if handle, err := winapi.GetModuleHandle(module.Name); err == nil && uintptr(handle) == module.Base {
			symbol := module.ExportTbl[forward.Value]
			if !strings.HasPrefix(symbol, "#") {
				if resolved, err := winapi.GetProcAddress(handle, symbol); err == nil {
					address = resolved
				}
			}
		}
		if address == 0 {
			continue
		}
		source := forward.Value
		if !d.Is64Bit && module.Name == "user32.dll" {
			source = address
		}
		d.Forwards[address] = append(d.Forwards[address], ForwardOrigin{SourceModule: module, SourceAddress: source})
	}
}

func (d *Dumper) DetermineIATSize(iatBuf []byte) uint32 {
	lastValidOffset := uint32(0)
	ptrSize := d.PtrSize
	limit := 5120 * d.PtrSize
	if len(iatBuf) < limit {
		limit = len(iatBuf)
	}

	for i := 0; i < limit; i += ptrSize {
		if lastValidOffset != 0 && uint32(i) >= lastValidOffset+0x100 {
			break
		}
		var val uintptr
		if d.Is64Bit {
			val = uintptr(binary.LittleEndian.Uint64(iatBuf[i : i+8]))
		} else {
			val = uintptr(binary.LittleEndian.Uint32(iatBuf[i : i+4]))
		}

		if d.IsAPIAddress(val) {
			lastValidOffset = uint32(i)
		}
	}

	return lastValidOffset + uint32(ptrSize)
}

func (d *Dumper) Process() (*pe.PEHeader, error) {
	if d.IAT == 0 {
		return nil, fmt.Errorf("must set IAT before calling Process()")
	}

	// Read header from memory
	var secBuf [0x1000]byte
	if !d.RPM(d.ImageBase, secBuf[:]) {
		return nil, fmt.Errorf("reading PE header failed")
	}
	peHeader, err := pe.ParsePEHeader(secBuf[:])
	if err != nil {
		return nil, fmt.Errorf("parsing PE header failed: %w", err)
	}
	peHeader.Sanitize()

	iatData := make([]byte, 5120*d.PtrSize)
	if !d.RPM(d.IAT, iatData) {
		return nil, fmt.Errorf("reading IAT failed")
	}

	iatSize := d.DetermineIATSize(iatData)
	log.Infof("Determined IAT size: 0x%X", iatSize)

	peHeader.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = uint32(d.IAT - d.ImageBase)
	peHeader.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_IAT].Size = iatSize + uint32(d.PtrSize)

	if d.AllModules == nil {
		if err := d.TakeModuleSnapshot(); err != nil {
			return nil, err
		}
	}

	allowApiSets := false
	for _, oi := range d.OriginalImports {
		if strings.HasPrefix(oi.DLLName, "api-ms-win") {
			allowApiSets = true
			break
		}
	}

	ptrSize := d.PtrSize
	slotCount := int(iatSize) / ptrSize
	slots := make([]IATSlot, slotCount)

	// PASS 1: Collect candidates
	for i := 0; i < slotCount; i++ {
		slots[i].ChosenCandidate = -1
		var slotAddr uintptr
		if d.Is64Bit {
			slotAddr = uintptr(binary.LittleEndian.Uint64(iatData[i*ptrSize : (i+1)*ptrSize]))
		} else {
			slotAddr = uintptr(binary.LittleEndian.Uint32(iatData[i*ptrSize : (i+1)*ptrSize]))
		}

		slots[i].OriginalValue = uint64(slotAddr)
		if slotAddr == 0 {
			slots[i].IsZero = true
			continue
		}

		for _, rm := range d.AllModules {
			if _, ok := rm.ExportTbl[slotAddr]; ok {
				slots[i].Candidates = append(slots[i].Candidates, ResolutionCandidate{Address: slotAddr, Module: rm})
			}
		}

		// Variant B: forwards
		if origins, ok := d.Forwards[slotAddr]; ok {
			for _, o := range origins {
				slots[i].Candidates = append(slots[i].Candidates, ResolutionCandidate{
					Address: o.SourceAddress,
					Module:  o.SourceModule,
				})
			}
		}

		if len(slots[i].Candidates) == 0 {
			log.Infof("IAT slot 0x%08X -> 0x%08X unresolvable", d.IAT+uintptr(i*ptrSize), slotAddr)
		}
	}

	// PASS 2: Grouping and voting
	var thunks []*ImportThunk

	for i := 0; i < slotCount; {
		if slots[i].IsZero {
			i++
			continue
		}

		groupStart := i
		groupEnd := i
		for groupEnd+1 < slotCount && !slots[groupEnd+1].IsZero {
			groupEnd++
		}

		ordinalMask := uint64(winapi.IMAGE_ORDINAL_FLAG32)
		if d.Is64Bit {
			ordinalMask = winapi.IMAGE_ORDINAL_FLAG64
		}
		ordinalOnly := true
		for j := groupStart; j <= groupEnd; j++ {
			value := slots[j].OriginalValue
			if len(slots[j].Candidates) != 0 || value&ordinalMask == 0 || value&^(ordinalMask|0xFFFF) != 0 {
				ordinalOnly = false
				break
			}
		}
		if ordinalOnly {
			log.Infof("Preserving unbound ordinal-only IAT group at 0x%X (%d slots); its DLL cannot be inferred from addresses", d.IAT+uintptr(groupStart*ptrSize), groupEnd-groupStart+1)
			i = groupEnd + 1
			continue
		}

		moduleVotes := make(map[string]int)
		for j := groupStart; j <= groupEnd; j++ {
			for _, cand := range slots[j].Candidates {
				moduleVotes[cand.Module.Name]++
			}
		}

		winnerName := ""
		winnerVotes := -1
		moduleNames := make([]string, 0, len(moduleVotes))
		for name := range moduleVotes {
			moduleNames = append(moduleNames, name)
		}
		sort.Strings(moduleNames)
		for _, modName := range moduleNames {
			votes := moduleVotes[modName]
			if votes > winnerVotes || (votes == winnerVotes && preferenceScore(modName) > preferenceScore(winnerName)) {
				winnerVotes = votes
				winnerName = modName
			}
		}

		var winnerRM *RemoteModule
		for j := groupStart; j <= groupEnd; j++ {
			for k, cand := range slots[j].Candidates {
				if cand.Module.Name == winnerName {
					slots[j].ChosenCandidate = k
					if winnerRM == nil {
						winnerRM = cand.Module
					}
					break
				}
			}
		}

		apiSetName := ""
		if allowApiSets && winnerRM != nil {
			for j := groupStart; j <= groupEnd; j++ {
				if slots[j].ChosenCandidate < 0 && len(slots[j].Candidates) == 0 {
					continue
				}
				var funcName string
				if slots[j].ChosenCandidate < 0 {
					funcName = slots[j].Candidates[0].Module.ExportTbl[slots[j].Candidates[0].Address]
				} else {
					funcName = winnerRM.ExportTbl[slots[j].Candidates[slots[j].ChosenCandidate].Address]
				}

				if strings.HasPrefix(funcName, "RtlQueryPerformance") {
					funcName = strings.TrimPrefix(funcName, "Rtl")
				}

				mapped := onecoreuap.GetOneCoreUAPModuleByAPI(funcName)
				if j == groupStart {
					apiSetName = mapped
				} else if apiSetName != "" && mapped != apiSetName {
					apiSetName = ""
				}
			}
		}

		if apiSetName != "" && winnerRM != nil {
			for j := groupStart; j <= groupEnd; j++ {
				if slots[j].ChosenCandidate < 0 && len(slots[j].Candidates) > 0 {
					funcName := slots[j].Candidates[0].Module.ExportTbl[slots[j].Candidates[0].Address]
					for funcAddr, name := range winnerRM.ExportTbl {
						if name == funcName {
							slots[j].Candidates[0].Address = funcAddr
							slots[j].ChosenCandidate = 0
							log.Infof("IAT slot 0x%X: remapped apiset member %s", d.IAT+uintptr(j*ptrSize), funcName)
							break
						}
					}
				}
			}
		}

		var thunk *ImportThunk
		for j := groupStart; j <= groupEnd; j++ {
			if slots[j].ChosenCandidate < 0 {
				details := make([]string, 0, len(slots[j].Candidates))
				for _, candidate := range slots[j].Candidates {
					details = append(details, candidate.Module.Name+"!"+candidate.Module.ExportTbl[candidate.Address])
				}
				if os.Getenv("UNMIDA_DEBUG_IMPORTS") != "" {
					os.WriteFile(".dependencies/runtime-iat.bin", iatData, 0600)
					os.WriteFile(".dependencies/runtime-header.bin", secBuf[:], 0600)
					for offset := groupStart; offset <= groupEnd; offset++ {
						value := uint64(binary.LittleEndian.Uint32(iatData[offset*ptrSize:]))
						if d.Is64Bit {
							value = binary.LittleEndian.Uint64(iatData[offset*ptrSize:])
						}
						names := []string{}
						for _, candidate := range slots[offset].Candidates {
							names = append(names, candidate.Module.Name+"!"+candidate.Module.ExportTbl[candidate.Address])
						}
						log.Infof("Import diagnostic 0x%X -> 0x%X: %v", d.IAT+uintptr(offset*ptrSize), value, names)
					}
				}
				return nil, fmt.Errorf("IAT slot 0x%X has no candidate for module %s; candidates: %v", d.IAT+uintptr(j*ptrSize), winnerName, details)
			}

			if thunk == nil {
				thunk = &ImportThunk{
					Module: winnerRM,
					Name:   winnerName,
				}
				thunks = append(thunks, thunk)
			}

			cand := slots[j].Candidates[slots[j].ChosenCandidate]
			if d.Is64Bit {
				binary.LittleEndian.PutUint64(iatData[j*ptrSize:(j+1)*ptrSize], uint64(cand.Address))
			} else {
				binary.LittleEndian.PutUint32(iatData[j*ptrSize:(j+1)*ptrSize], uint32(cand.Address))
			}
			thunk.Addresses = append(thunk.Addresses, j)
		}

		if thunk != nil && apiSetName != "" && winnerRM != nil && len(thunk.Addresses) > 0 {
			firstSlot := thunk.Addresses[0]
			var firstAddr uintptr
			if d.Is64Bit {
				firstAddr = uintptr(binary.LittleEndian.Uint64(iatData[firstSlot*ptrSize : (firstSlot+1)*ptrSize]))
			} else {
				firstAddr = uintptr(binary.LittleEndian.Uint32(iatData[firstSlot*ptrSize : (firstSlot+1)*ptrSize]))
			}
			if !d.hasOriginalImport(thunk.Name, winnerRM.ExportTbl[firstAddr]) {
				log.Infof("OneCoreUAP: Using %s instead of %s", apiSetName, winnerName)
				thunk.Name = apiSetName
			}
		}

		i = groupEnd + 1
	}

	// Create .import section
	importSec := peHeader.CreateSection(".import", 0x1000)

	descSize := 20
	totalDescs := len(thunks) + 1 // null terminator
	strOffset := totalDescs * descSize

	secData := bytes.NewBuffer(make([]byte, 0, 0x1000))
	descBytes := make([]byte, totalDescs*descSize)
	secData.Write(descBytes)

	for thunkIdx, thunk := range thunks {
		firstSlot := thunk.Addresses[0]
		firstThunkRVA := uint32(d.IAT - d.ImageBase + uintptr(firstSlot*ptrSize))

		// Write DLL name
		nameRVA := importSec.Header.VirtualAddress + uint32(secData.Len())
		secData.WriteString(thunk.Name)
		secData.WriteByte(0)

		// Update descriptor
		descStart := thunkIdx * descSize
		binary.LittleEndian.PutUint32(secData.Bytes()[descStart+12:descStart+16], nameRVA)
		binary.LittleEndian.PutUint32(secData.Bytes()[descStart+16:descStart+20], firstThunkRVA)

		rm := thunk.Module
		var firstAddr uintptr
		if d.Is64Bit {
			firstAddr = uintptr(binary.LittleEndian.Uint64(iatData[firstSlot*ptrSize : (firstSlot+1)*ptrSize]))
		} else {
			firstAddr = uintptr(binary.LittleEndian.Uint32(iatData[firstSlot*ptrSize : (firstSlot+1)*ptrSize]))
		}
		log.Infof("Thunk %s - first import: %s", thunk.Name, rm.ExportTbl[firstAddr])

		for _, slotIdx := range thunk.Addresses {
			var funcAddr uintptr
			if d.Is64Bit {
				funcAddr = uintptr(binary.LittleEndian.Uint64(iatData[slotIdx*ptrSize : (slotIdx+1)*ptrSize]))
			} else {
				funcAddr = uintptr(binary.LittleEndian.Uint32(iatData[slotIdx*ptrSize : (slotIdx+1)*ptrSize]))
			}
			funcName := rm.ExportTbl[funcAddr]

			if strings.HasPrefix(funcName, "#") {
				ord, _ := strconv.Atoi(funcName[1:])
				if d.Is64Bit {
					binary.LittleEndian.PutUint64(iatData[slotIdx*ptrSize:(slotIdx+1)*ptrSize], winapi.IMAGE_ORDINAL_FLAG64|uint64(ord))
				} else {
					binary.LittleEndian.PutUint32(iatData[slotIdx*ptrSize:(slotIdx+1)*ptrSize], winapi.IMAGE_ORDINAL_FLAG32|uint32(ord))
				}
				continue
			}

			if strings.HasPrefix(funcName, "RtlQueryPerformance") && strings.HasPrefix(thunk.Name, "api-ms-win") {
				funcName = strings.TrimPrefix(funcName, "Rtl")
			}

			// IMAGE_IMPORT_BY_NAME: Hint (2 bytes) + Name + \0
			if secData.Len()%2 != 0 {
				secData.WriteByte(0)
			}
			currRVA := importSec.Header.VirtualAddress + uint32(secData.Len())
			if d.Is64Bit {
				binary.LittleEndian.PutUint64(iatData[slotIdx*ptrSize:(slotIdx+1)*ptrSize], uint64(currRVA))
			} else {
				binary.LittleEndian.PutUint32(iatData[slotIdx*ptrSize:(slotIdx+1)*ptrSize], currRVA)
			}

			secData.WriteByte(0) // Hint lo
			secData.WriteByte(0) // Hint hi
			secData.WriteString(funcName)
			secData.WriteByte(0)
		}
	}

	_ = strOffset

	// Align import section data
	for secData.Len()%0x1000 != 0 {
		secData.WriteByte(0)
	}
	importSec.Data = secData.Bytes()
	importSec.Header.SizeOfRawData = uint32(len(importSec.Data))
	importSec.Header.VirtualSize = importSec.Header.SizeOfRawData
	peHeader.SizeOfImage = importSec.Header.VirtualAddress + importSec.Header.VirtualSize
	peHeader.SectionAlign(&peHeader.SizeOfImage)

	peHeader.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = importSec.Header.VirtualAddress
	peHeader.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_IMPORT].Size = uint32(len(thunks) * descSize)

	if uint64(iatSize)+uint64(ptrSize) > uint64(len(iatData)) {
		return nil, fmt.Errorf("IAT exceeds maximum size")
	}
	clear(iatData[iatSize : iatSize+uint32(ptrSize)])
	d.IATImage = iatData[:iatSize+uint32(ptrSize)]

	return peHeader, nil
}

func (d *Dumper) DumpToFile(fileName string, peHeader *pe.PEHeader, isDLL bool) error {
	f, actualPath, err := createDumpFile(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	d.OutputFile = actualPath

	dumpSize := peHeader.DumpSize
	buf := make([]byte, dumpSize)
	d.makeMemoryReadable(d.ImageBase, uintptr(dumpSize))

	if !d.RPM(d.ImageBase, buf) {
		return fmt.Errorf("DumpToFile RPM failed (base: 0x%X, size: 0x%X)", d.ImageBase, dumpSize)
	}

	iatRawOffset := uint32(d.IAT - d.ImageBase)
	delta := peHeader.TrimHugeSections(buf, &iatRawOffset)
	dumpSize -= delta

	if _, err := f.Write(buf[:dumpSize]); err != nil {
		return err
	}

	origSecCount := int(peHeader.FileHeader.NumberOfSections)
	for i := origSecCount; i < len(peHeader.Sections); i++ {
		sec := peHeader.Sections[i]
		if len(sec.Data) > 0 {
			if _, err := f.Seek(int64(sec.Header.PointerToRawData), io.SeekStart); err != nil {
				return err
			}
			if _, err := f.Write(sec.Data); err != nil {
				return err
			}
		} else {
			zeroes := make([]byte, sec.Header.SizeOfRawData)
			if _, err := f.Seek(int64(sec.Header.PointerToRawData), io.SeekStart); err != nil {
				return err
			}
			if _, err := f.Write(zeroes); err != nil {
				return err
			}
		}
	}

	peHeader.FileHeader.NumberOfSections = uint16(len(peHeader.Sections))
	peHeader.AddressOfEntryPoint = uint32(d.OEP - d.ImageBase)

	if isDLL {
		peHeader.FileHeader.Characteristics |= winapi.IMAGE_FILE_DLL
		debugger.SwitchSxSManifestType(f, peHeader, 1, 2)
	}

	if (peHeader.DllCharacteristics & 0x40) != 0 {
		log.Infof("Executable is ASLR-aware - disabling the flag in the dump")
		peHeader.DllCharacteristics &^= 0x40
	}

	if err := peHeader.SaveToStream(f); err != nil {
		return err
	}

	if _, err := f.Seek(int64(iatRawOffset), io.SeekStart); err != nil {
		return err
	}
	if _, err := f.Write(d.IATImage); err != nil {
		return err
	}

	return nil
}

func (d *Dumper) makeMemoryReadable(base uintptr, size uintptr) {
	addr := base
	end := base + size
	var mbi winapi.MEMORY_BASIC_INFORMATION

	for addr < end {
		ret, err := winapi.VirtualQueryEx(d.ProcessHandle, addr, &mbi)
		if err != nil || ret == 0 {
			break
		}
		if mbi.State == winapi.MEM_COMMIT && mbi.Protect == winapi.PAGE_NOACCESS {
			winapi.VirtualProtectEx(d.ProcessHandle, mbi.BaseAddress, mbi.RegionSize, winapi.PAGE_READONLY)
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
}

func (d *Dumper) getOriginalImports(filename string) []OriginalImport {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	header, err := pe.ParsePEHeader(data)
	if err != nil {
		return nil
	}
	directory := header.DataDirectory[winapi.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if directory.VirtualAddress == 0 {
		return nil
	}
	ptrSize := uint32(4)
	ordinalMask := uint64(winapi.IMAGE_ORDINAL_FLAG32)
	if header.Is64Bit {
		ptrSize = 8
		ordinalMask = winapi.IMAGE_ORDINAL_FLAG64
	}
	var imports []OriginalImport
	for offset := uint32(0); uint64(offset)+20 <= uint64(directory.Size); offset += 20 {
		descriptor := fileRVA(header, data, directory.VirtualAddress+offset, 20)
		if descriptor == nil {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(descriptor[12:16])
		if nameRVA == 0 {
			break
		}
		name := strings.ToLower(fileString(header, data, nameRVA))
		thunk := binary.LittleEndian.Uint32(descriptor[0:4])
		if thunk == 0 {
			thunk = binary.LittleEndian.Uint32(descriptor[16:20])
		}
		if thunk == 0 {
			continue
		}
		for index := uint32(0); index < 5120; index++ {
			entry := fileRVA(header, data, thunk+index*ptrSize, ptrSize)
			if entry == nil {
				break
			}
			value := uint64(binary.LittleEndian.Uint32(entry))
			if ptrSize == 8 {
				value = binary.LittleEndian.Uint64(entry)
			}
			if value == 0 {
				break
			}
			var function string
			if value&ordinalMask != 0 {
				function = "#" + strconv.Itoa(int(value&0xFFFF))
			} else if value <= 0xFFFFFFFD {
				function = fileString(header, data, uint32(value)+2)
			}
			if name != "" && function != "" {
				imports = append(imports, OriginalImport{DLLName: name, FuncName: function})
			}
		}
	}
	return imports
}

func (d *Dumper) hasOriginalImport(dll, funcName string) bool {
	lowerDLL := strings.ToLower(dll)
	for _, oi := range d.OriginalImports {
		if oi.DLLName == lowerDLL && oi.FuncName == funcName {
			return true
		}
	}
	return false
}

// DumperDotnet dumps Themida .NET processes
type DumperDotnet struct {
	OutputFile    string
	ProcessHandle syscall.Handle
	ImageBase     uintptr
}

func NewDumperDotnet(hProcess syscall.Handle, imageBase uintptr) *DumperDotnet {
	return &DumperDotnet{
		ProcessHandle: hProcess,
		ImageBase:     imageBase,
	}
}

func (dd *DumperDotnet) DumpToFile(fileName string) error {
	var header [0x1000]byte
	if _, err := winapi.ReadProcessMemory(dd.ProcessHandle, dd.ImageBase, header[:]); err != nil {
		return fmt.Errorf("DumpToFile header RPM failed: %w", err)
	}

	peHeader, err := pe.ParsePEHeader(header[:])
	if err != nil {
		return fmt.Errorf("ParsePEHeader failed: %w", err)
	}

	lastSec := peHeader.Sections[len(peHeader.Sections)-1]
	size := lastSec.Header.VirtualAddress + lastSec.Header.VirtualSize

	f, actualPath, err := createDumpFile(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	dd.OutputFile = actualPath

	buf := make([]byte, size)
	physicalSize := size
	peHeader.FileAlign(&physicalSize)
	imageSize := physicalSize
	peHeader.SectionAlign(&imageSize)
	peHeader.SizeOfImage = imageSize

	if len(peHeader.Sections) > 0 {
		peHeader.Sections[0].Rename(".text")
	}

	log.Infof("Output has %d sections, determined size to be 0x%X", len(peHeader.Sections), size)

	var done uint32
	ptr := dd.ImageBase
	var mbi winapi.MEMORY_BASIC_INFORMATION
	mbi.RegionSize = 0x1000

	for done < size {
		ret, err := winapi.VirtualQueryEx(dd.ProcessHandle, ptr, &mbi)
		if err != nil || ret == 0 {
			return fmt.Errorf("VirtualQueryEx failed at 0x%X", ptr)
		}
		if mbi.RegionSize == 0 {
			return fmt.Errorf("VirtualQueryEx returned a zero region at 0x%X", ptr)
		}

		remaining := mbi.BaseAddress + mbi.RegionSize - ptr
		chunk := uint32(min(remaining, uintptr(size-done)))
		if size-done < chunk {
			chunk = size - done
		}

		if mbi.State == winapi.MEM_COMMIT {
			if _, err := winapi.ReadProcessMemory(dd.ProcessHandle, ptr, buf[done:done+chunk]); err != nil {
				return fmt.Errorf("DumpToFile RPM failed at 0x%X: %w", ptr, err)
			}
		} else if mbi.State == winapi.MEM_RESERVE {
			// zeroed
		} else {
			return fmt.Errorf("unexpected region state 0x%X at 0x%X", mbi.State, ptr)
		}

		done += chunk
		ptr += uintptr(chunk)
	}

	if _, err := f.Write(buf); err != nil {
		return err
	}

	if size < physicalSize {
		pad := make([]byte, physicalSize-size)
		if _, err := f.Write(pad); err != nil {
			return err
		}
	}

	return peHeader.SaveToStream(f)
}

func ChangeFileExt(path, newExt string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + newExt
}

func createDumpFile(path string) (*os.File, string, error) {
	file, err := os.Create(path)
	if err == nil {
		return file, path, nil
	}
	if !os.IsPermission(err) {
		return nil, path, err
	}
	fallback, resolveErr := filepath.Abs(filepath.Base(path))
	if resolveErr != nil {
		return nil, path, resolveErr
	}
	if filepath.Clean(fallback) == filepath.Clean(path) {
		return nil, path, err
	}
	file, err = os.Create(fallback)
	if err == nil {
		log.Infof("Output directory is not writable; saving dump to %s", fallback)
	}
	return file, fallback, err
}
