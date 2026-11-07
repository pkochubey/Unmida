package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"unmida/pkg/log"
	"unmida/pkg/patcher"
	"unmida/pkg/pe"
	"unmida/pkg/themida"
)

type Options struct {
	File, Parameters string
	CreateData       bool
	PID              uint32
}

func Execute(action string, options Options) error {
	filename, err := filepath.Abs(options.File)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	header, err := pe.ParsePEHeader(data)
	if err != nil {
		return err
	}
	if header.FileHeader.Machine != 0x14C && header.FileHeader.Machine != 0x8664 {
		return fmt.Errorf("unsupported PE machine: 0x%X", header.FileHeader.Machine)
	}
	if action == "unpack" {
		if header.Is64Bit != (unsafe.Sizeof(uintptr(0)) == 8) {
			return fmt.Errorf("use the %d-bit Unmida executable for this file", map[bool]int{true: 64, false: 32}[header.Is64Bit])
		}
		if header.Is64Bit {
			debugger, err := themida.NewDebugger64(filename, options.Parameters, options.CreateData)
			if err != nil {
				return err
			}
			return debugger.RunDebugLoop()
		}
		debugger, err := themida.NewDebugger32(filename, options.Parameters, options.CreateData)
		if err != nil {
			return err
		}
		return debugger.RunDebugLoop()
	}
	if header.Is64Bit {
		return fmt.Errorf("%s is available only for PE32 files, as in the original program", action)
	}
	if action == "dump" {
		if options.PID == 0 {
			return fmt.Errorf("PID must be greater than zero")
		}
		return patcher.DumpProcessCode(options.PID, filename)
	}
	patch, err := patcher.NewPatcher(filename)
	if err != nil {
		return err
	}
	switch action {
	case "shrink":
		return patch.ProcessShrink()
	case "mkdata":
		return patch.ProcessMkData()
	default:
		return fmt.Errorf("unknown operation: %s", action)
	}
}

func CLI(args []string) int {
	usage := "Unmida <file> [--no-data] [--parameters <command line>]\nUnmida /unpack <file> [--no-data] [--parameters <command line>]\nUnmida /shrink <file>\nUnmida /mkdata <file>\nUnmida /dump <PID> <file>"
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "/?" {
		fmt.Println(usage)
		return 0
	}
	action := strings.TrimLeft(strings.ToLower(args[0]), "/-")
	options := Options{CreateData: true}
	index := 1
	switch action {
	case "unpack", "dump", "shrink", "mkdata":
	default:
		action = "unpack"
		index = 0
	}
	if action == "dump" {
		if index >= len(args) {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		pid, err := strconv.ParseUint(args[index], 10, 32)
		if err != nil || pid == 0 {
			fmt.Fprintln(os.Stderr, "Invalid PID")
			return 2
		}
		options.PID = uint32(pid)
		index++
	}
	if index >= len(args) {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	options.File = args[index]
	index++
	for index < len(args) {
		switch args[index] {
		case "--no-data":
			options.CreateData = false
		case "--parameters":
			index++
			if index >= len(args) {
				fmt.Fprintln(os.Stderr, "Missing --parameters value")
				return 2
			}
			options.Parameters = args[index]
		default:
			fmt.Fprintln(os.Stderr, "Unknown argument:", args[index])
			return 2
		}
		index++
	}
	switch action {
	case "unpack", "dump", "shrink", "mkdata":
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if err := Execute(action, options); err != nil {
		log.Fatalf("%v", err)
		return 1
	}
	return 0
}
