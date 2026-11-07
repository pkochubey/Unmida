package winapi

import (
	"syscall"
	"unsafe"
)

// Windows Constants
const (
	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000

	PROCESS_ALL_ACCESS   = 0x1FFFFF
	PROCESS_VM_READ      = 0x0010
	PROCESS_VM_WRITE     = 0x0020
	PROCESS_VM_OPERATION = 0x0008

	THREAD_SUSPEND_RESUME = 0x0002
	THREAD_ALL_ACCESS     = 0x1FFFFF

	DBG_CONTINUE              = 0x00010002
	DBG_EXCEPTION_NOT_HANDLED = 0x80010001
	DBG_CONTROL_BREAK         = 0x40010008
	DBG_CONTROL_C             = 0x40010005

	EXCEPTION_DEBUG_EVENT      = 1
	CREATE_THREAD_DEBUG_EVENT  = 2
	CREATE_PROCESS_DEBUG_EVENT = 3
	EXIT_THREAD_DEBUG_EVENT    = 4
	EXIT_PROCESS_DEBUG_EVENT   = 5
	LOAD_DLL_DEBUG_EVENT       = 6
	UNLOAD_DLL_DEBUG_EVENT     = 7
	OUTPUT_DEBUG_STRING_EVENT  = 8
	RIP_EVENT                  = 9

	EXCEPTION_ACCESS_VIOLATION      = 0xC0000005
	EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002
	EXCEPTION_BREAKPOINT            = 0x80000003
	EXCEPTION_SINGLE_STEP           = 0x80000004

	DEBUG_PROCESS             = 0x00000001
	DEBUG_ONLY_THIS_PROCESS   = 0x00000002
	CREATE_DEFAULT_ERROR_MODE = 0x04000000
	CREATE_NEW_CONSOLE        = 0x00000010
	NORMAL_PRIORITY_CLASS     = 0x00000020
	STARTF_USESHOWWINDOW      = 0x00000001
	SW_SHOW                   = 5
	SW_HIDE                   = 0

	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x00000010

	CONTEXT_i386               = 0x00010000
	CONTEXT_CONTROL_32         = CONTEXT_i386 | 0x00000001
	CONTEXT_INTEGER_32         = CONTEXT_i386 | 0x00000002
	CONTEXT_SEGMENTS_32        = CONTEXT_i386 | 0x00000004
	CONTEXT_FLOATING_POINT_32  = CONTEXT_i386 | 0x00000008
	CONTEXT_DEBUG_REGISTERS_32 = CONTEXT_i386 | 0x00000010
	CONTEXT_FULL_32            = CONTEXT_CONTROL_32 | CONTEXT_INTEGER_32 | CONTEXT_SEGMENTS_32

	CONTEXT_AMD64              = 0x00100000
	CONTEXT_CONTROL_64         = CONTEXT_AMD64 | 0x00000001
	CONTEXT_INTEGER_64         = CONTEXT_AMD64 | 0x00000002
	CONTEXT_SEGMENTS_64        = CONTEXT_AMD64 | 0x00000004
	CONTEXT_FLOATING_POINT_64  = CONTEXT_AMD64 | 0x00000008
	CONTEXT_DEBUG_REGISTERS_64 = CONTEXT_AMD64 | 0x00000010
	CONTEXT_FULL_64            = CONTEXT_CONTROL_64 | CONTEXT_INTEGER_64 | CONTEXT_FLOATING_POINT_64

	STATUS_SUCCESS      = 0x00000000
	STATUS_PORT_NOT_SET = 0xC0000353

	IMAGE_FILE_MACHINE_I386  = 0x014c
	IMAGE_FILE_MACHINE_AMD64 = 0x8664
	IMAGE_FILE_DLL           = 0x2000

	IMAGE_DIRECTORY_ENTRY_EXPORT    = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT    = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
	IMAGE_DIRECTORY_ENTRY_SECURITY  = 4
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
	IMAGE_DIRECTORY_ENTRY_DEBUG     = 6
	IMAGE_DIRECTORY_ENTRY_TLS       = 9
	IMAGE_DIRECTORY_ENTRY_IAT       = 12

	IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
	IMAGE_SCN_MEM_EXECUTE          = 0x20000000
	IMAGE_SCN_MEM_READ             = 0x40000000
	IMAGE_SCN_MEM_WRITE            = 0x80000000

	IMAGE_ORDINAL_FLAG32 = 0x80000000
	IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
)

// WOW64 / 32-bit Context
type FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type CONTEXT32 struct {
	ContextFlags uint32

	Dr0 uint32
	Dr1 uint32
	Dr2 uint32
	Dr3 uint32
	Dr6 uint32
	Dr7 uint32

	FloatSave FLOATING_SAVE_AREA

	SegGs uint32
	SegFs uint32
	SegEs uint32
	SegDs uint32

	Edi uint32
	Esi uint32
	Ebx uint32
	Edx uint32
	Ecx uint32
	Eax uint32

	Ebp    uint32
	Eip    uint32
	SegCs  uint32
	EFlags uint32
	Esp    uint32
	SegSs  uint32

	ExtendedRegisters [512]byte
}

type M128A struct {
	Low  uint64
	High int64
}

type CONTEXT64 struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	ContextFlags uint32
	MxCsr        uint32

	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32

	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64

	Rip uint64

	Header    [2]M128A
	Legacy    [8]M128A
	Xmm0      M128A
	Xmm1      M128A
	Xmm2      M128A
	Xmm3      M128A
	Xmm4      M128A
	Xmm5      M128A
	Xmm6      M128A
	Xmm7      M128A
	Xmm8      M128A
	Xmm9      M128A
	Xmm10     M128A
	Xmm11     M128A
	Xmm12     M128A
	Xmm13     M128A
	Xmm14     M128A
	Xmm15     M128A
	Reserved4 [96]byte

	VectorRegister [26]M128A
	VectorControl  uint64

	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// Exception record for current architecture
type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      uintptr
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_DEBUG_INFO struct {
	ExceptionRecord EXCEPTION_RECORD
	DwFirstChance   uint32
}

type CREATE_THREAD_DEBUG_INFO struct {
	HThread           syscall.Handle
	LpThreadLocalBase uintptr
	LpStartAddress    uintptr
}

type CREATE_PROCESS_DEBUG_INFO struct {
	HFile                 syscall.Handle
	HProcess              syscall.Handle
	HThread               syscall.Handle
	LpBaseOfImage         uintptr
	DwDebugInfoFileOffset uint32
	NNumberOfBytesToMap   uint32
	LpThreadLocalBase     uintptr
	LpStartAddress        uintptr
	LpImageName           uintptr
	FUnicode              uint16
}

type EXIT_THREAD_DEBUG_INFO struct {
	DwExitCode uint32
}

type EXIT_PROCESS_DEBUG_INFO struct {
	DwExitCode uint32
}

type LOAD_DLL_DEBUG_INFO struct {
	HFile                 syscall.Handle
	LpBaseOfDll           uintptr
	DwDebugInfoFileOffset uint32
	NNumberOfBytesToMap   uint32
	LpImageName           uintptr
	FUnicode              uint16
}

type UNLOAD_DLL_DEBUG_INFO struct {
	LpBaseOfDll uintptr
}

type OUTPUT_DEBUG_STRING_INFO struct {
	LpDebugStringData  uintptr
	FUnicode           uint16
	NDebugStringLength uint16
}

type RIP_INFO struct {
	DwError uint32
	DwType  uint32
}

type DEBUG_EVENT struct {
	DwDebugEventCode uint32
	DwProcessId      uint32
	DwThreadId       uint32
	_                [0]uintptr
	U                [160]byte
}

func (de *DEBUG_EVENT) Exception() *EXCEPTION_DEBUG_INFO {
	return (*EXCEPTION_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) CreateThread() *CREATE_THREAD_DEBUG_INFO {
	return (*CREATE_THREAD_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) CreateProcessInfo() *CREATE_PROCESS_DEBUG_INFO {
	return (*CREATE_PROCESS_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) ExitThread() *EXIT_THREAD_DEBUG_INFO {
	return (*EXIT_THREAD_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) ExitProcess() *EXIT_PROCESS_DEBUG_INFO {
	return (*EXIT_PROCESS_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) LoadDll() *LOAD_DLL_DEBUG_INFO {
	return (*LOAD_DLL_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) UnloadDll() *UNLOAD_DLL_DEBUG_INFO {
	return (*UNLOAD_DLL_DEBUG_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) DebugString() *OUTPUT_DEBUG_STRING_INFO {
	return (*OUTPUT_DEBUG_STRING_INFO)(unsafe.Pointer(&de.U[0]))
}

func (de *DEBUG_EVENT) RipInfo() *RIP_INFO {
	return (*RIP_INFO)(unsafe.Pointer(&de.U[0]))
}

type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uint32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type MODULEENTRY32W struct {
	DwSize        uint32
	Th32ModuleID  uint32
	Th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	ModBaseAddr   uintptr
	ModBaseSize   uint32
	HModule       syscall.Handle
	SzModule      [256]uint16
	SzExePath     [260]uint16
}
