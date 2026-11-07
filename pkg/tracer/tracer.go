package tracer

import (
	"fmt"
	"unmida/pkg/winapi"
	"syscall"
)

type PredicateFunc func(tracer *Tracer, c32 *winapi.CONTEXT32, c64 *winapi.CONTEXT64) bool

type Tracer struct {
	ProcessID, ThreadID uint32
	ThreadHandle        syscall.Handle
	Is64Bit             bool
	Predicate           PredicateFunc
	Counter, Limit      uint32
	LimitReached        bool
	StartAddress        uintptr
	Pending             bool
}

func NewTracer(processID, threadID uint32, threadHandle syscall.Handle, is64Bit bool, predicate PredicateFunc) *Tracer {
	return &Tracer{ProcessID: processID, ThreadID: threadID, ThreadHandle: threadHandle, Is64Bit: is64Bit, Predicate: predicate}
}

func (t *Tracer) Trace(address uintptr, limit uint32) error {
	t.Counter, t.Limit, t.StartAddress = 0, limit, address
	t.LimitReached, t.Pending = false, true
	if t.Is64Bit {
		var c winapi.CONTEXT64
		c.ContextFlags = winapi.CONTEXT_CONTROL_64
		if err := winapi.GetThreadContext64(t.ThreadHandle, &c); err != nil {
			return err
		}
		c.Rip = uint64(address)
		c.EFlags |= 0x100
		if err := winapi.SetThreadContext64(t.ThreadHandle, &c); err != nil {
			return err
		}
	} else {
		var c winapi.CONTEXT32
		c.ContextFlags = winapi.CONTEXT_CONTROL_32
		if err := winapi.GetThreadContext32(t.ThreadHandle, &c); err != nil {
			return err
		}
		c.Eip = uint32(address)
		c.EFlags |= 0x100
		if err := winapi.SetThreadContext32(t.ThreadHandle, &c); err != nil {
			return err
		}
	}
	if err := winapi.ContinueDebugEvent(t.ProcessID, t.ThreadID, winapi.DBG_CONTINUE); err != nil {
		return err
	}
	t.Pending = false
	suspended := make(map[uint32]syscall.Handle)
	defer func() {
		for _, h := range suspended {
			winapi.ResumeThread(h)
			winapi.CloseHandle(h)
		}
	}()
	for {
		var event winapi.DEBUG_EVENT
		if err := winapi.WaitForDebugEvent(&event, 0xFFFFFFFF); err != nil {
			return err
		}
		if event.DwDebugEventCode == winapi.EXIT_PROCESS_DEBUG_EVENT {
			winapi.ContinueDebugEvent(event.DwProcessId, event.DwThreadId, winapi.DBG_CONTINUE)
			return fmt.Errorf("target exited during import tracing")
		}
		if event.DwThreadId != t.ThreadID {
			switch event.DwDebugEventCode {
			case winapi.CREATE_THREAD_DEBUG_EVENT:
				winapi.CloseHandle(event.CreateThread().HThread)
			case winapi.LOAD_DLL_DEBUG_EVENT:
				winapi.CloseHandle(event.LoadDll().HFile)
			}
			if _, ok := suspended[event.DwThreadId]; !ok && event.DwDebugEventCode != winapi.EXIT_THREAD_DEBUG_EVENT {
				h, err := winapi.OpenThread(winapi.THREAD_SUSPEND_RESUME, false, event.DwThreadId)
				if err != nil {
					winapi.ContinueDebugEvent(event.DwProcessId, event.DwThreadId, winapi.DBG_CONTINUE)
					return err
				}
				if _, err = winapi.SuspendThread(h); err != nil {
					winapi.CloseHandle(h)
					winapi.ContinueDebugEvent(event.DwProcessId, event.DwThreadId, winapi.DBG_CONTINUE)
					return err
				}
				suspended[event.DwThreadId] = h
			}
			status := uint32(winapi.DBG_CONTINUE)
			if event.DwDebugEventCode == winapi.EXCEPTION_DEBUG_EVENT {
				status = winapi.DBG_EXCEPTION_NOT_HANDLED
			}
			if err := winapi.ContinueDebugEvent(event.DwProcessId, event.DwThreadId, status); err != nil {
				return err
			}
			continue
		}
		t.Pending = true
		if event.DwDebugEventCode == winapi.EXCEPTION_DEBUG_EVENT {
			exc := event.Exception().ExceptionRecord
			if exc.ExceptionCode != winapi.EXCEPTION_SINGLE_STEP {
				return fmt.Errorf("exception 0x%08X at 0x%X during import trace", exc.ExceptionCode, exc.ExceptionAddress)
			}
			stop, err := t.onSingleStep()
			if err != nil || stop {
				return err
			}
		} else {
			switch event.DwDebugEventCode {
			case winapi.LOAD_DLL_DEBUG_EVENT:
				winapi.CloseHandle(event.LoadDll().HFile)
			case winapi.EXIT_THREAD_DEBUG_EVENT:
				return fmt.Errorf("traced thread exited")
			}
		}
		if err := winapi.ContinueDebugEvent(event.DwProcessId, event.DwThreadId, winapi.DBG_CONTINUE); err != nil {
			return err
		}
		t.Pending = false
	}
}

func (t *Tracer) onSingleStep() (bool, error) {
	t.Counter++
	var c32 winapi.CONTEXT32
	var c64 winapi.CONTEXT64
	if t.Is64Bit {
		c64.ContextFlags = winapi.CONTEXT_CONTROL_64 | winapi.CONTEXT_INTEGER_64
		if err := winapi.GetThreadContext64(t.ThreadHandle, &c64); err != nil {
			return true, err
		}
	} else {
		c32.ContextFlags = winapi.CONTEXT_CONTROL_32 | winapi.CONTEXT_INTEGER_32
		if err := winapi.GetThreadContext32(t.ThreadHandle, &c32); err != nil {
			return true, err
		}
	}
	if t.Limit != 0 && t.Counter > t.Limit {
		t.LimitReached = true
	}
	stop := t.LimitReached
	if !stop && t.Predicate != nil {
		if t.Is64Bit {
			stop = t.Predicate(t, nil, &c64)
		} else {
			stop = t.Predicate(t, &c32, nil)
		}
	}
	if t.Is64Bit {
		c64.EFlags &^= 0x100
		if !stop {
			c64.EFlags |= 0x100
		}
		if err := winapi.SetThreadContext64(t.ThreadHandle, &c64); err != nil {
			return true, err
		}
	} else {
		c32.EFlags &^= 0x100
		if !stop {
			c32.EFlags |= 0x100
		}
		if err := winapi.SetThreadContext32(t.ThreadHandle, &c32); err != nil {
			return true, err
		}
	}
	if t.LimitReached {
		return true, fmt.Errorf("import trace exceeded %d instructions", t.Limit)
	}
	return stop, nil
}
