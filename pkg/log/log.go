package log

import (
	"fmt"
	"os"
	"sync"
)

type MsgType int

const (
	Info MsgType = iota
	Good
	Fatal
)

var output struct {
	sync.RWMutex
	handler func(MsgType, string)
}

func SetHandler(handler func(MsgType, string)) func() {
	output.Lock()
	previous := output.handler
	output.handler = handler
	output.Unlock()
	return func() { output.Lock(); output.handler = previous; output.Unlock() }
}

func Log(kind MsgType, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	output.RLock()
	handler := output.handler
	output.RUnlock()
	if handler != nil {
		handler(kind, message)
		return
	}
	names := [...]string{"Info", "Good", "Fatal"}
	name := "Log"
	if kind >= Info && kind <= Fatal {
		name = names[kind]
	}
	stream := os.Stdout
	if kind == Fatal {
		stream = os.Stderr
	}
	fmt.Fprintf(stream, "[%s] %s\n", name, message)
}

func Infof(format string, args ...interface{})  { Log(Info, format, args...) }
func Goodf(format string, args ...interface{})  { Log(Good, format, args...) }
func Fatalf(format string, args ...interface{}) { Log(Fatal, format, args...) }
