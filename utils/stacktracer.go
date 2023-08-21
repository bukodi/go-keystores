package utils

import (
	"fmt"
	"path"
	"runtime"
)

type StackTracer interface {
	error
	Callers() []uintptr
}

type withStack struct {
	cause error
	stack []uintptr
}

func (ws withStack) Callers() []uintptr {
	return ws.stack
}

func (ws withStack) Error() string {
	return ws.cause.Error()
}

func (ws withStack) String() string {
	if ws.stack != nil && len(ws.stack) > 0 {
		fn := runtime.FuncForPC(ws.stack[0])
		if fn != nil {
			fullPath, line := fn.FileLine(ws.stack[0])
			_, file := path.Split(fullPath)
			return fmt.Sprintf("%T@%s:%d : %s", ws.cause, file, line, ws.cause.Error())
		}
	}
	return fmt.Sprintf("%T: %s", ws.cause, ws.cause.Error())
}

const maxDumpDepth = 5

func (ws withStack) GoString() string {
	msg := fmt.Sprintf("%+v", ws.cause)
	if ws.stack != nil && len(ws.stack) > 0 {
		for i := 0; i < len(ws.stack) && i < maxDumpDepth; i++ {
			fn := runtime.FuncForPC(ws.stack[i])
			if fn != nil {
				fullPath, line := fn.FileLine(ws.stack[i])
				_, file := path.Split(fullPath)
				msg += fmt.Sprintf("\n  %s:%d", file, line)
			} else {
				msg += "\n  <frame not available>"
			}

		}
	} else {
		msg += "\n  <stack trace not available>"
	}
	if ws.cause != nil {
		msg += "\nCaused by: " + fmt.Sprintf("%#v", ws.cause)
	}
	return msg
}

func WithStack(err error) error {
	return WithStackSkip(1, err)
}

func WithStackSkip(skip int, err error) error {
	if err == nil {
		return nil
	}
	pcs := make([]uintptr, 32)
	count := runtime.Callers(skip+1, pcs)
	ws := withStack{
		cause: err,
		stack: make([]uintptr, count),
	}
	for i := 0; i < count; i++ {
		ws.stack[i] = pcs[i]
	}

	return ws
}
