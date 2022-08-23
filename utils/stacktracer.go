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

func WithStack(err error) error {
	return WithStackSkip(1, err)
}

func WithStackSkip(skip int, err error) error {
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
