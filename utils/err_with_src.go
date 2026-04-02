package utils

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"slices"
)

type errWithSourceAndAttrs struct {
	msg    string
	err    error
	Attrs  []slog.Attr
	Source *slog.Source
}

func (e errWithSourceAndAttrs) Error() string {
	return e.msg
}

func (e errWithSourceAndAttrs) Unwrap() error {
	return e.err
}

func HandleError(err error, attrs ...slog.Attr) error {
	return errorHandler(0, "", err, attrs...)
}

func HandleErrorMsg(msg string, err error, attrs ...slog.Attr) error {
	return errorHandler(0, msg, err, attrs...)
}

func SkipFramesHandleErrorMsg(skipFrames int, msg string, err error, attrs ...slog.Attr) error {
	return errorHandler(skipFrames, msg, err, attrs...)
}

var errorHandler = func(skipFrames int, msg string, err error, args ...slog.Attr) error {
	if err == nil && msg == "" {
		return nil
	}
	pc := callerPC(4 + skipFrames)
	fs := runtime.CallersFrames([]uintptr{pc})
	f, _ := fs.Next()
	src := &slog.Source{
		Function: f.Function,
		File:     f.File,
		Line:     f.Line,
	}
	truncateSourcePath(src)
	if msg == "" && err != nil {
		msg = err.Error()
	} else if msg != "" && err == nil {
		err = nil
	}
	var errWA = errWithSourceAndAttrs{msg, err, slices.Clone(args), src}
	return errWA
}

func PrintErrorWithStack(err error) string {
	return fmt.Sprintf("%+v\n", err)
}

// Format implements the fmt.Formatter interface
func (e errWithSourceAndAttrs) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			// For %#v, use the GoString method
			e.formatWithSourceAndAttrs(f)
		} else if f.Flag('+') {
			e.formatWithSourceAndAttrs(f)
		} else {
			// For %v, show a basic format
			fmt.Fprintf(f, "%s", e.msg)
			if len(e.Attrs) > 0 {
				fmt.Fprint(f, " (")
				for i, attr := range e.Attrs {
					if i > 0 {
						fmt.Fprint(f, ", ")
					}
					fmt.Fprintf(f, "%s=%v", attr.Key, attr.Value)
				}
				fmt.Fprint(f, ")")
			}
		}
	case 's':
		// For %s, just show the error message
		fmt.Fprint(f, e.msg)
	default:
		// For any other verb, fall back to default behavior
		fmt.Fprintf(f, "%%!%c(errWithSourceAndAttrs=%s)", verb, e.msg)
	}
}

type errStackFrame struct {
	source *slog.Source
	err    error
}

func (e errWithSourceAndAttrs) stackAndAttrs() ([]*errStackFrame, map[string]slog.Value) {
	var stack = make([]*errStackFrame, 0)
	var attrs = make(map[string]slog.Value)

	var currErr error = e
	for {
		frame := errStackFrame{
			err: currErr,
		}
		if esrc, ok := currErr.(errWithSourceAndAttrs); ok {
			frame.source = esrc.Source
			for _, attrInErr := range esrc.Attrs {
				attrs[attrInErr.Key] = attrInErr.Value
			}
		}
		stack = append(stack, &frame)
		if parentErr, ok := currErr.(interface{ Unwrap() error }); ok {
			currErr = parentErr.Unwrap()
			if currErr == nil {
				break
			}
		} else {
			break
		}
	}
	slices.Reverse(stack)
	return stack, attrs
}

func (e errWithSourceAndAttrs) formatWithSourceAndAttrs(w io.Writer) {
	stack, attrs := e.stackAndAttrs()
	fmt.Fprint(w, e.Error())

	if len(attrs) > 0 {
		fmt.Fprint(w, "\n  attributes:")
		for key, value := range attrs {
			fmt.Fprintf(w, "\n  - %s = %v", key, value)
		}
	}
	if len(stack) > 0 {
		fmt.Fprint(w, "\n  stack:")
		for _, frame := range stack {
			if frame.source == nil {
				fmt.Fprintf(w, "\n  - %s", frame.err.Error())
			} else {
				fmt.Fprintf(w, "\n  - %s ( %s )", frame.err.Error(), sourceToString(frame.source))
			}
		}
	}
	if len(attrs) > 0 || len(stack) > 0 {
		fmt.Fprint(w, "\n")
	}
}

// callerPC returns the program counter at the given stack depth.
func callerPC(depth int) uintptr {
	var pcs [1]uintptr
	runtime.Callers(depth, pcs[:])
	return pcs[0]
}

var ErrorUserAbort = fmt.Errorf("User aborted the operation")
