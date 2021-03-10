package keystores

import "errors"

var (
	ErrAlreadyOpen   = errors.New("already open")
	ErrAlreadyClosed = errors.New("already closed")
)

type Openable interface {
	Open() error
	Close() error
	IsOpen() bool
}

func EnsureOpen(obj Openable) error {
	if obj.IsOpen() {
		return nil
	} else {
		return obj.Open()
	}
}

func EnsureClosed(obj Openable) error {
	if obj.IsOpen() {
		return obj.Close()
	} else {
		return nil
	}
}

func MustClosed(obj Openable) {
	if obj.IsOpen() {
		err := obj.Close()
		if err != nil {
			panic(ErrorHandler(err))
		}
	}
}
