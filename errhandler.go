package keystores

import "github.com/pkg/errors"

var ErrorHandler func(err error, context ...interface{}) error

func init() {
	ErrorHandler = defaultErrorHandler
}

func defaultErrorHandler(err error, context ...interface{}) error {
	return errors.WithStack(err)
}
