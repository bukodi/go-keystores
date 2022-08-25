package keystores

import (
	"github.com/bukodi/go-keystores/utils"
)

var ErrorHandler func(err error, context ...interface{}) error

func init() {
	ErrorHandler = defaultErrorHandler
}

func defaultErrorHandler(err error, context ...interface{}) error {
	return utils.WithStackSkip(2, err)
}
