package utils

/*
Copyright 2021 CodeNotary, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Original: https://github.com/codenotary/immudb/blob/master/embedded/multierr/multierr.go

import (
	"errors"
	"fmt"
)

type MultiErr struct {
	errors []error
}

func CollectError(currentError error, newError error) error {
	if newError == nil {
		return currentError
	}
	if currentError == nil {
		return newError
	}
	var currentMultiErr *MultiErr
	if multiErr, ok := currentError.(*MultiErr); ok {
		currentMultiErr = multiErr
	} else {
		currentMultiErr = NewMultiErr()
		currentMultiErr.Append(currentError)
	}
	if multiErr, ok := newError.(*MultiErr); ok {
		for _, e := range multiErr.errors {
			currentMultiErr.Append(e)
		}
	} else {
		currentMultiErr.Append(newError)
	}
	return currentMultiErr
}

func NewMultiErr() *MultiErr {
	return &MultiErr{}
}

func (me *MultiErr) Append(err error) *MultiErr {
	if err != nil {
		me.errors = append(me.errors, err)
	}

	return me
}

func (me *MultiErr) Includes(err error) bool {
	for _, e := range me.errors {
		if errors.Is(e, err) {
			return true
		}
	}

	return false
}

func (me *MultiErr) HasErrors() bool {
	return len(me.errors) > 0
}

func (me *MultiErr) Errors() []error {
	return me.errors
}

func (me *MultiErr) Reduce() error {
	if !me.HasErrors() {
		return nil
	}
	return me
}

func (me *MultiErr) Is(target error) bool {
	for _, err := range me.errors {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}

func (me *MultiErr) As(target interface{}) bool {
	for _, err := range me.errors {
		if errors.As(err, target) {
			return true
		}
	}

	return false
}

func (me *MultiErr) Error() string {
	if me.errors == nil {
		return "empty list of errors"
	}
	msg := fmt.Sprintf("%d errors:", len(me.errors))
	for i, err := range me.errors {
		msg += fmt.Sprintf("\n%d.: %s", i, err.Error())
	}
	return msg
}

func (me *MultiErr) GoString() string {
	if me.errors == nil {
		return "empty list of errors"
	}
	msg := fmt.Sprintf("%d errors:", len(me.errors))
	for i, err := range me.errors {
		msg += fmt.Sprintf("\n%d.: %#v", i, err)
	}
	return msg
}
