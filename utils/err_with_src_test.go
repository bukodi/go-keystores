package utils

import (
	"fmt"
	"log/slog"
	"testing"
)

func TestErrFormatting(t *testing.T) {
	errStdRoot := fmt.Errorf("root std error")
	dumpError(t, errStdRoot, "std root")

	errStdWrapped := fmt.Errorf("wrapped err: %w", errStdRoot)
	dumpError(t, errStdWrapped, "std wrapped")

	errMdaWrapper := HandleError(errStdWrapped, slog.String("attr1", "string value"), slog.Int("attr2", 42))
	dumpError(t, errMdaWrapper, "mda wrapped")

	errStdWrapped2 := fmt.Errorf("std wrapped 2: %w", errMdaWrapper)
	dumpError(t, errStdWrapped2, "std wrapped 2")

	errMdaWrapper2 := HandleError(errStdWrapped2, slog.String("attr3", "other value"), slog.Int("attr2", 56))
	dumpError(t, errMdaWrapper2, "mda wrapped 2")

}

func dumpError(t *testing.T, err error, title string) {
	t.Logf("---- BEGIN %s ----", title)
	t.Logf("s: %s", err)
	t.Logf("v: %v", err)
	t.Logf("+v: %+v", err)
	t.Logf("#v: %#v", err)
	t.Logf("Error(): %s", err.Error())
	if uw, ok := err.(interface{ Unwrap() error }); ok {
		t.Logf("Unwrap() error: %+v", uw.Unwrap())
	}
	if uw, ok := err.(interface{ Unwrap() []error }); ok {
		t.Logf("Unwrap() []error: %+v", uw.Unwrap())
	}
	t.Logf("---- END %s ----", title)
	t.Logf("")
}
