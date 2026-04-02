package utils

import (
	"fmt"
	"log/slog"
	"strings"
)

func SErr(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.Any("err", err)
}

func ToAnySlice(slogAttrs []slog.Attr) []any {
	attrs := make([]any, 0, len(slogAttrs))
	for _, sa := range slogAttrs {
		attrs = append(attrs, sa)
	}
	return attrs
}

const LevelTrace slog.Level = slog.LevelDebug - 4

func truncateSourcePath(src *slog.Source) {
	if src == nil {
		return
	}
	posL := strings.LastIndex(src.File, "/")
	if posL < 0 {
		return
	} else {
		src.File = src.File[posL+1:]
	}
}

func sourceToString(src *slog.Source) string {
	if src == nil {
		return ""
	}
	ret := src.File
	posL := strings.LastIndex(src.File, "/")
	if posL > 0 {
		ret = src.File[posL+1:]
	}
	return fmt.Sprintf("%s:%d", ret, src.Line)
}
