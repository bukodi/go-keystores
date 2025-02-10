package utils

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestCallback(t *testing.T) {
	defer func() {
		numAtStart := runtime.NumGoroutine()
		if numAtStart != runtime.NumGoroutine() {
			t.Errorf("Number of Running Goroutines at start: %d, but at end: %d", numAtStart, runtime.NumGoroutine())
		}
	}()

	fmt.Printf("Number of Running Goroutines: %d\n", runtime.NumGoroutine())

	fnListFiles := func(ctx context.Context, baseDir string, chFilename chan<- string, chErr chan<- error) {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for i := 0; i < 10; i++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				chFilename <- fmt.Sprintf("%s/file%d", baseDir, i)
			}
		}
	}

	dirNames := []string{"dir1", "dir2", "dir3"}
	p := []Producer[string]{
		func(ctx context.Context, strings chan<- string, errors chan<- error) {
			fnListFiles(ctx, dirNames[0], strings, errors)
		},
		func(ctx context.Context, strings chan<- string, errors chan<- error) {
			fnListFiles(ctx, dirNames[1], strings, errors)
		},
		func(ctx context.Context, strings chan<- string, errors chan<- error) {
			fnListFiles(ctx, dirNames[2], strings, errors)
		},
	}
	done := Start(context.Background(), p, func(filename string) {
		t.Logf("file: %s", filename)
	}, func(err error) {
		t.Logf("error: %s", err.Error())
	})

	fmt.Printf("Number of Running Goroutines: %d\n", runtime.NumGoroutine())
	<-done
	fmt.Printf("Number of Running Goroutines: %d\n", runtime.NumGoroutine())

}
