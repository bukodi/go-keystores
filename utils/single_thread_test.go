package utils

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

func TestSingleThreadPool(t *testing.T) {
	var ex SingleThreadExecutor
	ex.Start(context.Background())

	for i := 0; i < 100; i++ {
		ex.SubmitJob(func() {
			//time.Sleep(1 * time.Millisecond)
			tid := syscall.Gettid()
			t.Logf("Job %d  - OS Thread ID: %d\n", i, tid)
		})
	}
	done := ex.Shutdown()
	<-done
}

type SingleThreadExecutor struct {
	workerDone chan struct{}
	jobs       chan func()

	workerCtx context.Context
	cancelFn  context.CancelFunc
	err       error // set to non-nil by the first cancel call
}

type Worker struct {
}

func (ste *SingleThreadExecutor) SubmitJob(job func()) {
	ste.jobs <- job
}

func (ste *SingleThreadExecutor) Start(ctx context.Context) {
	if ste.jobs != nil {
		panic("already started")
	}
	ste.jobs = make(chan func())

	ste.workerDone = make(chan struct{})
	ste.workerCtx, ste.cancelFn = context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	worker := func() {
		runtime.LockOSThread()
		defer func() {
			close(ste.workerDone)
			runtime.UnlockOSThread()
		}()

		wg.Done()
		for {
			select {
			case <-ste.workerCtx.Done():
				return
			case job, ok := <-ste.jobs:
				if !ok {
					return
				} else {
					job()
				}
			}
		}
	}

	go worker()
	wg.Wait()
}

func (ste *SingleThreadExecutor) Shutdown() <-chan struct{} {
	if ste.jobs == nil {
		panic("already shut down")
	}
	close(ste.jobs)
	return ste.workerDone
}
