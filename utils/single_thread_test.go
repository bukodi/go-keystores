package utils

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

type Executor interface {
	Submit(job func()) <-chan struct{}
}

func TestSingleThreadExecutor(t *testing.T) {
	var ex SingleThreadExecutor
	ex.Start(context.Background())

	for i := 0; i < 100; i++ {
		<-ex.Submit(func() {
			//time.Sleep(1 * time.Millisecond)
			tid := syscall.Gettid()
			t.Logf("Job %d  - OS Thread ID: %d", i, tid)
		})
		t.Logf("Job %d executed.", i)
	}
	done := ex.Shutdown()
	<-done
}

func TestDirectExecutor(t *testing.T) {
	var ex DirectExecutor

	for i := 0; i < 100; i++ {
		<-ex.Submit(func() {
			//time.Sleep(1 * time.Millisecond)
			tid := syscall.Gettid()
			t.Logf("Job %d  - OS Thread ID: %d", i, tid)
		})
		t.Logf("Job %d executed.", i)
	}
}

type ForwardExecutor struct {
	donwnstream Executor
}

var _ Executor = (*ForwardExecutor)(nil)

func (fe *ForwardExecutor) Submit(job func()) <-chan struct{} {
	return fe.donwnstream.Submit(job)
}

type DirectExecutor struct{}

var _ Executor = (*DirectExecutor)(nil)

func (de *DirectExecutor) Submit(job func()) <-chan struct{} {
	job()
	done := make(chan struct{})
	close(done)
	return done
}

type SingleThreadExecutor struct {
	workerDone chan struct{}
	jobs       chan jobWrapper

	workerCtx context.Context
	cancelFn  context.CancelFunc
	err       error // set to non-nil by the first cancel call
}

var _ Executor = (*SingleThreadExecutor)(nil)

type jobWrapper struct {
	job  func()
	done chan struct{}
}

func (ste *SingleThreadExecutor) Submit(job func()) <-chan struct{} {
	jobDone := make(chan struct{})
	ste.jobs <- jobWrapper{
		job:  job,
		done: jobDone,
	}
	return jobDone
}

func (ste *SingleThreadExecutor) Start(ctx context.Context) {
	if ste.jobs != nil {
		panic("already started")
	}
	ste.jobs = make(chan jobWrapper)

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
			case jobW, ok := <-ste.jobs:
				if !ok {
					return
				} else {
					jobW.job()
					close(jobW.done)
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
