package asyncks

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const maxKeyStores = 1000
const maxKeysPerStore = 1000
const timeout = 500 * time.Millisecond
const keyProcessTime = 1 * time.Millisecond

func TestCallback(t *testing.T) {

	xor := func(a, b [32]byte) [32]byte {
		c := [32]byte{}
		for i := 0; i < 32; i++ {
			c[i] = a[i] ^ b[i]
		}
		return c
	}
	_ = xor

	var counter atomic.Int32

	t.Logf("----------- Before start ------------")
	ksNames := make([]string, 0, maxKeyStores)
	for i := 0; i < cap(ksNames); i++ {
		ksNames = append(ksNames, fmt.Sprintf("ks%d", i))
	}
	ctx100ms, _ := context.WithTimeout(context.Background(), timeout)
	done := procWithCallbacks(ctx100ms, ksNames, func(kn KeyName) {
		counter.Add(1)
		//t.Logf("Key found: %s", kn)
	}, func(err error) {
		t.Logf("Error: %s", err.Error())
	})
	t.Logf("----------- Started ------------")
	<-done
	t.Logf("----------- Done ------------")
	t.Logf("counter=%d", counter.Load())
}

type KeyName string

func listKeys(ctx context.Context, ksName string, chKeyNames chan<- KeyName, chErr chan<- error) {
	for i := 0; i < maxKeysPerStore; i++ {
		if ctx.Err() != nil {
			return
		}
		time.Sleep(keyProcessTime)
		if i%100 == 0 {
			chErr <- fmt.Errorf(fmt.Sprintf("%s-key%d wrong", ksName, i))
		} else {
			chKeyNames <- KeyName(fmt.Sprintf("%s-key%d", ksName, i))
		}
	}
}

func procWithCallbacks(ctx context.Context, ksNames []string, onKeyFound func(KeyName), onErr func(error)) <-chan struct{} {
	chKeyNames := make(chan KeyName)
	chErr := make(chan error)
	chDone := make(chan struct{})

	go func() {
		defer func() {
			if err := ctx.Err(); err != nil {
				onErr(err)
			}
			close(chDone)
		}()
		for {
			select {
			case kn, ok := <-chKeyNames:
				if !ok {
					return
				} else {
					onKeyFound(kn)
				}
			case err, ok := <-chErr:
				if !ok {
					return
				} else {
					onErr(err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		var wg sync.WaitGroup
		for _, ksName := range ksNames {
			wg.Add(1)
			go func() {
				defer wg.Done()
				listKeys(ctx, ksName, chKeyNames, chErr)
			}()
		}
		wg.Wait()
		close(chKeyNames)
		close(chErr)
	}()

	return chDone
}
