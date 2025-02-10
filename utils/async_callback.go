package utils

import (
	"context"
	"log/slog"
	"sync"
)

// https://go101.org/article/channel-closing.html

type Producer2[T any] func(context.Context, chan<- T, chan<- error)
type Consumer2[T any] func(context.Context, <-chan T, <-chan error)

type Producer[T any] func(context.Context, chan<- T, chan<- error)

func Start[T any](ctx context.Context, producers []Producer[T], onValue func(T), onError func(error)) (done <-chan struct{}) {
	if onError == nil {
		onError = func(err error) {
			slog.ErrorContext(ctx, err.Error(), "err", err)
		}
	}
	if onValue == nil {
		onValue = func(v T) {
			slog.DebugContext(ctx, "value produced", "value", v)
		}
	}

	chValues := make(chan T)
	chErr := make(chan error)
	chDone := make(chan struct{})

	go func() {
		defer func() {
			if err := ctx.Err(); err != nil {
				onError(err)
			}
			close(chDone)
		}()
		for {
			select {
			case v, ok := <-chValues:
				if !ok {
					return
				} else {
					onValue(v)
				}
			case err, ok := <-chErr:
				if !ok {
					return
				} else {
					onError(err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		var wg sync.WaitGroup
		for _, producer := range producers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				producer(ctx, chValues, chErr)
			}()
		}
		wg.Wait()
		close(chValues)
		close(chErr)
	}()

	return chDone
}
