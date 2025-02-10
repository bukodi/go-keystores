package utils

func SafeClose[T any](ch chan T) (isOk bool) {
	defer func() {
		err := recover()
		if err != nil {
			isOk = false
		}
	}()
	close(ch)
	return true
}

func SafePut[T any](ch chan<- T, v T) (isOk bool) {
	defer func() {
		err := recover()
		if err != nil {
			isOk = false
		}
	}()
	ch <- v
	return true
}
