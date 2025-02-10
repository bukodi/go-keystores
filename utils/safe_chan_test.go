package utils

import "testing"

func TestChannelClose(t *testing.T) {
	ch1 := make(chan int, 1)

	t.Logf("len(ch1)=%d", len(ch1))
	ch1 <- 1
	t.Logf("len(ch1)=%d", len(ch1))
	v1, ok1 := <-ch1
	t.Logf("len(ch1)=%d, v=%d, ok=%t", len(ch1), v1, ok1)
	//ch1 <- 2
	if SafePut(ch1, 2) {
		t.Logf("Channel is closed")
	} else {
		t.Logf("success put")
	}
	t.Logf("len(ch1)=%d", len(ch1))
	close(ch1)
	if SafePut(ch1, 3) {
		t.Logf("success put")
	} else {
		t.Logf("Channel is closed")
	}
	t.Logf("len(ch1)=%d", len(ch1))
	v2, ok2 := <-ch1
	t.Logf("len(ch1)=%d, v=%d, ok=%t", len(ch1), v2, ok2)
	v3, ok3 := <-ch1
	t.Logf("len(ch1)=%d, v=%d, ok=%t", len(ch1), v3, ok3)
	v4, ok4 := <-ch1
	t.Logf("len(ch1)=%d, v=%d, ok=%t", len(ch1), v4, ok4)
	SafeClose(ch1)

}
