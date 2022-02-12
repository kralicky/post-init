package util

import (
	"sync"
	"time"
)

type SharedTimer struct {
	t          *time.Timer
	c          chan struct{}
	expired    bool
	mu         *sync.Mutex
	timeout    time.Duration
	blockCount int
	cond       *sync.Cond
	reset      chan struct{}
}

func NewSharedTimer(timeout time.Duration) *SharedTimer {
	mu := &sync.Mutex{}
	ct := &SharedTimer{
		t:     time.NewTimer(timeout),
		c:     make(chan struct{}),
		mu:    mu,
		cond:  sync.NewCond(mu),
		reset: make(chan struct{}),
	}
	go ct.run()
	return ct
}

func (ct *SharedTimer) C() <-chan struct{} {
	return ct.c
}

func (ct *SharedTimer) run() {
	for {
		select { // S1 (timer state unknown)
		case <-ct.t.C:
			ct.mu.Lock() // S2 (timer expired)
			if ct.blockCount == 0 {
				ct.expired = true
				close(ct.c)
				ct.mu.Unlock()
				return
			}
			// Block count is > 0, but the timer has expired. When the last Unblock()
			// is called, it will briefly exchange ownership of the mutex with this
			// goroutine to reset the timer at the correct time.

			// Depending on which goroutine
			ct.cond.Signal()
			// Wait for Unblock() to signal that we can continue
			ct.cond.Wait() // S3 (timer expired)
			// Reset the timer, and if
			ct.t.Reset(ct.timeout)
			ct.cond.Signal()
			// Note that in this case the mutex is unlocked in Unblock(), not here.
		case <-ct.reset:
			ct.mu.Lock()
			if !ct.t.Stop() {
				<-ct.t.C
			}
			ct.t.Reset(ct.timeout)
			ct.mu.Unlock()
		}
	}
}

func (ct *SharedTimer) Block() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.expired {
		return
	}
	ct.blockCount++
}

func (ct *SharedTimer) Unblock() {
	ct.mu.Lock()
	if ct.expired {
		ct.mu.Unlock()
		return
	}
	if ct.blockCount == 0 {
		panic("unblock called when block count is 0")
	}
	if ct.blockCount == 1 {
		// Block count is about to hit 0, but before we can change it to 0, we need
		// to know whether the timer has expired or not, by forcing run() to wait
		// at either S2 or S3.
		select {
		case ct.reset <- struct{}{}:
			// If we get here, the timer has either expired but its channel is not
			// drained, or it has not expired yet. run() will be waiting in the second
			// case, so we can safely decrement the block count and unlock the mutex.
			ct.blockCount--
		default:
			// If we get here, run() could be waiting in either S2 or S3.

			// Signal the wait condition first, while we still hold the mutex.
			// This will wake up run() if it is waiting in S3, and Wait() will now be
			// blocked trying to acquire the mutex.
			ct.cond.Signal()

			// Next, wait on the condition variable, which will unlock the mutex.
			// Either code path (S2 or S3) will signal us to wake up eventually.
			// This has the effect of atomically swapping execution states with run().
			ct.cond.Wait()

			// If run() was originally waiting at S3, it will now have completed the
			// reset routine and be back waiting at its select statement.

			// Now that run() is guaranteed to have already observed that the block
			// count is not 0, we can safely decrement the block count to 0.
			ct.blockCount--

			// Signal the wait condition again, to wake up run() if it was originally
			// waiting at S2, as it will now be waiting at S3. This is a no-op
			// otherwise.
			ct.cond.Signal()
		}
		ct.mu.Unlock()
	}
}
