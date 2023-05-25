package server

import "sync"

type Counter struct {
	sync.RWMutex
	count int
}

func (counter *Counter) GetNoLock() int {
	return counter.count
}

func (counter *Counter) Get() int {
	counter.RLock()
	defer counter.RUnlock()
	return counter.count
}

func (counter *Counter) Increment() {
	counter.count = counter.count + 1
}

func (counter *Counter) Decrement() {
	counter.Lock()
	counter.count = counter.count - 1
	counter.Unlock()
}
