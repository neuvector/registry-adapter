package server

import "sync"

type Counter struct {
	sync.RWMutex
	count int
}

func (workload *Counter) GetNoLock() int {
	return workload.count
}

func (workload *Counter) Get() int {
	workload.RLock()
	defer workload.RUnlock()
	return workload.count
}

func (workload *Counter) Increment() {
	workload.count = workload.count + 1
}

func (workload *Counter) Decrement() {
	workload.Lock()
	workload.count = workload.count - 1
	workload.Unlock()
}
