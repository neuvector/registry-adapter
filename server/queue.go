package server

import "sync"

type ScanRequestQueue struct {
	sync.RWMutex
	queue []ScanRequest
}

func (scanRequestQueue *ScanRequestQueue) Enqueue(newRequest ScanRequest) {
	scanRequestQueue.queue = append(scanRequestQueue.queue, newRequest)
}

func (scanRequestQueue *ScanRequestQueue) Dequeue() ScanRequest {
	current := scanRequestQueue.queue[0]
	if len(scanRequestQueue.queue) == 1 {
		scanRequestQueue.queue = []ScanRequest{}
		return current
	}
	scanRequestQueue.queue = scanRequestQueue.queue[1:]
	return current
}

func (scanRequestQueue *ScanRequestQueue) Length() int {
	return len(scanRequestQueue.queue)
}
