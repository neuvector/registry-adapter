package server

import "sync"

type ScanRequestQueue struct {
	sync.RWMutex
	queue []ScanRequest
}

func (scanRequestQueue *ScanRequestQueue) enqueue(newRequest ScanRequest) {
	scanRequestQueue.queue = append(scanRequestQueue.queue, newRequest)
}

func (scanRequestQueue *ScanRequestQueue) dequeue(newRequest ScanRequest) ScanRequest {
	current := scanRequestQueue.queue[0]
	if len(scanRequestQueue.queue) == 1 {
		scanRequestQueue.queue = []ScanRequest{}
		return current
	}
	scanRequestQueue.queue = scanRequestQueue.queue[1:]
	return current
}
