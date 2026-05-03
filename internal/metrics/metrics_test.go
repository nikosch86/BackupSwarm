package metrics_test

import (
	"sync"
	"testing"

	"backupswarm/internal/metrics"
)

func TestCounters_LoadAndReset_ReturnsSumsAndZeroes(t *testing.T) {
	t.Parallel()

	var c metrics.Counters
	c.AddBytesUp(100)
	c.AddBytesDown(50)
	c.AddFilesBackedUp()
	c.AddFilesBackedUp()
	c.AddChunksStored()

	snap := c.LoadAndReset()
	if snap.BytesUp != 100 {
		t.Errorf("BytesUp = %d, want 100", snap.BytesUp)
	}
	if snap.BytesDown != 50 {
		t.Errorf("BytesDown = %d, want 50", snap.BytesDown)
	}
	if snap.FilesBackedUp != 2 {
		t.Errorf("FilesBackedUp = %d, want 2", snap.FilesBackedUp)
	}
	if snap.ChunksStored != 1 {
		t.Errorf("ChunksStored = %d, want 1", snap.ChunksStored)
	}

	second := c.LoadAndReset()
	if second != (metrics.Snapshot{}) {
		t.Errorf("second LoadAndReset = %+v, want zero (counters should reset)", second)
	}
}

func TestCounters_ConcurrentAdd_RaceFree(t *testing.T) {
	t.Parallel()

	var c metrics.Counters
	const workers = 16
	const perWorker = 1000

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for range perWorker {
				c.AddBytesUp(1)
				c.AddBytesDown(2)
				c.AddFilesBackedUp()
				c.AddChunksStored()
			}
		}()
	}
	wg.Wait()

	snap := c.LoadAndReset()
	if snap.BytesUp != workers*perWorker {
		t.Errorf("BytesUp = %d, want %d", snap.BytesUp, workers*perWorker)
	}
	if snap.BytesDown != workers*perWorker*2 {
		t.Errorf("BytesDown = %d, want %d", snap.BytesDown, workers*perWorker*2)
	}
	if snap.FilesBackedUp != workers*perWorker {
		t.Errorf("FilesBackedUp = %d, want %d", snap.FilesBackedUp, workers*perWorker)
	}
	if snap.ChunksStored != workers*perWorker {
		t.Errorf("ChunksStored = %d, want %d", snap.ChunksStored, workers*perWorker)
	}
}

func TestCounters_ZeroValueReady(t *testing.T) {
	t.Parallel()

	var c metrics.Counters
	c.AddBytesUp(7)
	snap := c.LoadAndReset()
	if snap.BytesUp != 7 {
		t.Errorf("BytesUp = %d, want 7", snap.BytesUp)
	}
}
