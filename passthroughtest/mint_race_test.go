package passthroughtest

import (
	"strings"
	"sync"
	"testing"
)

// TestConcurrentWorkloadMintsDoNotRaceOnTheCounter: the increment was locked
// and the sequence it names the execution with was read back after unlocking,
// which the race detector reports once enough mints are in flight. It is a
// defect in this harness rather than in the runtime, and a harness that trips
// -race fails a consumer's suite for a reason that is not theirs.
//
// Internal to the package, unlike the rest of the suite, because what it drives
// is the fake host's own mint endpoint rather than a solution's passthrough.
func TestConcurrentWorkloadMintsDoNotRaceOnTheCounter(t *testing.T) {
	host := NewHost(t)
	client := host.server.Client()
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			resp, err := client.Post(host.URL()+workloadMintPath, "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wait.Wait()
	if got := host.WorkloadMints(); got != 32 {
		t.Errorf("the host counted %d mints, want 32", got)
	}
}
