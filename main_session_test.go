//go:build linux

package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A pod's sidecar retries ProcessPod whenever it loses its interface, so the
// broker regularly gets a second call for a pod whose previous session is
// still running. Two live sessions for one pod mean two NSM connections and
// two veths carrying the same pod name on the slice router, so the new call
// must stop the old session and wait for it before proceeding.
func TestTakeOverStopsPreviousSession(t *testing.T) {
	s := &server{sessions: make(map[string]*podSession)}
	const key = "demo/pg-dcdr-dc-b-1"

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstRelease := s.takeOver(key, firstCancel)

	firstFinished := make(chan struct{})
	go func() { // the first session, running until it is told to stop
		<-firstCtx.Done()
		firstRelease()
		close(firstFinished)
	}()

	secondDone := make(chan struct{})
	go func() {
		_, secondCancel := context.WithCancel(context.Background())
		defer s.takeOver(key, secondCancel)()
		close(secondDone)
	}()

	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second session never started: takeOver did not stop the first one")
	}
	select {
	case <-firstFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("first session was not cancelled")
	}
	if err := firstCtx.Err(); err == nil {
		t.Error("first session's context should have been cancelled")
	}
}

// Sessions for different pods are independent: one pod attaching must never
// tear down another pod's datapath.
func TestTakeOverIsPerPod(t *testing.T) {
	s := &server{sessions: make(map[string]*podSession)}

	aCtx, aCancel := context.WithCancel(context.Background())
	releaseA := s.takeOver("demo/pod-a", aCancel)
	defer releaseA()

	_, bCancel := context.WithCancel(context.Background())
	releaseB := s.takeOver("demo/pod-b", bCancel)
	defer releaseB()

	if aCtx.Err() != nil {
		t.Fatal("attaching pod-b cancelled pod-a's session")
	}
}

// The map must not grow forever: the broker runs for the life of the node and
// sees every pod that ever attaches.
func TestTakeOverReleasesMapEntry(t *testing.T) {
	s := &server{sessions: make(map[string]*podSession)}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.takeOver("demo/pod-"+string(rune('a'+i%26)), cancel)()
		}(i)
	}
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) != 0 {
		t.Fatalf("sessions map still holds %d entries, want 0", len(s.sessions))
	}
}
