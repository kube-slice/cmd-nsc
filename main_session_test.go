//go:build linux

package main

import (
	"context"
	"sync"
	"sync/atomic"
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

// A broker that exits without closing its connections leaves them registered
// with a token nobody refreshes. NSM closes them when they expire, ten minutes
// later, and that close removes the interface by name in the pod's namespace --
// by then the live interface of whatever rebuilt the pod. Shutdown has to end
// the sessions itself.
func TestCloseAllSessionsClosesEveryLiveSession(t *testing.T) {
	s := &server{sessions: make(map[string]*podSession)}

	var cancelled int32
	for _, pod := range []string{"pg-0", "pg-1", "pg-2"} {
		release := s.takeOver(pod, func() { atomic.AddInt32(&cancelled, 1) })
		// A session ends by running its release, which is what closes done.
		// Real sessions do that from handlensmtask's defer, after the Close.
		go func(release func()) {
			time.Sleep(10 * time.Millisecond)
			release()
		}(release)
	}

	closed, live := s.closeAllSessions(5 * time.Second)
	if live != 3 || closed != 3 {
		t.Errorf("closed %d of %d sessions, want 3 of 3", closed, live)
	}
	if got := atomic.LoadInt32(&cancelled); got != 3 {
		t.Errorf("cancelled %d sessions, want 3", got)
	}
}

// A session that will not finish must not hold the process past its termination
// grace period: being killed mid-shutdown is what leaves connections registered.
func TestCloseAllSessionsGivesUpAtTheDeadline(t *testing.T) {
	s := &server{sessions: make(map[string]*podSession)}
	s.takeOver("wedged", func() {}) // never released

	start := time.Now()
	closed, live := s.closeAllSessions(100 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("waited %v for a wedged session, want to give up at the deadline", elapsed)
	}
	if closed != 0 || live != 1 {
		t.Errorf("closed %d of %d, want 0 of 1", closed, live)
	}
}

// A session ends by being cancelled -- that is how both shutdown and pod
// handover end one -- and the teardown that follows must still be able to talk
// to the nsmgr. Deriving the close deadline from the session's own context
// produced a context that was already expired before Close was called: every
// Close failed instantly with DeadlineExceeded, the shutdown counted the
// session as closed anyway, and the connection stayed registered. Those
// orphans are what later carry a dead process's netns and take down attaches
// node-wide.
func TestTeardownContextSurvivesSessionCancellation(t *testing.T) {
	sessionCtx, cancel := context.WithCancel(context.Background())
	cancel() // exactly the state teardown runs in

	closeCtx, cancelClose := context.WithTimeout(context.WithoutCancel(sessionCtx), staleCloseTimeout)
	defer cancelClose()

	if err := closeCtx.Err(); err != nil {
		t.Fatalf("close context is already dead before Close is called: %v", err)
	}
	deadline, ok := closeCtx.Deadline()
	if !ok {
		t.Fatal("close context has no deadline, so a hung Close would block shutdown")
	}
	if remaining := time.Until(deadline); remaining < staleCloseTimeout/2 {
		t.Errorf("close budget is %v, want close to %v", remaining, staleCloseTimeout)
	}

	// The naive form is what shipped, and it is dead on arrival.
	naiveCtx, cancelNaive := context.WithTimeout(sessionCtx, staleCloseTimeout)
	defer cancelNaive()
	if naiveCtx.Err() == nil {
		t.Error("expected a context derived from the cancelled session to be dead; the regression guard is not testing anything")
	}
}
