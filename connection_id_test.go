package main

import "testing"

// Reusing an id after a datapath loss gets the request answered from nsmgr's cache without the
// chain being driven to the forwarder, so no interface is ever created. Each attempt must be a
// new connection.
func TestConnectionIDChangesPerAttempt(t *testing.T) {
	first := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo", count: 0}
	later := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo", count: 7}

	if connectionID(later, 0) == connectionID(first, 0) {
		t.Errorf("connection id was reused across attempts: %q", connectionID(first, 0))
	}
}

// Within a single attempt the id must not wobble: it is used for the monitor lookup and the
// request itself.
func TestConnectionIDIsStableWithinAnAttempt(t *testing.T) {
	c := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo", count: 3}

	if a, b := connectionID(c, 0), connectionID(c, 0); a != b {
		t.Errorf("connection id is not deterministic within an attempt: %q != %q", a, b)
	}
}

func TestConnectionIDDistinguishesPodsAndServices(t *testing.T) {
	a := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo"}
	b := nscClient{podName: "pg-dcdr-dc-a-1", namespace: "demo"}
	// Same pod name in a different namespace must not collide.
	c := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "other"}

	if connectionID(a, 0) == connectionID(b, 0) {
		t.Error("different pods share a connection id")
	}
	if connectionID(a, 0) == connectionID(c, 0) {
		t.Error("same pod name in different namespaces shares a connection id")
	}
	if connectionID(a, 0) == connectionID(a, 1) {
		t.Error("different network service indexes share a connection id")
	}
}
