package main

import "testing"

// NSM heals a connection by id. If the id changes between attempts, the MonitorConnections lookup
// in handlensmtask cannot find the previous connection, so every reconnect builds a new one: the
// client gets a fresh overlay address and the old connection's veth is stranded on the vl3 router.
// That is the behaviour this test exists to prevent regressing.
func TestConnectionIDIsStableAcrossReconnects(t *testing.T) {
	first := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo", count: 0}
	// Same pod, later reconnect: the sidecar increments RetryCount on every attempt.
	later := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo", count: 7}

	if got, want := connectionID(later, 0), connectionID(first, 0); got != want {
		t.Errorf("connection id changed across reconnects: %q != %q", got, want)
	}
}

func TestConnectionIDIsStableWhenCalledRepeatedly(t *testing.T) {
	c := nscClient{podName: "pg-dcdr-dc-a-0", namespace: "demo"}

	if a, b := connectionID(c, 0), connectionID(c, 0); a != b {
		t.Errorf("connection id is not deterministic: %q != %q", a, b)
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
