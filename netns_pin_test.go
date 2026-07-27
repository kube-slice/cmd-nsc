package main

import (
	"fmt"
	"testing"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/common"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
)

const (
	podNetNS    = "inode://4/4026533855" // the application pod we are connecting for
	ourOwnNetNS = "file:///proc/thread-self/ns/net"
)

// The SDK's kernel mechanism client overwrites the target netns with our own. If that survives,
// the forwarder builds the veth in nsc-grpc-server and the application pod never gets nsm0.
func TestPinRestoresPodNetNSAfterSDKOverwrite(t *testing.T) {
	m := &networkservice.Mechanism{
		Cls:        "LOCAL",
		Type:       kernelmech.MECHANISM,
		Parameters: map[string]string{common.InodeURL: ourOwnNetNS, "name": "nsm0"},
	}

	pin(m, podNetNS)

	if got := m.GetParameters()[common.InodeURL]; got != podNetNS {
		t.Errorf("inodeURL = %q, want %q", got, podNetNS)
	}
	if got := m.GetParameters()["name"]; got != "nsm0" {
		t.Errorf("interface name was clobbered: %q", got)
	}
}

func TestPinIgnoresNonKernelMechanisms(t *testing.T) {
	m := &networkservice.Mechanism{
		Cls:        "LOCAL",
		Type:       "VFIO",
		Parameters: map[string]string{common.InodeURL: ourOwnNetNS},
	}

	pin(m, podNetNS)

	if got := m.GetParameters()[common.InodeURL]; got != ourOwnNetNS {
		t.Errorf("non-kernel mechanism was modified: %q", got)
	}
}

func TestPinHandlesNilAndEmpty(t *testing.T) {
	pin(nil, podNetNS) // must not panic

	m := &networkservice.Mechanism{Type: kernelmech.MECHANISM}
	pin(m, podNetNS)
	if got := m.GetParameters()[common.InodeURL]; got != podNetNS {
		t.Errorf("nil parameter map not populated: %q", got)
	}

	// With no inodeURL known, leave the mechanism untouched rather than blanking it.
	m2 := &networkservice.Mechanism{
		Type:       kernelmech.MECHANISM,
		Parameters: map[string]string{common.InodeURL: ourOwnNetNS},
	}
	pin(m2, "")
	if got := m2.GetParameters()[common.InodeURL]; got != ourOwnNetNS {
		t.Errorf("empty inodeURL should be a no-op, got %q", got)
	}
}

// The path names a process, and that process can exit while the namespace lives on -- a container
// restart is enough. Each request must resolve again rather than reuse the first answer.
func TestPinResolvesOnEveryRequest(t *testing.T) {
	calls := 0
	c := &netnsPinClient{
		inodeURL: "inode://4/4026533855",
		resolve: func(string) (string, error) {
			calls++
			return fmt.Sprintf("file:///proc/%d/ns/net", 1000+calls), nil
		},
	}

	first, err := c.currentNetNSURL()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := c.currentNetNSURL()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 2 {
		t.Errorf("resolved %d times, want 2 -- a cached path goes stale when the process exits", calls)
	}
	if first == second {
		t.Errorf("both requests reused %q instead of re-resolving", first)
	}
}

func TestPinReportsResolutionFailure(t *testing.T) {
	c := &netnsPinClient{
		inodeURL: "inode://4/4026533855",
		resolve:  func(string) (string, error) { return "", fmt.Errorf("boom") },
	}

	if _, err := c.currentNetNSURL(); err == nil {
		t.Error("expected the resolution failure to surface, not be silently ignored")
	}
}
