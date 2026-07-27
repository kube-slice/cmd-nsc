package main

import (
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
	c := &netnsPinClient{inodeURL: podNetNS}
	m := &networkservice.Mechanism{
		Cls:        "LOCAL",
		Type:       kernelmech.MECHANISM,
		Parameters: map[string]string{common.InodeURL: ourOwnNetNS, "name": "nsm0"},
	}

	c.pin(m)

	if got := m.GetParameters()[common.InodeURL]; got != podNetNS {
		t.Errorf("inodeURL = %q, want %q", got, podNetNS)
	}
	if got := m.GetParameters()["name"]; got != "nsm0" {
		t.Errorf("interface name was clobbered: %q", got)
	}
}

func TestPinIgnoresNonKernelMechanisms(t *testing.T) {
	c := &netnsPinClient{inodeURL: podNetNS}
	m := &networkservice.Mechanism{
		Cls:        "LOCAL",
		Type:       "VFIO",
		Parameters: map[string]string{common.InodeURL: ourOwnNetNS},
	}

	c.pin(m)

	if got := m.GetParameters()[common.InodeURL]; got != ourOwnNetNS {
		t.Errorf("non-kernel mechanism was modified: %q", got)
	}
}

func TestPinHandlesNilAndEmpty(t *testing.T) {
	(&netnsPinClient{inodeURL: podNetNS}).pin(nil) // must not panic

	m := &networkservice.Mechanism{Type: kernelmech.MECHANISM}
	(&netnsPinClient{inodeURL: podNetNS}).pin(m)
	if got := m.GetParameters()[common.InodeURL]; got != podNetNS {
		t.Errorf("nil parameter map not populated: %q", got)
	}

	// With no inodeURL known, leave the mechanism untouched rather than blanking it.
	m2 := &networkservice.Mechanism{
		Type:       kernelmech.MECHANISM,
		Parameters: map[string]string{common.InodeURL: ourOwnNetNS},
	}
	(&netnsPinClient{inodeURL: ""}).pin(m2)
	if got := m2.GetParameters()[common.InodeURL]; got != ourOwnNetNS {
		t.Errorf("empty inodeURL should be a no-op, got %q", got)
	}
}
