//go:build linux

package main

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/tools/nsurl"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func conn(id string, index uint32, mechType string, expires time.Time) *networkservice.Connection {
	return withPodLabel(id, index, mechType, expires, podNameOf(id))
}

// podNameOf strips the "-<retry>-<index>-<suffix>" tail the client appends.
func podNameOf(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) < 4 {
		return id
	}
	return strings.Join(parts[:len(parts)-3], "-")
}

func withPodLabel(id string, index uint32, mechType string, expires time.Time, podName string) *networkservice.Connection {
	return &networkservice.Connection{
		Id:        id,
		Labels:    map[string]string{"podName": podName},
		Mechanism: &networkservice.Mechanism{Type: mechType},
		Path: &networkservice.Path{
			Index: index,
			PathSegments: []*networkservice.PathSegment{
				{Id: id, Expires: timestamppb.New(expires)},
			},
		},
	}
}

// A pod that reconnects gets a new id every time, so nsmgr can be holding
// several connections for it at once. Every one of them must be found, so
// they can be closed before the next connection is created; anything missed
// stays registered, expires later, and takes the pod's live interface with
// it when it is torn down.
func TestConnectionsForPod(t *testing.T) {
	now := time.Now()
	pod := "pg-dcdr-dc-b-1"
	conns := map[string]*networkservice.Connection{
		"old":     conn(pod+"-1-0-AAAAAAAA", 1, kernelmech.MECHANISM, now.Add(2*time.Minute)),
		"live":    conn(pod+"-2-0-BBBBBBBB", 1, kernelmech.MECHANISM, now.Add(9*time.Minute)),
		"other":   conn("srvd-dc-b-2-1-0-CCCCCCCC", 1, kernelmech.MECHANISM, now.Add(9*time.Minute)),
		"ourside": conn(pod+"-3-0-DDDDDDDD", 0, kernelmech.MECHANISM, now.Add(9*time.Minute)),
		// A different mechanism is still this pod's connection and still has
		// to go: the pod is attaching fresh and must not leave anything behind.
		"vfio": conn(pod+"-4-0-EEEEEEEE", 1, "VFIO", now.Add(10*time.Minute)),
	}

	got := connectionsForPod(conns, pod)

	if len(got) != 3 {
		t.Fatalf("want all 3 of the pod's connections at path index 1, got %d: %+v", len(got), got)
	}
	if got[0].GetId() != pod+"-4-0-EEEEEEEE" || got[2].GetId() != pod+"-1-0-AAAAAAAA" {
		t.Errorf("got %q first and %q last, want most recently refreshed first",
			got[0].GetId(), got[2].GetId())
	}
}

// A pod attaching for the first time has nothing to adopt and nothing to close.
func TestConnectionsForPod_NoneExisting(t *testing.T) {
	got := connectionsForPod(map[string]*networkservice.Connection{}, "fresh-pod-0")
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

// The id encoding is ambiguous: "srvd-dc-b-2-1-0-<suffix>" reads equally as
// pod "srvd-dc-b-2" retry 1 or pod "srvd-dc-b" retry 2. The podName label
// decides it, so one pod can never adopt another pod's datapath.
func TestConnectionsForPod_LabelResolvesAmbiguousID(t *testing.T) {
	now := time.Now()
	conns := map[string]*networkservice.Connection{
		"a": conn("srvd-dc-b-2-1-0-AAAAAAAA", 1, kernelmech.MECHANISM, now.Add(time.Minute)),
	}

	if got := connectionsForPod(conns, "srvd-dc-b"); len(got) != 0 {
		t.Fatalf("got %+v, want none: srvd-dc-b must not claim srvd-dc-b-2's connection", got)
	}
	if got := connectionsForPod(conns, "srvd-dc-b-2"); len(got) != 1 {
		t.Fatalf("got %+v, want the connection to be found by its own pod", got)
	}
}

// Connections predating the label still resolve by id shape.
func TestConnectionsForPod_UnlabelledFallsBackToID(t *testing.T) {
	now := time.Now()
	unlabelled := withPodLabel("pg-dcdr-dc-b-1-2-0-BBBBBBBB", 1, kernelmech.MECHANISM, now.Add(time.Minute), "")
	conns := map[string]*networkservice.Connection{"a": unlabelled}

	if got := connectionsForPod(conns, "pg-dcdr-dc-b-1"); len(got) != 1 {
		t.Fatalf("got %+v, want the unlabelled connection matched by id", got)
	}
}

// A pod may send a network service URL that nsurl cannot build a mechanism
// from. Before validation the first parameter write panicked on a nil map,
// and since grpc-go installs no recovery that panic ended the broker for
// every pod on the node -- repeatedly, because the offending pod retries
// every second.
func TestValidateNetworkService(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		wantErr bool
	}{
		{"kernel://vl3-service-slice/nsm0", false},
		{"kernel://vl3-service-slice", true}, // no interface name: nil Parameters
		{"", true},
		{"vl3-service-slice", true},
		{"kernel://", true},
	} {
		u, err := url.Parse(tc.raw)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("%q: unexpected parse error %v", tc.raw, err)
			}
			continue
		}
		if gotErr := validateNetworkService(u) != nil; gotErr != tc.wantErr {
			t.Errorf("validateNetworkService(%q) error = %v, want error = %v", tc.raw, gotErr, tc.wantErr)
		}
	}
}

// The accepted form must survive the parameter write that used to panic.
func TestValidatedNetworkServiceAcceptsParameters(t *testing.T) {
	u, err := url.Parse("kernel://vl3-service-slice/nsm0")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNetworkService(u); err != nil {
		t.Fatalf("validateNetworkService: %v", err)
	}
	mech := (*nsurl.NSURL)(u).Mechanism()
	mech.Parameters["inodeURL"] = "inode://4/12345" // panicked before validation
}
