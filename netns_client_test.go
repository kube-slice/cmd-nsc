//go:build linux

package main

import (
	"context"
	"testing"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/common"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	vfiomech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vfio"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
)

// brokerInodeURL stands in for this process's own network namespace: the one
// answer that is always wrong, because an interface built there leaves the pod
// that asked for it with nothing.
const brokerInodeURL = "inode://4/4026533031"

func targetOf(mechanism *networkservice.Mechanism) string {
	return mechanism.GetParameters()[common.InodeURL]
}

// The kernel client rewrites the netns of every request with this process's
// own (see TestKernelClientDiscardsCallerSuppliedInodeURL). Running after it,
// the netns client has to put the application pod's namespace back, on the
// connection's mechanism and on the preferences, because sendfd reads both.
func TestNetNSClientRestoresThePodNamespace(t *testing.T) {
	request := newBrokeredRequest(t)

	_, err := chain.NewNetworkServiceClient(
		kernel.NewClient(),
		NewNetNSClient(appPodInodeURL, brokerInodeURL),
	).Request(context.Background(), request)
	if err != nil {
		t.Fatalf("request through the chain: %v", err)
	}

	if got := targetOf(request.GetConnection().GetMechanism()); got != appPodInodeURL {
		t.Errorf("connection mechanism targets %q, want the pod's namespace %q", got, appPodInodeURL)
	}
	if got := targetOf(request.GetMechanismPreferences()[0]); got != appPodInodeURL {
		t.Errorf("mechanism preference targets %q, want the pod's namespace %q", got, appPodInodeURL)
	}
}

// The shape of a heal replay: heal requests with begin.WithReselect(), which
// clears the connection's mechanism and leaves only the preference the kernel
// client rewrote. That is how a healing broker used to build the pod's
// interface inside itself.
func TestNetNSClientSurvivesAHealReplay(t *testing.T) {
	request := newBrokeredRequest(t)
	client := chain.NewNetworkServiceClient(
		kernel.NewClient(),
		NewNetNSClient(appPodInodeURL, brokerInodeURL),
	)

	if _, err := client.Request(context.Background(), request); err != nil {
		t.Fatalf("initial request: %v", err)
	}

	// reselect: the connection's mechanism is dropped, the stale preference stays
	request.GetConnection().Mechanism = nil

	if _, err := client.Request(context.Background(), request); err != nil {
		t.Fatalf("replayed request: %v", err)
	}

	for i, mechanism := range request.GetMechanismPreferences() {
		if got := targetOf(mechanism); got != appPodInodeURL {
			t.Errorf("preference %d targets %q after the replay, want the pod's namespace %q",
				i, got, appPodInodeURL)
		}
	}
}

// Belt and braces: even if the pod's namespace were somehow lost, a request
// that would build an interface in the broker must fail rather than succeed
// quietly. The pod stays disconnected either way; only one of the two leaves
// debris behind and hides the problem.
func TestNetNSClientRefusesToTargetTheBroker(t *testing.T) {
	request := newBrokeredRequest(t)

	_, err := chain.NewNetworkServiceClient(
		kernel.NewClient(),
		// the pod's namespace resolved to the broker's own
		NewNetNSClient(brokerInodeURL, brokerInodeURL),
	).Request(context.Background(), request)

	if err == nil {
		t.Fatal("request succeeded while targeting the broker's own namespace, want an error")
	}
}

// Closing has to name the pod too: begin closes with the connection it stored,
// whose mechanism names the broker, and a close aimed at the wrong namespace
// leaves the pod's interface in place.
func TestNetNSClientStampsClose(t *testing.T) {
	conn := newBrokeredRequest(t).GetConnection()
	conn.GetMechanism().GetParameters()[common.InodeURL] = brokerInodeURL

	_, err := chain.NewNetworkServiceClient(
		NewNetNSClient(appPodInodeURL, brokerInodeURL),
	).Close(context.Background(), conn)
	if err != nil {
		t.Fatalf("close through the chain: %v", err)
	}

	if got := targetOf(conn.GetMechanism()); got != appPodInodeURL {
		t.Errorf("close targets %q, want the pod's namespace %q", got, appPodInodeURL)
	}
}

// Only kernel mechanisms carry a netns to correct.
func TestNetNSClientLeavesOtherMechanismsAlone(t *testing.T) {
	vfio := &networkservice.Mechanism{
		Cls:        "LOCAL",
		Type:       vfiomech.MECHANISM,
		Parameters: map[string]string{common.InodeURL: "inode://4/999"},
	}
	request := &networkservice.NetworkServiceRequest{
		Connection:           &networkservice.Connection{Id: "id", Mechanism: vfio},
		MechanismPreferences: []*networkservice.Mechanism{vfio},
	}

	_, err := chain.NewNetworkServiceClient(
		NewNetNSClient(appPodInodeURL, brokerInodeURL),
	).Request(context.Background(), request)
	if err != nil {
		t.Fatalf("request through the chain: %v", err)
	}

	if got := targetOf(vfio); got != "inode://4/999" {
		t.Errorf("vfio mechanism was rewritten to %q, want it untouched", got)
	}
}

// The host component of an inode URL is written differently by different
// producers and ignored by the forwarder, so identity is the inode alone.
func TestSameNetNS(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"inode://4/4026533031", "inode://4/4026533031", true},
		{"inode://4/4026533031", "inode://64768/4026533031", true}, // same ns, different producer
		{"inode://4/4026533031", "inode://4/4026534407", false},
		{"file:///proc/thread-self/ns/net", "inode://4/4026533031", false},
		{"", "inode://4/4026533031", false},
		{"inode://4/4026533031", "", false},
	} {
		if got := sameNetNS(tc.a, tc.b); got != tc.want {
			t.Errorf("sameNetNS(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// The mechanism the kernel client builds when the request carries no
// preference of its own still has to end up pointing at the pod.
func TestNetNSClientCorrectsAGeneratedMechanism(t *testing.T) {
	request := &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{Id: "generated-0-0-Ab3xYz01"},
	}

	_, err := chain.NewNetworkServiceClient(
		kernel.NewClient(),
		NewNetNSClient(appPodInodeURL, brokerInodeURL),
	).Request(context.Background(), request)
	if err != nil {
		t.Fatalf("request through the chain: %v", err)
	}

	if len(request.GetMechanismPreferences()) == 0 {
		t.Fatal("kernel client produced no mechanism preference")
	}
	for i, mechanism := range request.GetMechanismPreferences() {
		if mechanism.GetType() != kernelmech.MECHANISM {
			continue
		}
		if got := targetOf(mechanism); got != appPodInodeURL {
			t.Errorf("generated preference %d targets %q, want the pod's namespace %q",
				i, got, appPodInodeURL)
		}
	}
}
