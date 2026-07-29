//go:build linux
// +build linux

package main

import (
	"context"
	"net/url"
	"testing"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/nsurl"
)

// appPodInodeURL is the shape of the value the client sidecar sends us over
// gRPC: the netns of the pod that actually wants the interface. It is never
// our own netns.
const appPodInodeURL = "inode://4/4026533901"

// newBrokeredRequest builds the request exactly the way handlensmtask does, so
// that the tests below exercise the real thing rather than a simplification.
func newBrokeredRequest(t *testing.T) *networkservice.NetworkServiceRequest {
	t.Helper()

	u, err := url.Parse("kernel://vl3-service-slice/nsm0")
	if err != nil {
		t.Fatalf("parsing network service url: %v", err)
	}

	mech := (*nsurl.NSURL)(u).Mechanism()
	mech.Parameters["inodeURL"] = appPodInodeURL

	return &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{
			Id:             "iperf-server-1-0-0-Ab3xYz01",
			NetworkService: (*nsurl.NSURL)(u).NetworkService(),
			Mechanism:      mech,
		},
		MechanismPreferences: []*networkservice.Mechanism{mech},
	}
}

// TestKernelClientDiscardsCallerSuppliedInodeURL is a characterization test for
// upstream behaviour we have to work around, not for behaviour we want.
//
// kernel.NewClient() calls Mechanism.SetNetNSURL unconditionally on every
// Request, and kernel.NetNSURL is an alias for common.InodeURL -- the same map
// key. So the app pod's netns that we carefully threaded in from ProcessPod is
// gone by the time the request leaves the chain, replaced by a reference to
// whichever netns this process is running in.
//
// That is why heal is disabled in handlensmtask: heal replays the stored
// mechanism, and the stored mechanism points at us. Only a fresh ProcessPod
// call carries a correct target.
//
// If this test ever fails, upstream has fixed the clobber and the decision to
// drop heal is worth revisiting.
func TestKernelClientDiscardsCallerSuppliedInodeURL(t *testing.T) {
	request := newBrokeredRequest(t)

	if got := request.MechanismPreferences[0].Parameters["inodeURL"]; got != appPodInodeURL {
		t.Fatalf("precondition: inodeURL = %q, want %q", got, appPodInodeURL)
	}

	if _, err := chain.NewNetworkServiceClient(kernel.NewClient()).
		Request(context.Background(), request); err != nil {
		t.Fatalf("request through kernel client: %v", err)
	}

	got := request.MechanismPreferences[0].Parameters["inodeURL"]
	if got == appPodInodeURL {
		t.Fatalf("inodeURL survived the kernel client (= %q); upstream no longer "+
			"clobbers the target netns, so healing in the broker may be safe again", got)
	}
	t.Logf("kernel client rewrote inodeURL %q -> %q", appPodInodeURL, got)
}

// TestBrokeredRequestNamesTheRequestedInterface guards the other half of the
// mechanism we depend on: the interface name from the network service URL has
// to survive, otherwise the app pod gets a connection-id-named veth instead of
// nsm0 and nothing downstream recognises it.
func TestBrokeredRequestNamesTheRequestedInterface(t *testing.T) {
	request := newBrokeredRequest(t)

	if _, err := chain.NewNetworkServiceClient(kernel.NewClient()).
		Request(context.Background(), request); err != nil {
		t.Fatalf("request through kernel client: %v", err)
	}

	if got := request.MechanismPreferences[0].Parameters["name"]; got != "nsm0" {
		t.Errorf("interface name = %q, want %q", got, "nsm0")
	}
}
