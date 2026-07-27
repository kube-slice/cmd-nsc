package main

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/common"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

// netnsPinClient forces the kernel mechanism to target the netns of the pod we are connecting on
// behalf of, rather than our own.
//
// The SDK's kernel mechanism client assumes the classic NSM layout, where the client runs inside
// the pod that should receive the interface, so it hardcodes the target:
//
//	mechanism.SetNetNSURL(netNSURL)   // file:///proc/thread-self/ns/net
//
// That overwrite is unconditional, so the inodeURL the sidecar reports for its own pod is
// discarded. sendfd then turns that file URL into an fd for *this* process's netns, and the
// forwarder dutifully creates the veth here in nsc-grpc-server instead of in the application pod.
// The pod is left without nsm0 while NSM reports the connection as established, and every retry
// leaves another dead veth behind in this namespace.
//
// Sitting between the mechanisms client and sendfd, this element restores the intended target
// before the fd is taken.
type netnsPinClient struct {
	// inodeURL identifies the target namespace itself, and stays valid for the life of the pod.
	inodeURL string
	// resolve turns that into a path. Called per request rather than once, because the path is
	// /proc/<pid>/ns/net and the process it names can exit while the namespace lives on -- a
	// container restart is enough. A stale path would send every later heal to a dead target.
	resolve func(string) (string, error)
}

// NewNetNSPinClient returns a client that pins the kernel mechanism to the netns identified by
// inodeURL, resolving it to a usable path on each request.
func NewNetNSPinClient(inodeURL string) networkservice.NetworkServiceClient {
	return &netnsPinClient{inodeURL: inodeURL, resolve: resolveNetNSFileURL}
}

func (c *netnsPinClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	netNSURL, err := c.currentNetNSURL()
	if err != nil {
		return nil, err
	}
	pin(request.GetConnection().GetMechanism(), netNSURL)
	for _, m := range request.GetMechanismPreferences() {
		pin(m, netNSURL)
	}
	return next.Client(ctx).Request(ctx, request, opts...)
}

// currentNetNSURL resolves the target namespace afresh, so a path that named a since-exited
// process is replaced rather than reused.
func (c *netnsPinClient) currentNetNSURL() (string, error) {
	if c.inodeURL == "" {
		return "", nil
	}
	netNSURL, err := c.resolve(c.inodeURL)
	if err != nil {
		return "", fmt.Errorf("resolving netns %q: %w", c.inodeURL, err)
	}
	return netNSURL, nil
}

func (c *netnsPinClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	// A namespace that has already gone is not a reason to refuse to tear the connection down.
	if netNSURL, err := c.currentNetNSURL(); err == nil {
		pin(conn.GetMechanism(), netNSURL)
	}
	return next.Client(ctx).Close(ctx, conn, opts...)
}

func pin(m *networkservice.Mechanism, netNSURL string) {
	if netNSURL == "" || m == nil || m.GetType() != kernelmech.MECHANISM {
		return
	}
	if m.GetParameters() == nil {
		m.Parameters = make(map[string]string)
	}
	m.GetParameters()[common.InodeURL] = netNSURL
}
