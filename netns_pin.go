package main

import (
	"context"

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
	inodeURL string
}

// NewNetNSPinClient returns a client that pins the kernel mechanism's netns to inodeURL.
func NewNetNSPinClient(inodeURL string) networkservice.NetworkServiceClient {
	return &netnsPinClient{inodeURL: inodeURL}
}

func (c *netnsPinClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	c.pin(request.GetConnection().GetMechanism())
	for _, m := range request.GetMechanismPreferences() {
		c.pin(m)
	}
	return next.Client(ctx).Request(ctx, request, opts...)
}

func (c *netnsPinClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	c.pin(conn.GetMechanism())
	return next.Client(ctx).Close(ctx, conn, opts...)
}

func (c *netnsPinClient) pin(m *networkservice.Mechanism) {
	if c.inodeURL == "" || m == nil || m.GetType() != kernelmech.MECHANISM {
		return
	}
	if m.GetParameters() == nil {
		m.Parameters = make(map[string]string)
	}
	m.GetParameters()[common.InodeURL] = c.inodeURL
}
