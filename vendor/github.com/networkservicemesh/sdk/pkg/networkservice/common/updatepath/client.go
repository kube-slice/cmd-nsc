package updatepath

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type updatePathClient struct {
	name string
}

// NewClient - creates a new updatePath client to update connection path.
func NewClient(name string) networkservice.NetworkServiceClient {
	return &updatePathClient{name: name}
}

// ensureAllExpires makes sure every path segment has Expires set
func ensureAllExpires(path *networkservice.Path) {
	if path == nil {
		fmt.Println("@@@@@@@@@@@@@@@@@@@@@")
		return
	}
	for i := range path.PathSegments {
		if path.PathSegments[i].Expires == nil {
			path.PathSegments[i].Expires = timestamppb.New(time.Now().Add(time.Minute))
		}
	}
}

// Request updates the path and ensures expiration is set
func (i *updatePathClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	if request.Connection == nil {
		request.Connection = &networkservice.Connection{}
	}
	if request.Connection.Path == nil {
		request.Connection.Path = &networkservice.Path{}
	}

	// Ensure existing path segments have Expires
	ensureAllExpires(request.Connection.Path)

	var index uint32
	var err error
	request.Connection, index, err = updatePath(request.Connection, i.name)
	if err != nil {
		return nil, err
	}

	// Forward request to next
	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}

	// Ensure Expires also after getting response
	ensureAllExpires(conn.Path)

	// Update connection ID and index (original behavior)
	conn.Id = conn.Path.PathSegments[index].Id
	conn.Path.Index = index

	return conn, nil
}

// Close updates the path and ensures expiration is set
func (i *updatePathClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	if conn.Path == nil {
		conn.Path = &networkservice.Path{}
	}

	// Ensure Expires before update
	ensureAllExpires(conn.Path)

	var err error
	conn, _, err = updatePath(conn, i.name)
	if err != nil {
		return nil, err
	}

	// Ensure Expires again after update
	ensureAllExpires(conn.Path)

	return next.Client(ctx).Close(ctx, conn, opts...)
}
