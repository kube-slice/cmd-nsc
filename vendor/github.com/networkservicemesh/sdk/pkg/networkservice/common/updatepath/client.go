// Copyright (c) 2020-2022 Cisco Systems, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package updatepath

import (
	"context"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

// updatePathClient is the client that updates connection path
type updatePathClient struct {
	name string
}

// NewClient creates a new updatePath client to update connection path.
//
// name - name of the client
//
// Workflows are documented in common.go
func NewClient(name string) networkservice.NetworkServiceClient {
	return &updatePathClient{name: name}
}

// ensurePreviousExpires sets Expires on the last path segment if nil
func ensurePreviousExpires(path *networkservice.Path) {
	if path == nil {
		return
	}
	l := len(path.PathSegments)
	if l == 0 {
		return
	}
	if path.PathSegments[l-1].Expires == nil {
		path.PathSegments[l-1].Expires = timestamppb.New(time.Now().Add(1 * time.Minute))
	}
}

// Request updates the path and ensures expiration
func (i *updatePathClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (conn *networkservice.Connection, err error) {
	if request.Connection == nil {
		request.Connection = &networkservice.Connection{}
	}

	// Ensure previous path segment has Expires before updating path
	if request.Connection.Path != nil {
		ensurePreviousExpires(request.Connection.Path)
	}

	var index uint32
	request.Connection, index, err = updatePath(request.Connection, i.name)
	if err != nil {
		return nil, err
	}

	conn, err = next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}

	// Ensure current connection path segment has Expires
	if conn.Path != nil {
		ensurePreviousExpires(conn.Path)
	}

	conn.Id = conn.Path.PathSegments[index].Id
	conn.Path.Index = index

	return conn, err
}

// Close updates the path and ensures expiration
func (i *updatePathClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (_ *empty.Empty, err error) {
	// Ensure previous path segment has Expires before closing
	if conn.Path != nil {
		ensurePreviousExpires(conn.Path)
	}

	conn, _, err = updatePath(conn, i.name)
	if err != nil {
		return nil, err
	}

	// Ensure after update as well
	if conn.Path != nil {
		ensurePreviousExpires(conn.Path)
	}

	return next.Client(ctx).Close(ctx, conn, opts...)
}
