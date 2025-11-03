// Copyright (c) 2021 Cisco and/or its affiliates.
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

package connect

import (
	"context"
	"time"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/networkservicemesh/sdk/pkg/networkservice/common/clientconn"
)

type connectClient struct {
	cancel context.CancelFunc
}

const (
	loadAttempts    = 50
	loadSleepMillis = 50
)

// NewClient - returns a connect chain element
func NewClient(cancelFunc context.CancelFunc) networkservice.NetworkServiceClient {
	return &connectClient{cancel: cancelFunc}
}

func (c *connectClient) tryLoadClientConn(ctx context.Context) (grpc.ClientConnInterface, bool) {
	for i := 0; i < loadAttempts; i++ {
		// If caller's ctx is done, stop retrying immediately.
		select {
		case <-ctx.Done():
			return nil, false
		default:
		}

		if cc, loaded := clientconn.Load(ctx); loaded {
			return cc, true
		}

		time.Sleep(loadSleepMillis * time.Millisecond)
	}
	return nil, false
}

func (c *connectClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	cc, loaded := c.tryLoadClientConn(ctx)
	if !loaded {
		// If we have a cancel func, call it to signal higher-level shutdown/retry logic.
		if c.cancel != nil {
			c.cancel()
		}
		return nil, errors.New("no grpc.ClientConnInterface provided after retries")
	}
	conn, err := networkservice.NewNetworkServiceClient(cc).Request(ctx, request, opts...)
	return conn, err
}

func (c *connectClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cc, loaded := c.tryLoadClientConn(ctx)
	if !loaded {
		if c.cancel != nil {
			c.cancel()
		}
		return nil, errors.New("no grpc.ClientConnInterface provided after retries")
	}
	return networkservice.NewNetworkServiceClient(cc).Close(ctx, conn, opts...)
}
