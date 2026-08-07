//go:build linux
// +build linux

// Copyright (c) 2026 Avesha, Inc. All rights reserved.
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

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/common"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

// netnsClient keeps every request this broker sends pointed at the network
// namespace of the pod the connection belongs to.
//
// kernel.NewClient() rewrites the mechanism's netns on every request with
// file:///proc/thread-self/ns/net -- this process -- and kernel.NetNSURL is an
// alias of common.InodeURL, so it overwrites the very parameter that carries
// the application pod's namespace. A sidecar could ignore that, because its
// own namespace was the right answer. A broker cannot: the answer is a
// different pod every time.
//
// The initial request survives that only by accident: the pod's value is an
// inode:// URL, sendfd only converts file:// values into descriptors, and the
// connection's mechanism therefore reaches the forwarder unmodified. Any
// internally triggered replay loses it -- heal replays with reselect, which
// clears the connection's mechanism and leaves only the preference the kernel
// client just rewrote, so the interface gets built in this pod instead of the
// application's. That is what a heal-enabled broker leaves behind: a stray
// nsm0 holding an overlay address, and a dead veth per attempt.
//
// This element runs immediately after the kernel client and before sendfd, so
// it has the last word on the value that reaches the wire, on the first
// request and on every replay alike.
type netnsClient struct {
	inodeURL    string
	ownInodeURL string
}

// NewNetNSClient returns a client that stamps inodeURL, the network namespace
// of the pod this chain serves, onto every kernel mechanism it forwards.
//
// ownInodeURL is this process's own namespace. It is not used to build
// anything: it is the value the result is checked against, so that a request
// which would have created an interface in the broker fails loudly instead.
func NewNetNSClient(inodeURL, ownInodeURL string) networkservice.NetworkServiceClient {
	return &netnsClient{inodeURL: inodeURL, ownInodeURL: ownInodeURL}
}

// OwnNetNSInodeURL returns this process's network namespace in the inode://
// form the sidecar sends, for use as the guard value.
func OwnNetNSInodeURL() (string, error) {
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", fmt.Errorf("reading own network namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("reading own network namespace: unexpected stat type %T", info.Sys())
	}
	return fmt.Sprintf("inode://4/%d", stat.Ino), nil
}

// sameNetNS compares two netns references by inode number alone. The host
// component is written differently by different producers (the sidecar
// hardcodes 4, grpcfd uses the real device number) and the forwarder ignores
// it, so comparing whole strings would miss a match.
func sameNetNS(a, b string) bool {
	inode := func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "inode" {
			return ""
		}
		return strings.TrimPrefix(parsed.Path, "/")
	}
	left, right := inode(a), inode(b)
	return left != "" && left == right
}

func (c *netnsClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	// Both, not either: retry, begin and the mechanism dispatcher all clone the
	// request, so the connection's mechanism and the preference that produced
	// it are not the same object by the time they get here, and sendfd reads
	// both.
	c.stamp(request.GetConnection().GetMechanism())
	for _, mechanism := range request.GetMechanismPreferences() {
		c.stamp(mechanism)
	}

	// Nothing below this point may target this process. Building an interface
	// in the broker is never a useful outcome: the pod that asked for it stays
	// disconnected and the broker keeps the debris. Fail the request instead,
	// so the pod's sidecar can ask again with a namespace that is current.
	if err := c.refuseOwnNetNS(request.GetConnection().GetMechanism()); err != nil {
		return nil, err
	}
	for _, mechanism := range request.GetMechanismPreferences() {
		if err := c.refuseOwnNetNS(mechanism); err != nil {
			return nil, err
		}
	}

	return next.Client(ctx).Request(ctx, request, opts...)
}

func (c *netnsClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	// begin closes with the connection it stored, whose mechanism names this
	// process. Without stamping, a close would ask the forwarder to remove an
	// interface from the broker's namespace instead of the pod's.
	c.stamp(conn.GetMechanism())

	return next.Client(ctx).Close(ctx, conn, opts...)
}

// refuseOwnNetNS reports an error if mechanism would send the forwarder to
// this process's own namespace.
func (c *netnsClient) refuseOwnNetNS(mechanism *networkservice.Mechanism) error {
	if c.ownInodeURL == "" || mechanism == nil || mechanism.GetType() != kernelmech.MECHANISM {
		return nil
	}
	target := mechanism.GetParameters()[common.InodeURL]
	if sameNetNS(target, c.ownInodeURL) {
		return fmt.Errorf("refusing to build an interface in the broker's own network namespace (%v)", target)
	}
	return nil
}

func (c *netnsClient) stamp(mechanism *networkservice.Mechanism) {
	if c.inodeURL == "" || mechanism == nil {
		return
	}
	if mechanism.GetType() != kernelmech.MECHANISM {
		return
	}
	if mechanism.GetParameters() == nil {
		mechanism.Parameters = make(map[string]string)
	}
	mechanism.GetParameters()[common.InodeURL] = c.inodeURL
}
