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
	"testing"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/common"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

const (
	podNetNS   = "inode://4/4026534362"
	otherNetNS = "inode://4/4026534999"
)

// brokeredConnection is shaped the way nsmgr reports one back over
// MonitorConnections: index 1, the pod's own segment first.
func brokeredConnection(podName, id, inodeURL string, expires time.Time) *networkservice.Connection {
	return &networkservice.Connection{
		Id:     id,
		Labels: map[string]string{"podName": podName},
		Mechanism: &networkservice.Mechanism{
			Cls:        "LOCAL",
			Type:       kernelmech.MECHANISM,
			Parameters: map[string]string{common.InodeURL: inodeURL, "name": "nsm0"},
		},
		Path: &networkservice.Path{
			Index: 1,
			PathSegments: []*networkservice.PathSegment{
				{Name: podName, Id: id, Expires: timestamppb.New(expires)},
				{Name: "nsmgr-xyz", Id: "nsmgr-segment", Expires: timestamppb.New(expires)},
			},
		},
	}
}

// A connection belonging to an earlier incarnation of the pod names a network
// namespace whose process is gone. Adopting one asks the forwarder to enter
// /proc/<pid>/ns/net for a dead pid, and it then answers "no such file or
// directory: all forwarders have failed" for every attach on the node -- four
// thousand of them in three minutes, with the slice router holding zero client
// interfaces and every database spanning that site unreachable.
func TestAdoptionCandidateMustMatchThePodsNetNS(t *testing.T) {
	now := time.Now().Add(9 * time.Minute)
	conns := map[string]*networkservice.Connection{
		"a": brokeredConnection("pg-dcdr-dc-a-0", "pg-dcdr-dc-a-0-0-0-AAA", otherNetNS, now),
	}

	for _, candidate := range connectionsForPod(conns, "pg-dcdr-dc-a-0") {
		if sameNetNS(candidate.GetMechanism().GetParameters()[common.InodeURL], podNetNS) {
			t.Error("a connection in a different namespace was treated as adoptable")
		}
	}
}

// The whole point: the pod's live connection is recognised, and re-issued under
// the id updatepath will match on, so the request travels the chain as a refresh
// and nothing downstream rebuilds the interface.
func TestAdoptionRewritesTheConnectionForReissue(t *testing.T) {
	now := time.Now().Add(9 * time.Minute)
	const id = "pg-dcdr-dc-a-0-3-0-BBB"
	conns := map[string]*networkservice.Connection{
		"a": brokeredConnection("pg-dcdr-dc-a-0", id, podNetNS, now),
	}

	candidates := connectionsForPod(conns, "pg-dcdr-dc-a-0")
	if len(candidates) != 1 {
		t.Fatalf("found %d adoption candidates, want 1", len(candidates))
	}
	if !sameNetNS(candidates[0].GetMechanism().GetParameters()[common.InodeURL], podNetNS) {
		t.Fatal("the pod's own connection was rejected by the namespace guard")
	}

	adopted := candidates[0].Clone()
	adopted.Id = adopted.GetPath().GetPathSegments()[0].GetId()
	adopted.GetPath().Index = 0

	// updatepath matches on (Index, PathSegments[Index].Name) and then reuses
	// PathSegments[Index].Id. Both must line up or it appends a segment and we
	// get a brand new connection -- the rebuild this exists to avoid.
	if adopted.GetPath().GetIndex() != 0 {
		t.Errorf("Path.Index = %d, want 0", adopted.GetPath().GetIndex())
	}
	if adopted.GetId() != id {
		t.Errorf("adopted id = %q, want the pod segment's id %q", adopted.GetId(), id)
	}
	if got := adopted.GetPath().GetPathSegments()[0].GetName(); got != "pg-dcdr-dc-a-0" {
		t.Errorf("segment 0 name = %q, want the pod name", got)
	}
	if got := adopted.GetMechanism().GetParameters()[common.InodeURL]; got != podNetNS {
		t.Errorf("adopted mechanism targets %q, want the pod's namespace %q", got, podNetNS)
	}
}

// Newest first, so a restart resumes the connection that was most recently
// refreshed rather than a leftover from an earlier incarnation.
func TestAdoptionPrefersTheMostRecentlyRefreshedConnection(t *testing.T) {
	old := time.Now().Add(1 * time.Minute)
	fresh := time.Now().Add(9 * time.Minute)
	conns := map[string]*networkservice.Connection{
		"old":   brokeredConnection("runfix-0", "runfix-0-0-0-OLD", podNetNS, old),
		"fresh": brokeredConnection("runfix-0", "runfix-0-4-0-NEW", podNetNS, fresh),
	}

	candidates := connectionsForPod(conns, "runfix-0")
	if len(candidates) != 2 {
		t.Fatalf("found %d candidates, want 2", len(candidates))
	}
	if got := candidates[0].GetPath().GetPathSegments()[0].GetId(); got != "runfix-0-4-0-NEW" {
		t.Errorf("first candidate is %q, want the most recently refreshed one", got)
	}
}
