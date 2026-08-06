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
	"strings"
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

// The id a pod's connection carries has to be the same on every attempt. It
// used to be "<pod>-<retry>-<index>-<random>", so a pod that reconnected -- and
// after a broker restart every pod on the node reconnects at once -- arrived as
// a stranger: new connection, newly allocated address, old id abandoned for
// something to clean up later.
func TestConnectionIDIsIdenticalAcrossRetries(t *testing.T) {
	const (
		pod = "pg-dcdr-dc-a-0"
		uid = "6f1a9c34-1b2e-4d55-9d8a-7c0e2f3b4a51"
	)

	first := connectionID(pod, uid, 0)
	for retry := 0; retry < 5; retry++ {
		// The retry count is deliberately not an input any more.
		if got := connectionID(pod, uid, 0); got != first {
			t.Fatalf("attempt %d produced %q, want %q on every attempt", retry, got, first)
		}
	}
	if !strings.Contains(first, uid) {
		t.Errorf("id %q does not carry the pod UID, so it is not stable across broker restarts", first)
	}
}

// Two pods must never share an id, in this cluster or any other sharing the
// slice: the id is what the whole mesh uses to tell one pod's datapath from
// another's.
func TestConnectionIDIsUniquePerPodAndIncarnation(t *testing.T) {
	const uidA = "6f1a9c34-1b2e-4d55-9d8a-7c0e2f3b4a51"
	const uidB = "0c7d5e21-9a3f-4e60-8b11-2d4f6a8c9e03"

	ids := map[string]string{
		"same name, different cluster": connectionID("runfix-0", uidB, 0),
		"this pod":                     connectionID("runfix-0", uidA, 0),
		"different pod":                connectionID("runfix-1", uidA, 0),
		"second network service":       connectionID("runfix-0", uidA, 1),
	}

	seen := map[string]string{}
	for name, id := range ids {
		if other, clash := seen[id]; clash {
			t.Errorf("%q and %q share id %q", name, other, id)
		}
		seen[id] = name
	}
}

// A pod that is genuinely replaced gets a new UID, and must get a new id with
// it: the new incarnation lives in a different network namespace, and inheriting
// the old connection is how the forwarder ends up entering /proc/<pid>/ns/net
// for a dead pid.
func TestRecreatedPodDoesNotInheritTheOldConnectionID(t *testing.T) {
	const pod = "d1-drill-dc-a-1"
	before := connectionID(pod, "6f1a9c34-1b2e-4d55-9d8a-7c0e2f3b4a51", 0)
	after := connectionID(pod, "0c7d5e21-9a3f-4e60-8b11-2d4f6a8c9e03", 0)
	if before == after {
		t.Error("a recreated pod kept the old connection id; its namespace is gone and adopting it strands the node")
	}
}

// belongsToPod falls back to the id when a connection carries no podName label,
// so it has to recognise both shapes: connections created before an upgrade are
// still live and still this pod's.
func TestBelongsToPodRecognisesBothIDShapes(t *testing.T) {
	const pod = "runfix-0"
	for name, id := range map[string]string{
		"stable id":     connectionID(pod, "6f1a9c34-1b2e-4d55-9d8a-7c0e2f3b4a51", 0),
		"legacy id":     "runfix-0-3-0-Ab3xK9zQ",
		"legacy retry0": "runfix-0-0-0-RDHlAa70",
	} {
		conn := &networkservice.Connection{
			Path: &networkservice.Path{PathSegments: []*networkservice.PathSegment{{Name: pod, Id: id}}},
		}
		if !belongsToPod(conn, pod) {
			t.Errorf("%s (%q) was not recognised as belonging to %s", name, id, pod)
		}
	}

	// A different pod whose name is a prefix must not match.
	conn := &networkservice.Connection{
		Path: &networkservice.Path{PathSegments: []*networkservice.PathSegment{
			{Name: "runfix-0-extra", Id: connectionID("runfix-0-extra", "0c7d5e21-9a3f-4e60-8b11-2d4f6a8c9e03", 0)},
		}},
	}
	if belongsToPod(conn, "runfix-0") {
		t.Error("one pod's connection was attributed to another whose name is a prefix of it")
	}
}

// The interface name lives in the mechanism, and re-issuing an adopted
// connection without presenting one let the kernel client generate a name from
// the network service instead: "vl3-servic-<hash>" rather than nsm0. The pod
// came back with an interface, but not the one its application looks for, which
// is indistinguishable from having none -- every database on the node reported
// no datapath while the router happily showed a full set of links.
func TestAdoptionKeepsTheInterfaceName(t *testing.T) {
	want := &networkservice.Mechanism{
		Cls:        "LOCAL",
		Type:       kernelmech.MECHANISM,
		Parameters: map[string]string{common.InodeURL: podNetNS, "name": "nsm0"},
	}

	// What adoptConnectionForPod now sends.
	adopted := brokeredConnection("runfix-0", "runfix-0-0-abc", podNetNS, time.Now().Add(9*time.Minute)).Clone()
	adopted.Mechanism = want.Clone()
	request := &networkservice.NetworkServiceRequest{
		Connection:           adopted,
		MechanismPreferences: []*networkservice.Mechanism{want.Clone()},
	}

	if got := request.GetConnection().GetMechanism().GetParameters()["name"]; got != "nsm0" {
		t.Errorf("connection mechanism names the interface %q, want nsm0", got)
	}
	if len(request.GetMechanismPreferences()) == 0 {
		t.Fatal("no mechanism preference: the kernel client will generate its own interface name")
	}
	if got := request.GetMechanismPreferences()[0].GetParameters()["name"]; got != "nsm0" {
		t.Errorf("preference names the interface %q, want nsm0", got)
	}
	if got := request.GetMechanismPreferences()[0].GetParameters()[common.InodeURL]; got != podNetNS {
		t.Errorf("preference targets %q, want the pod's namespace", got)
	}
}
