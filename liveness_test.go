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
	"os"
	"syscall"
	"testing"
)

func ownInodeURLForTest(t *testing.T) string {
	t.Helper()
	url, err := OwnNetNSInodeURL()
	if err != nil {
		t.Fatalf("reading own namespace: %v", err)
	}
	return url
}

// Every path that stops the check from running has to answer "live". A check
// that cannot run says nothing about the data path, and reading its silence as
// death would have heal rebuild every connection on the node, continuously --
// which is worse than the blindness it was added to cure.
func TestLivenessCheckFailsOpen(t *testing.T) {
	own := ownInodeURLForTest(t)

	for name, podInodeURL := range map[string]string{
		"no namespace recorded":      "",
		"not an inode url":           "file:///proc/thread-self/ns/net",
		"unparseable inode":          "inode://4/not-a-number",
		"namespace nothing lives in": "inode://4/999999999",
	} {
		check := podLivenessCheck(podInodeURL, own)
		if !check(context.Background(), nil) {
			t.Errorf("%s: reported dead; it must assume live when it cannot measure", name)
		}
	}
}

// Pinging in the broker's own namespace would measure this process's
// connectivity and report it as the pod's. That is the same mistake the netns
// client already guards against on the request path.
func TestLivenessCheckRefusesTheBrokersOwnNamespace(t *testing.T) {
	own := ownInodeURLForTest(t)
	if !podLivenessCheck(own, own)(context.Background(), nil) {
		t.Error("running in the broker's own namespace must not report the pod dead")
	}
}

// inNetNS locks a thread and moves it; whatever happens it has to put the thread
// back, or this process leaks a thread that silently belongs to a pod's
// namespace and will be handed to unrelated work later.
func TestInNetNSRestoresTheThread(t *testing.T) {
	before := netnsInodeOfThread(t)

	// A *different* namespace, or the restore is a no-op and this proves
	// nothing. Under `unshare -n` pid 1 is still in the host's.
	other := otherNamespacePath(t, before)

	ran := false
	inside := uint64(0)
	live, err := inNetNS(other, func() bool { ran = true; inside = netnsInodeOfThread(t); return true })
	if err != nil {
		t.Skipf("cannot setns in this environment: %v", err)
	}
	if !ran || !live {
		t.Error("the function was not run, or its result was lost")
	}
	if inside == before {
		t.Error("the function ran in the original namespace; setns did not take effect")
	}
	if after := netnsInodeOfThread(t); after != before {
		t.Errorf("thread left in namespace %v, started in %v", after, before)
	}
}

// The same, when the function panics: the restore is deferred precisely so a
// panic cannot unwind through a thread that is still in the pod's namespace.
func TestInNetNSRestoresAfterPanic(t *testing.T) {
	before := netnsInodeOfThread(t)

	other := otherNamespacePath(t, before)
	func() {
		defer func() { _ = recover() }()
		_, _ = inNetNS(other, func() bool { panic("boom") })
	}()

	if after := netnsInodeOfThread(t); after != before {
		t.Errorf("thread left in namespace %v after a panic, started in %v", after, before)
	}
}

func netnsInodeOfThread(t *testing.T) uint64 {
	t.Helper()
	info, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatalf("reading thread namespace: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type %T", info.Sys())
	}
	return stat.Ino
}

// otherNamespacePath finds a network namespace that is not ours, so entering it
// is a real move. Run the binary under `sudo unshare -n` and pid 1 supplies one.
func otherNamespacePath(t *testing.T, own uint64) string {
	t.Helper()
	for _, pid := range []string{"1", "self"} {
		path := "/proc/" + pid + "/ns/net"
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Ino != own {
			return path
		}
	}
	t.Skip("no second network namespace available; run under: sudo unshare -n")
	return ""
}
