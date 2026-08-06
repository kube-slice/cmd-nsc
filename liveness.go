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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelheal "github.com/networkservicemesh/sdk-kernel/pkg/kernel/tools/heal"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"golang.org/x/sys/unix"
)

// podLivenessCheck returns a heal liveness check that runs inside the pod's
// network namespace rather than this process's.
//
// Heal on its own only learns that a connection is broken when the control
// plane says so. A data path that has quietly stopped passing traffic -- an
// interface whose peer went away, a route that no longer resolves -- looks
// entirely healthy from the control plane, and heal leaves it alone. That is the
// shape of the worst failures seen on this deployment: interfaces present,
// nsmgr content, nothing flowing.
//
// The check upstream uses for this, KernelLivenessCheck, pings the connection's
// destination addresses with go-ping, and go-ping sends from whatever network
// namespace the calling thread is in. Upstream runs one nsc per application pod,
// so that is the pod's namespace and the ping measures the real data path. This
// broker serves every pod on the node from its own namespace, where the pod's
// nsm0 does not exist and those addresses are unreachable. Used as-is it would
// report every connection on the node dead, and heal would rebuild all of them,
// continuously. So the ping is moved into the pod's namespace for the duration
// of the check.
//
// It fails open. Anything that stops the check from running -- an unparseable
// inode, a namespace that has gone away, setns refused -- returns true. A check
// that cannot run says nothing about the data path, and treating silence as
// death is exactly the reconnect storm described above.
func podLivenessCheck(podInodeURL, ownInodeURL string) func(context.Context, *networkservice.Connection) bool {
	return func(deadlineCtx context.Context, conn *networkservice.Connection) bool {
		logger := log.FromContext(deadlineCtx)

		if podInodeURL == "" {
			return true
		}
		// The broker's own namespace is never a pod's data path. Pinging in it
		// would measure this process's connectivity and attribute the answer to
		// the pod, which is how the netns clobber this fork already fixes went
		// unnoticed for so long.
		if sameNetNS(podInodeURL, ownInodeURL) {
			logger.Warnf("liveness check asked to run in the broker's own namespace %v, skipping", podInodeURL)
			return true
		}

		nsPath, err := netnsPathForInodeURL(podInodeURL)
		if err != nil {
			logger.Warnf("liveness check could not locate namespace %v: %v, assuming live", podInodeURL, err)
			return true
		}

		live, err := inNetNS(nsPath, func() bool {
			return kernelheal.KernelLivenessCheck(deadlineCtx, conn)
		})
		if err != nil {
			logger.Warnf("liveness check could not enter namespace %v: %v, assuming live", nsPath, err)
			return true
		}
		if !live {
			logger.Warnf("data path for %v is not answering in namespace %v", conn.GetId(), nsPath)
		}
		return live
	}
}

// netnsPathForInodeURL turns an "inode://<dev>/<ino>" reference into the
// /proc/<pid>/ns/net path of a process living in that namespace.
//
// There is no way to open a namespace by inode, so the inode has to be matched
// against the namespaces /proc exposes. This is what the forwarder does with the
// same URLs, and it is why a pod whose processes are gone can no longer be
// reached: the inode outlives its last process only as a reference nothing can
// open.
func netnsPathForInodeURL(inodeURL string) (string, error) {
	parsed, err := url.Parse(inodeURL)
	if err != nil {
		return "", fmt.Errorf("parsing %q: %w", inodeURL, err)
	}
	if parsed.Scheme != "inode" {
		return "", fmt.Errorf("%q is not an inode url", inodeURL)
	}
	want, err := strconv.ParseUint(strings.TrimPrefix(parsed.Path, "/"), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parsing inode from %q: %w", inodeURL, err)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("reading /proc: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue // not a pid
		}
		path := filepath.Join("/proc", entry.Name(), "ns", "net")
		info, err := os.Stat(path)
		if err != nil {
			continue // the process exited while we were looking
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Ino == want {
			return path, nil
		}
	}
	return "", fmt.Errorf("no process is in namespace %v", want)
}

// inNetNS runs fn with the calling thread moved into the namespace at nsPath,
// and puts the thread back afterwards.
//
// The thread is locked for the whole of it: setns moves one thread, and without
// the lock the Go runtime is free to finish fn on a different one, leaving a
// thread of this process in a pod's namespace to be handed to unrelated work
// later.
//
// If the thread cannot be moved back it is deliberately left locked. A locked
// thread whose goroutine ends is destroyed rather than returned to the pool,
// which is the only safe outcome: the alternative is a thread that silently
// belongs to a pod's namespace for the rest of the process's life.
func inNetNS(nsPath string, fn func() bool) (result bool, err error) {
	runtime.LockOSThread()
	restoreThread := true
	defer func() {
		if restoreThread {
			runtime.UnlockOSThread()
		}
	}()

	ownFD, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("opening own namespace: %w", err)
	}
	defer func() { _ = unix.Close(ownFD) }()

	targetFD, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("opening %v: %w", nsPath, err)
	}
	defer func() { _ = unix.Close(targetFD) }()

	if err := unix.Setns(targetFD, unix.CLONE_NEWNET); err != nil {
		return false, fmt.Errorf("entering %v: %w", nsPath, err)
	}

	// Deferred so it runs even if fn panics: a panic that escaped without this
	// would unwind through a thread still in the pod's namespace.
	defer func() {
		if restoreErr := unix.Setns(ownFD, unix.CLONE_NEWNET); restoreErr != nil {
			restoreThread = false
			err = fmt.Errorf("could not return from %v: %w", nsPath, restoreErr)
		}
	}()

	return fn(), nil
}
