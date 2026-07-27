package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInodeFromURL(t *testing.T) {
	got, err := inodeFromURL("inode://4/4026533855")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 4026533855 {
		t.Errorf("inode = %d, want 4026533855", got)
	}
}

func TestInodeFromURLRejectsOtherSchemes(t *testing.T) {
	// A file URL means the caller already has a path; treating it as an inode would silently
	// produce the wrong namespace.
	for _, in := range []string{"file:///proc/thread-self/ns/net", "inode://4/notanumber", "://"} {
		if _, err := inodeFromURL(in); err == nil {
			t.Errorf("inodeFromURL(%q) succeeded, want error", in)
		}
	}
}

// The resolver must find a namespace by inode using only procfs, which is what every runtime
// exposes -- it must not depend on k3s, containerd or any particular pinning directory.
func TestResolveFindsNetNSViaProcfs(t *testing.T) {
	ourNetNS := "/proc/self/ns/net"
	info, err := os.Stat(ourNetNS)
	if err != nil {
		t.Skipf("cannot stat %s: %v", ourNetNS, err)
	}
	ino := info.Sys().(*syscall.Stat_t).Ino

	got, err := resolveNetNSFileURL(fmt.Sprintf("inode://4/%d", ino))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(got, "file:///proc/") || !strings.HasSuffix(got, "/ns/net") {
		t.Errorf("resolved to %q, want a file:///proc/<pid>/ns/net URL", got)
	}

	// The returned path must name the same namespace we asked for.
	resolved, err := os.Stat(strings.TrimPrefix(got, "file://"))
	if err != nil {
		t.Fatalf("resolved path is not usable: %v", err)
	}
	if resolved.Sys().(*syscall.Stat_t).Ino != ino {
		t.Errorf("resolved path points at a different namespace")
	}
}

func TestResolveReportsMissingNamespaceClearly(t *testing.T) {
	dir := t.TempDir() // no pid entries at all
	old := procPath
	procPath = dir
	defer func() { procPath = old }()

	_, err := resolveNetNSFileURL("inode://4/999999999")
	if err == nil {
		t.Fatal("expected an error for an unknown inode")
	}
	// The operator's most likely mistake is missing hostPID; say so.
	if !strings.Contains(err.Error(), "hostPID") {
		t.Errorf("error should mention hostPID, got: %v", err)
	}
}

// Namespaces pinned as bind mounts must be found too: a sandbox whose processes have exited still
// has a usable namespace, and runtimes differ in where they pin it.
func TestResolveFindsPinnedNetNS(t *testing.T) {
	dir := t.TempDir()
	old := procPath
	procPath = dir
	defer func() { procPath = old }()

	pinDir := t.TempDir()
	pinned := filepath.Join(pinDir, "cni-1234")
	if err := os.WriteFile(pinned, nil, 0o600); err != nil {
		t.Fatalf("cannot create fixture: %v", err)
	}
	info, err := os.Stat(pinned)
	if err != nil {
		t.Fatalf("cannot stat fixture: %v", err)
	}
	ino := info.Sys().(*syscall.Stat_t).Ino

	oldDirs := netnsBindDirs
	netnsBindDirs = []string{pinDir}
	defer func() { netnsBindDirs = oldDirs }()

	got, err := resolveNetNSFileURL(fmt.Sprintf("inode://4/%d", ino))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "file://"+pinned {
		t.Errorf("resolved to %q, want %q", got, "file://"+pinned)
	}
}
