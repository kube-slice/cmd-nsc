package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// procPath is the mount point of procfs. Overridden in tests.
var procPath = "/proc"

// netnsBindDirs are the well known locations where container runtimes and CNI plugins pin network
// namespaces as bind mounts. A pinned namespace stays valid even when no process currently lives
// in it, so these are searched after procfs.
//
// This list is deliberately runtime agnostic: containerd, CRI-O, Docker and the various CNI
// plugins each use their own directory, and a node may host more than one of them.
var netnsBindDirs = []string{
	"/run/netns",            // iproute2 / CNI convention
	"/var/run/netns",        // same, on distros where /var/run is not a symlink
	"/run/docker/netns",     // Docker
	"/var/run/docker/netns", // Docker
	"/run/containerd/netns", // containerd
	"/var/run/containerd/netns",
	"/run/crio/netns", // CRI-O
	"/var/run/crio/netns",
}

// resolveNetNSFileURL turns the "inode://<dev>/<ino>" URL the sidecar reports for its own pod into
// a "file:///proc/<pid>/ns/net" URL.
//
// The inode form only works when the receiver already holds a file descriptor for that namespace,
// which is how upstream NSM passes netns handles: the client runs inside the target pod, sendfd
// hands its own netns fd across a unix socket, and recvfd turns the received fd back into a path.
// Neither leg here is a unix socket -- the sidecar reaches us over TCP and we reach nsmgr over TCP
// -- so no descriptor is ever transferred and the bare inode reaches the forwarder as something it
// cannot open.
//
// Sharing the host PID namespace lets us translate the inode into a path instead. The forwarder
// shares that namespace as well, so /proc/<pid>/ns/net resolves to the same namespace there.
func resolveNetNSFileURL(inodeURL string) (string, error) {
	ino, err := inodeFromURL(inodeURL)
	if err != nil {
		return "", err
	}

	// A running pod always has a process in its namespace, so procfs answers first and is the
	// path the forwarder resolves identically, since it shares the host PID namespace.
	pid, procErr := findPIDByNetNSInode(ino)
	if procErr == nil {
		return (&url.URL{Scheme: "file", Path: fmt.Sprintf("/proc/%d/ns/net", pid)}).String(), nil
	}
	if !errors.Is(procErr, errNetNSNotFound) && !errors.Is(procErr, errNetNSPermission) {
		return "", procErr
	}

	// Fall back to a namespace pinned by the runtime or CNI.
	if path, err := findPinnedNetNSByInode(ino); err == nil {
		return (&url.URL{Scheme: "file", Path: path}).String(), nil
	}

	if errors.Is(procErr, errNetNSPermission) {
		return "", fmt.Errorf("cannot resolve netns inode %d: %w", ino, procErr)
	}

	return "", fmt.Errorf("no network namespace with inode %d found under %s or %v; "+
		"hostPID must be enabled on this pod for it to see the application pod's namespace",
		ino, procPath, netnsBindDirs)
}

func inodeFromURL(inodeURL string) (uint64, error) {
	u, err := url.Parse(inodeURL)
	if err != nil {
		return 0, fmt.Errorf("parsing inode url %q: %w", inodeURL, err)
	}
	if u.Scheme != "inode" {
		return 0, fmt.Errorf("expected an inode:// url, got %q", inodeURL)
	}
	ino, err := strconv.ParseUint(filepath.Base(u.Path), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing inode from %q: %w", inodeURL, err)
	}
	return ino, nil
}

// findPIDByNetNSInode scans procfs for a process whose network namespace has the given inode.
// Requires hostPID to see processes outside this pod.
func findPIDByNetNSInode(ino uint64) (int, error) {
	entries, err := os.ReadDir(procPath)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", procPath, err)
	}

	var scanned, denied int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}
		scanned++
		info, err := os.Stat(filepath.Join(procPath, e.Name(), "ns", "net"))
		if err != nil {
			// A process that exited between listing and stat is ordinary. Permission denied is
			// not: it means we can see the process but not its namespace, and the namespace we
			// are looking for may be one of those we were refused.
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if stat.Ino == ino {
			return pid, nil
		}
	}

	// Being refused most of what we can see is the signature of a missing capability rather than
	// a genuinely absent namespace, and it is worth saying so plainly: the symptom otherwise
	// looks identical to hostPID not being set at all.
	if denied > 0 && denied >= scanned/2 {
		return 0, fmt.Errorf(
			"could not read the network namespace of %d of the %d processes visible in %s: %w; "+
				"SYS_PTRACE is required to read /proc/<pid>/ns/net of processes in other pods",
			denied, scanned, procPath, errNetNSPermission)
	}

	return 0, errNetNSNotFound
}

var errNetNSNotFound = errors.New("no process found with a matching network namespace")

// errNetNSPermission indicates the namespaces exist but we are not allowed to read them.
var errNetNSPermission = errors.New("permission denied reading network namespaces")

// findPinnedNetNSByInode looks for a network namespace pinned as a bind mount. Runtimes and CNI
// plugins pin namespaces so they outlive the process that created them, and a sandbox whose
// processes have all exited still has a usable namespace here.
func findPinnedNetNSByInode(ino uint64) (string, error) {
	for _, dir := range netnsBindDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // directory absent on this runtime
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if stat.Ino == ino {
				return p, nil
			}
		}
	}
	return "", errNetNSNotFound
}
