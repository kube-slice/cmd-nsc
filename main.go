// Copyright (c) 2020-2022 Doc.ai and/or its affiliates.
// Copyright (c) 2021-2022 Nordix and/or its affiliates.
//
// Copyright (c) 2022 Cisco and/or its affiliates.
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

//go:build linux
// +build linux

// Package main define a nsc application
package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/common"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	vfiomech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vfio"
	"github.com/networkservicemesh/cmd-nsc/internal/config"
	nscpb "github.com/networkservicemesh/cmd-nsc/pkg/nsc/generated/nsc"
	"github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/mechanisms/vfio"
	sriovtoken "github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/token"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/clientinfo"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/excludedprefixes"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/heal"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/null"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/retry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/nsurl"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type server struct {
	nscpb.UnimplementedNSCServiceServer
	clientset *kubernetes.Clientset

	// One NSM session per pod at a time. A sidecar could never call twice
	// concurrently for the same pod because it *was* the pod's only client;
	// this broker serves every pod on the node, and its clients retry, so
	// overlapping ProcessPod calls for one pod are routine. Two sessions for
	// one pod mean two connections and two veths carrying the same pod name
	// on the slice router, which is how a pod ends up shadowed by its own
	// stale interface.
	mu       sync.Mutex
	sessions map[string]*podSession
}

type podSession struct {
	cancel context.CancelFunc
	done   chan struct{}
	// superseded is set when a newer session for the same pod is taking over.
	// The outgoing session then hands the connection across instead of closing
	// it -- see supersededFromContext.
	superseded *atomic.Bool
}

type supersededKey struct{}

// supersededFromContext reports whether a newer session for this pod has taken
// over, which means the connection must be left alone.
//
// A pod's connection id is stable, so the incoming session asks for the very id
// this one holds: that request is a refresh and the interface never moves.
// Closing on the way out would delete nsm0 and force the incoming session to
// build it again -- a guaranteed outage on a path that should cost nothing.
func supersededFromContext(ctx context.Context) bool {
	flag, ok := ctx.Value(supersededKey{}).(*atomic.Bool)
	return ok && flag.Load()
}

// closeAllSessions ends every live pod session and waits for each one to finish.
//
// It no longer closes their NSM connections: shuttingDown is set first, so each
// session leaves its connection registered for the successor to adopt. What is
// waited for here is the sessions unwinding, so the gRPC server can stop.
//
// Until now SIGTERM stopped the gRPC server and did nothing else. Every NSM
// connection this broker held stayed registered, holding a token that nobody
// was left to refresh, and NSM closed each one when it expired -- roughly ten
// minutes later, long after a replacement broker had rebuilt every pod on the
// node. That close removes the interface by name in the pod's namespace, so it
// took out the *live* interface belonging to the replacement's connection. The
// result was a node-wide loss of the data plane on a timer, once per restart,
// with nothing restarting to explain it. Measured on a three cluster loop: the
// slice router went from seventeen client interfaces to none, ten minutes after
// a broker restart, with no pod having restarted in between.
//
// Closing here also hands each address back to the vl3 IPAM straight away, so
// the replacement can be given the same ones instead of allocating fresh
// addresses and changing every nexthop the slice router has been told about.
//
// Sessions are cancelled first and waited for afterwards: their closes run
// concurrently, and the process only has its termination grace period.
func (s *server) closeAllSessions(timeout time.Duration) (ended, live int) {
	s.mu.Lock()
	sessions := make([]*podSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mu.Unlock()

	for _, session := range sessions {
		session.cancel()
	}

	deadline := time.After(timeout)
	for _, session := range sessions {
		select {
		case <-session.done:
			ended++
		case <-deadline:
			return ended, len(sessions)
		}
	}
	return ended, len(sessions)
}

// takeOver stops any session already running for key and waits for it to
// finish, then registers this one. The returned release function unregisters
// it and wakes anything waiting.
func (s *server) takeOver(key string, cancel context.CancelFunc, superseded *atomic.Bool) func() {
	s.mu.Lock()
	previous := s.sessions[key]
	s.mu.Unlock()

	if previous != nil {
		// Tell it it is being replaced before cancelling, so its teardown hands
		// the connection over rather than closing it.
		if previous.superseded != nil {
			previous.superseded.Store(true)
		}
		previous.cancel()
		select {
		case <-previous.done:
		case <-time.After(sessionHandoverTimeout):
			log.FromContext(context.Background()).
				Warnf("previous session for %v did not finish within %v, continuing", key, sessionHandoverTimeout)
		}
	}

	current := &podSession{cancel: cancel, done: make(chan struct{}), superseded: superseded}
	s.mu.Lock()
	s.sessions[key] = current
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		if s.sessions[key] == current {
			delete(s.sessions, key)
		}
		s.mu.Unlock()
		close(current.done)
	}
}

const (
	sessionHandoverTimeout = 30 * time.Second
	// staleCloseTimeout bounds a Close of a connection this pod no longer
	// uses. The peer may be gone, in which case the Close never completes.
	staleCloseTimeout = 10 * time.Second
	// shutdownCloseTimeout bounds how long shutdown waits for live sessions to
	// end. It has to fit inside the pod's termination grace period.
	shutdownCloseTimeout = 20 * time.Second
)

// shuttingDown reports whether this process is on its way out, which changes
// what the end of a session means.
//
// Ending a session normally -- the pod is gone, or its sidecar is re-attaching
// -- means the connection is finished with and must be closed. Ending one
// because the *broker* is stopping means the opposite: the pod is still there
// and still using its interface, and the successor will adopt the connection
// within seconds. Closing on the way out is what made a broker restart cost
// every pod on the node its data plane.
var shuttingDown atomic.Bool

type nscClient struct {
	podName        string
	nodeName       string
	namespace      string
	networkService string
	inodeUrl       string
	count          int32
	// uid is the pod's Kubernetes UID. It is what makes a connection id stable
	// across retries and unique across clusters -- see connectionID.
	uid string
}

// validateNetworkService rejects a URL that nsurl cannot turn into a usable
// mechanism. Mechanism() only allocates its Parameters map when the path has
// an interface name, so "kernel://vl3-service-slice" (no /nsm0) yields a nil
// map and the first parameter write panics. As a sidecar that panic killed
// the one pod that was misconfigured; here the value arrives over gRPC from
// any pod on the node and the panic would kill the broker, so every pod on
// the node would lose its datapath -- repeatedly, because the offending pod
// retries every second.
func validateNetworkService(nsURL *url.URL) error {
	if nsURL.Scheme == "" || nsURL.Host == "" {
		return fmt.Errorf("network service %q needs a scheme and a service name", nsURL.String())
	}
	if (*nsurl.NSURL)(nsURL).Mechanism().GetParameters() == nil {
		return fmt.Errorf("network service %q has no interface name (expected e.g. kernel://service/nsm0)", nsURL.String())
	}
	return nil
}

func getResolverAddress() (string, error) {
	if os.Getenv("DNS_RESOLVER_IP") != "" {
		return os.Getenv("DNS_RESOLVER_IP"), nil
	}

	// The very first time when cmd-nsc boots up, the resolv.conf.restore file is
	// not available, hence we will try to get the resolver IP from the original resolv.conf.
	// The nsm dnscontext package overwrites the original resolv.conf after copying its
	// contents to resolv.conf.restore. If the cmd-nsc container restarts for any reason, it cannot use
	// the resolver IP in the original resolv.conf since the dnscontext would have overwritten
	// it to point to the localhost address, so we read the resolver IP from the restore file
	// resolv.conf.restore.
	file, err := os.Open("/etc/nsm-dns-config/resolv.conf.restore")
	if err != nil {
		file, err = os.Open("/etc/resolv.conf")
		if err != nil {
			return "", err
		}
	}

	resolverAddr := ""

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		cfgLine := strings.Split(scanner.Text(), " ")
		if cfgLine[0] == "nameserver" {
			resolverAddr = cfgLine[1]
			break
		}
	}

	return resolverAddr, nil
}

func resolveNsmConnectURL(ctx context.Context, connectURL *url.URL) (string, error) {
	if connectURL.Scheme == "unix" {
		return connectURL.Host, nil
	}

	// The resolv.conf is overwritten before the monitorClient connection is made. This will cause the container to crashloop.
	// This turns into a chicken and egg problem. Until the connection to nsmgr is established and the nsc
	// receives connection context to the nse, the dns proxy would not know the IP address of the
	// upstream dns servers, hence it cannot resolve any dns names. To fix this problem, we will read the
	// IP address of kube-dns service from /etc/nsm-dns-config/resolv.conf.restore before getting to monitorClient connection
	// and use it to resolve the tcp connect URL.
	resolverAddr, err := getResolverAddress()
	if err != nil {
		return "", err
	}

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(resolverAddr, "53"))
		},
	}

	host, port, err := net.SplitHostPort(connectURL.Host)
	if err != nil {
		return "", err
	}

	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		return "", errors.New("error resolving connect URL, addr list empty")
	}

	return net.JoinHostPort(addrs[0], port), nil
}

func getNsmgrNodeLocalServiceName(nodeName string) string {
	// The nsmgr node local service name is generated by the nsmgr init container that runs a
	// bash script to get the md5 hash of the node name. It uses the echo command to pipe the
	// node name to md5sum command. The echo command appends a newline character automatically at
	// the end of the node name string, hence we need to do the same here to generate identical
	// hash values.
	nodeNameHash := md5.Sum([]byte(nodeName + "\n"))
	return "nsm-" + hex.EncodeToString(nodeNameHash[:])
}

// handlensmtask brings up one pod's connection and holds it until the pod's
// sidecar goes away. Every failure is returned rather than fatal: this
// process serves every pod on the node, so exiting over one pod's problem
// takes the datapath away from all the others.
func handlensmtask(parentCtx context.Context, clientConfig nscClient) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Logging and tracing are process wide and are configured once in main():
	// this function runs per pod, and re-running the global setup on every
	// attach both races with other pods and re-enables tracing they may have
	// turned off.
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[:1]}))

	logger := log.FromContext(ctx)

	// ********************************************************************************
	// Get config from environment
	// ********************************************************************************
	c := &config.Config{}
	if err := envconfig.Usage("nsm", c); err != nil {
		return fmt.Errorf("reading nsm config usage: %w", err)
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return fmt.Errorf("processing nsm config from env: %w", err)
	}
	ownNetNS, err := OwnNetNSInodeURL()
	if err != nil {
		return err
	}
	if sameNetNS(clientConfig.inodeUrl, ownNetNS) {
		return fmt.Errorf("pod %v asked for an interface in the broker's own network namespace (%v)",
			clientConfig.podName, clientConfig.inodeUrl)
	}

	c.Name = clientConfig.podName
	// set network service
	nsURL, err := url.Parse(clientConfig.networkService)
	if err != nil {
		return fmt.Errorf("parsing network service %q: %w", clientConfig.networkService, err)
	}
	if err := validateNetworkService(nsURL); err != nil {
		return err
	}
	c.NetworkServices = []url.URL{*nsURL}
	// TODO: Remove this once internalTrafficPolicyi=Local for the nsmgr service works reliably.
	c.ConnectTo = url.URL{Scheme: "tcp", Host: getNsmgrNodeLocalServiceName(clientConfig.nodeName) + ".kubeslice-system.svc.cluster.local:5001"}
	// Resolve connect URL if the connection scheme is tcp or udp
	fmt.Println("nsm_url: ", c.ConnectTo.String())
	resolvedHost, err := resolveNsmConnectURL(ctx, &c.ConnectTo)
	if err != nil {
		return fmt.Errorf("resolving nsm connect host %v: %w", c.ConnectTo.String(), err)
	}
	c.ConnectTo.Host = resolvedHost
	logger.Infof("rootConf: %+v", c)

	// Check if pod network is ready before making connection to the nsmgr over tcp. This is needed if the cmd-nsc sidecar is
	// running alongside the istio-proxy sidecar. If istio is enabled on the pod, the istio-init container installs iptable
	// rules to redirect all incoming and outgoing traffic to the port numbers that the istio-proxy listens on. This leads to
	// a condition where the pod network is virtually dead from the time istio-init installs the iptable rules to the time the
	// istio-proxy sidecar boots up and is ready to listen on the port numbers to which all the traffic is redirected. This means
	// that any other container in the pod cannot make network connections to the outside world until the istio-proxy is ready.
	// This causes the cmd-nsc to crashloop trying to reach nsmgr over tcp. So we need to check if the pod network is operational
	// before attempting to connect to the nsmgr.

	// Open Telemetry is initialised once in main(). Doing it here created a
	// span exporter, a metric exporter and their goroutines per pod attach,
	// none of which outlive a sidecar but all of which accumulate in a
	// process that runs for the life of the node.
	// ********************************************************************************
	// Get a x509Source
	// ********************************************************************************

	// ********************************************************************************
	// Create Network Service Manager nsmClient
	// ********************************************************************************
	dialOptions := append(tracing.WithTracingDial(),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
		),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				insecure.NewCredentials(),
			),
		),
	)

	dnsClient := null.NewClient()

	// Heal is on, and it repairs the application pod's connection rather than
	// building a copy of it in here.
	//
	// It used to do the latter. Heal replays the request that begin stored,
	// and by the time begin stores it kernel.NewClient() has overwritten the
	// mechanism's netns with this process's own (SetNetNSURL is unconditional,
	// and NetNSURL and InodeURL are the same map key). Replaying that rebuilt
	// the pod's interface inside the broker: a stray nsm0 holding an overlay
	// address, and a dead veth per attempt.
	//
	// NewNetNSClient below now runs immediately after the kernel client and
	// re-asserts the pod's namespace on every request that leaves this chain,
	// replays included, and refuses outright to send a request that would
	// target this process. Recovery in place is worth having: the alternative
	// is the sidecar noticing the interface is gone and asking for a whole new
	// connection, which costs a teardown, a new address, and seconds of
	// downtime for a break heal can repair.
	//
	// The liveness check stays off. It probes the datapath from whichever netns
	// the process runs in, which here is the broker's, so it would report on a
	// connection nobody is using. Heal reacts to the connection monitor
	// instead, which is namespace independent.
	//
	// upstreamrefresh stays out: it is a second internally triggered replay and
	// nothing needs it.
	nsmClient := client.NewClient(ctx,
		client.WithClientURL(&c.ConnectTo),
		client.WithName(c.Name),
		//client.WithAuthorizeClient(authorize.NewClient(authorize.Any())),
		client.WithHealClient(heal.NewClient(ctx)),
		client.WithAdditionalFunctionality(
			//ensureexpires.NewClient(3*time.Minute),
			clientinfo.NewClient(),
			sriovtoken.NewClient(),
			mechanisms.NewClient(map[string]networkservice.NetworkServiceClient{
				vfiomech.MECHANISM: chain.NewNetworkServiceClient(vfio.NewClient()),
				kernelmech.MECHANISM: chain.NewNetworkServiceClient(
					kernel.NewClient(),
					// after the clobber, before sendfd reads the value
					NewNetNSClient(clientConfig.inodeUrl, ownNetNS),
				),
			}),
			sendfd.NewClient(),
			dnsClient,
			excludedprefixes.NewClient(excludedprefixes.WithAwarenessGroups(c.AwarenessGroups)),
		),
		client.WithDialTimeout(c.DialTimeout),
		client.WithDialOptions(dialOptions...),
	)

	nsmClient = retry.NewClient(nsmClient, cancel, retry.WithTryTimeout(c.RequestTimeout), retry.WithInterval(5*time.Second))

	// ********************************************************************************
	// Configure signal handling context
	// ********************************************************************************
	// Signals are handled once, in main(). Registering a handler per pod made
	// the process swallow SIGTERM for as long as any session was live, which
	// is always, so the broker could only ever be SIGKILLed.
	signalCtx, cancelSignalCtx := context.WithCancel(ctx)
	defer cancelSignalCtx()

	go func() {
		select {
		case <-parentCtx.Done():
			cancelSignalCtx()
		}
	}()
	// ********************************************************************************
	// Create Network Service Manager monitorClient
	// ********************************************************************************
	dialCtx, cancelDial := context.WithTimeout(signalCtx, c.DialTimeout)
	defer cancelDial()

	logger.Infof("NSC: Connecting to Network Service Manager %v", c.ConnectTo.String())
	cc, err := grpc.DialContext(dialCtx, grpcutils.URLToTarget(&c.ConnectTo), dialOptions...)
	if err != nil {
		return fmt.Errorf("dialling NSMgr: %w", err)
	}

	// The broker is long lived and dials nsmgr once per pod attach, so this
	// connection has to be released here; a process-lifetime leak of one
	// ClientConn (and its goroutines) per attach exhausts file descriptors.
	defer func() { _ = cc.Close() }()

	monitorClient := networkservice.NewMonitorConnectionClient(cc)

	// ********************************************************************************
	// Initiate connections
	// ********************************************************************************
	for i := 0; i < len(c.NetworkServices); i++ {
		// Update network services configs
		u := (*nsurl.NSURL)(&c.NetworkServices[i])
		fmt.Println("****************************************")
		fmt.Println(strings.ToUpper(u.Scheme))
		fmt.Println("****************************************")
		id := connectionID(c.Name, clientConfig.uid, i)
		mech := u.Mechanism()
		mech.Parameters["inodeURL"] = clientConfig.inodeUrl
		fmt.Println("####################################")
		fmt.Println("machnism: ", mech)
		// Construct a request
		label := u.Labels()
		label["podName"] = clientConfig.podName
		label["nodeName"] = clientConfig.nodeName
		request := &networkservice.NetworkServiceRequest{
			Connection: &networkservice.Connection{
				Id:             id,
				NetworkService: u.NetworkService(),
				Labels:         label,
				Mechanism:      mech,
			},
			MechanismPreferences: []*networkservice.Mechanism{
				mech,
			},
		}

		// Close whatever the nsmgr still holds for this pod from an *earlier
		// incarnation* before asking for a connection -- but never the id we
		// are about to reuse, which closeConnectionsForPod is told to keep.
		//
		// A leftover is a connection nobody will refresh again. Left alone it
		// stays registered until its token expires, and that teardown removes
		// nsm0 from the pod -- by then the interface belongs to the live
		// connection. The pod sees it vanish, asks again, strands another, and
		// the mesh reconnects itself once per token lifetime forever.
		//
		// It has to happen before the Request and not after: the interface
		// carries the same name in the same netns, so a Close that lands
		// afterwards deletes the one just created.
		var resp *networkservice.Connection
		adoptedExisting := false

		// Resuming what is already there beats rebuilding it: the interface,
		// its address and its routes survive untouched, and the slice router
		// never has to be told anything. Only when there is nothing safe to
		// resume do we fall through to the teardown below.
		// signalCtx for the same reason the Request below uses it: the adopted
		// connection must be refreshed for exactly as long as this pod's
		// session lives, and no longer.
		if adopted := adoptConnectionForPod(signalCtx, nsmClient, monitorClient, c.Name, clientConfig.inodeUrl, mech, logger); adopted != nil {
			resp = adopted
			adoptedExisting = true
		}

		if !adoptedExisting {
			closeConnectionsForPod(ctx, nsmClient, monitorClient, c.Name, id, logger)
		}

		// signalCtx, not ctx: this request must die with the pod that asked
		// for it. ctx is rooted at context.Background(), so when the pod is
		// deleted and its sidecar's RPC ends, a request issued on ctx keeps
		// being retried -- up to maxRetry times the request timeout -- for a
		// pod that no longer exists, against an endpoint that keeps
		// cancelling it.
		if !adoptedExisting {
			var err error
			resp, err = nsmClient.Request(signalCtx, request)
			if err != nil {
				// Returning lets the pod's sidecar ask again straight away
				// instead of waiting for its 10s interface watchdog, and stops
				// this handler parking on a session that has no datapath.
				return fmt.Errorf("requesting connection for pod %v: %w", c.Name, err)
			}
		}

		defer func() {
			// The session is over: either the pod is gone or its sidecar is
			// about to ask again. Leave nothing registered for it. Closing
			// only the connection this session created would leave behind
			// anything a failed Close left over earlier, and that leftover
			// expires later and takes the next incarnation's interface with
			// it.
			//
			// The close runs on a context detached from this session's. A
			// session ends by being cancelled -- that is how shutdown and pod
			// handover both end one -- so deriving the close deadline from ctx
			// produced a context that was already expired before Close was
			// called. Every Close then failed instantly with DeadlineExceeded
			// while the shutdown counted the session as closed, which is the
			// orphan this whole path exists to prevent. Values are kept so the
			// logger and any auth data survive; only the cancellation is
			// dropped.
			if shuttingDown.Load() {
				// Left deliberately registered: the pod still needs it and the
				// next broker adopts it. See shuttingDown.
				logger.Infof("shutting down, leaving connection to %v in place for the next broker", u.NetworkService())
				cancel()
				return
			}
			if supersededFromContext(parentCtx) {
				// A newer session for this pod is taking over and will ask for
				// this same id. See supersededFromContext.
				logger.Infof("handing connection to %v over to the newer session for this pod", u.NetworkService())
				cancel()
				return
			}

			teardownCtx := context.WithoutCancel(ctx)

			closeCtx, cancelClose := context.WithTimeout(teardownCtx, staleCloseTimeout)
			if _, closeErr := nsmClient.Close(closeCtx, resp); closeErr != nil {
				logger.Errorf("closing connection to %v: %v", u.NetworkService(), closeErr)
			} else {
				logger.Infof("closed connection to %v", u.NetworkService())
			}
			cancelClose()

			// The session is over, so nothing is being reused: close everything.
			closeConnectionsForPod(teardownCtx, nsmClient, monitorClient, c.Name, "", logger)
			cancel()
		}()

		logger.Infof("successfully connected to %v. Response: %v", u.NetworkService(), resp)
	}

	// Wait for cancel event to terminate
	<-signalCtx.Done()
	fmt.Println("signalctx cancelled")
	return nil
}

// adoptConnectionForPod resumes the connection the nsmgr already holds for
// podName rather than tearing it down and building a new one, and returns nil
// when there is nothing safe to resume.
//
// This is what makes a broker restart stop being an outage. The interface, its
// address and its routes all belong to the connection, not to this process, so
// leaving the connection alone leaves the pod's data plane untouched. Rebuilding
// instead cost every pod on the node its nsm0 and drew a fresh address, which is
// what left the slice router forwarding to nexthops that no longer existed.
//
// It works because the client path segment is named after the *pod*
// (client.WithName below), and that name outlives this process. updatepath sees
// a request whose current segment name already matches, reuses the existing
// connection id and adds no segment, so the request travels the chain as a
// refresh: nothing downstream rebuilds anything.
//
// The netns guard is not optional. A connection belonging to an earlier
// incarnation of the pod names a network namespace whose process is gone.
// Adopting one asks the forwarder to enter /proc/<pid>/ns/net for a dead pid,
// which it answers with "no such file or directory: all forwarders have failed"
// for every attach on the node -- measured at four thousand in three minutes,
// with the slice router holding zero client interfaces. A candidate whose
// namespace is not this pod's is left for the caller to close.
func adoptConnectionForPod(
	ctx context.Context,
	nsmClient networkservice.NetworkServiceClient,
	monitorClient networkservice.MonitorConnectionClient,
	podName, inodeURL string,
	mech *networkservice.Mechanism,
	logger log.Logger,
) *networkservice.Connection {
	monitorCtx, cancelMonitor := context.WithTimeout(ctx, staleCloseTimeout)
	defer cancelMonitor()

	stream, err := monitorClient.MonitorConnections(monitorCtx, &networkservice.MonitorScopeSelector{})
	if err != nil {
		logger.Warnf("could not list connections of pod %v to adopt: %v", podName, err)
		return nil
	}
	event, err := stream.Recv()
	if err != nil {
		logger.Warnf("could not read connection list of pod %v to adopt: %v", podName, err)
		return nil
	}

	// Newest first, so the most recently refreshed connection is preferred.
	for _, candidate := range connectionsForPod(event.GetConnections(), podName) {
		if !sameNetNS(candidate.GetMechanism().GetParameters()[common.InodeURL], inodeURL) {
			logger.Infof("not adopting connection %v of pod %v: it targets %v, this pod is %v",
				candidate.GetId(), podName, candidate.GetMechanism().GetParameters()[common.InodeURL], inodeURL)
			continue
		}

		adopted := candidate.Clone()
		adopted.Id = adopted.GetPath().GetPathSegments()[0].GetId()
		adopted.GetPath().Index = 0

		// Carry the same mechanism the create path asks for, as both the
		// connection's mechanism and the preference. It names the interface.
		// Re-issuing without it let the kernel client fall back to a name
		// generated from the network service -- "vl3-servic-<hash>" instead of
		// nsm0 -- so the pod came back with an interface its application does
		// not know to look for, which is indistinguishable from having none.
		adopted.Mechanism = mech.Clone()
		resp, err := nsmClient.Request(ctx, &networkservice.NetworkServiceRequest{
			Connection:           adopted,
			MechanismPreferences: []*networkservice.Mechanism{mech.Clone()},
		})
		if err != nil {
			// The endpoint may have restarted under it, in which case there is
			// nothing to resume. The caller closes and builds afresh.
			logger.Warnf("could not adopt connection %v of pod %v, rebuilding instead: %v", adopted.GetId(), podName, err)
			return nil
		}
		logger.Infof("adopted connection %v of pod %v, its interface was left in place", adopted.GetId(), podName)
		return resp
	}
	return nil
}

// closeConnectionsForPod closes every connection the nsmgr still holds for
// podName. Closes are bounded and concurrent: the peer of a connection the
// pod no longer uses may be gone, in which case the Close never completes,
// and nothing here is allowed to hold up the pod's next connection.
func closeConnectionsForPod(
	ctx context.Context,
	nsmClient networkservice.NetworkServiceClient,
	monitorClient networkservice.MonitorConnectionClient,
	podName, keepID string,
	logger log.Logger,
) {
	// Detached here too, so this works no matter what the caller hands in. It is
	// called on paths where the session context has already been cancelled, and
	// a cancelled parent turns every deadline below into an already-expired one:
	// the sweep then reports failure without having closed anything, leaving the
	// stale connections it exists to remove. Its own timeouts still bound it.
	ctx = context.WithoutCancel(ctx)

	monitorCtx, cancelMonitor := context.WithTimeout(ctx, staleCloseTimeout)
	defer cancelMonitor()

	stream, err := monitorClient.MonitorConnections(monitorCtx, &networkservice.MonitorScopeSelector{})
	if err != nil {
		logger.Warnf("could not list connections of pod %v: %v", podName, err)
		return
	}
	event, err := stream.Recv()
	if err != nil {
		logger.Warnf("could not read connection list for pod %v: %v", podName, err)
		return
	}

	var closing sync.WaitGroup
	for _, previous := range connectionsForPod(event.GetConnections(), podName) {
		stale := previous.Clone()
		stale.Id = stale.GetPath().GetPathSegments()[0].GetId()
		stale.GetPath().Index = 0

		// Never close the id we are about to ask for. A pod's id is stable now,
		// so the connection carrying it is this pod's live one: closing it
		// removes nsm0 and the Request that follows has to build it again,
		// which is the downtime this whole path exists to avoid. Re-requesting
		// it instead is a refresh and leaves the interface alone. Leftovers
		// from earlier incarnations carry a different UID, so they still close.
		if keepID != "" && stale.GetId() == keepID {
			logger.Infof("keeping connection %v of pod %v, it is the one being reused", stale.GetId(), podName)
			continue
		}

		closing.Add(1)
		go func(stale *networkservice.Connection) {
			defer closing.Done()
			closeCtx, cancelClose := context.WithTimeout(ctx, staleCloseTimeout)
			defer cancelClose()
			if _, closeErr := nsmClient.Close(closeCtx, stale); closeErr != nil {
				logger.Warnf("could not close connection %v of pod %v: %v", stale.Id, podName, closeErr)
				return
			}
			logger.Infof("closed connection %v of pod %v", stale.Id, podName)
		}(stale)
	}
	closing.Wait()
}

// connectionsForPod returns every connection nsmgr still holds for podName,
// most recently refreshed first, whatever mechanism they use. They are all
// leftovers: a pod gets a fresh connection id on every attempt, so none of
// them will ever be refreshed again. Pod names are stable for a StatefulSet,
// so a pod that is deleted and recreated finds its own previous connections
// here and must close all of them, not just the ones that happen to match
// the mechanism it is asking for now. Connection ids are built as
// "<podName>-<retry>-<index>-<suffix>", so the pod name prefix identifies
// every incarnation of this pod's session, including ones this process did
// not create (for example before a broker restart).
func connectionsForPod(conns map[string]*networkservice.Connection, podName string) []*networkservice.Connection {
	var out []*networkservice.Connection
	for _, conn := range conns {
		path := conn.GetPath()
		if path == nil || len(path.GetPathSegments()) == 0 || path.GetIndex() != 1 {
			continue
		}
		if !belongsToPod(conn, podName) {
			continue
		}
		out = append(out, conn)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return latestExpiry(out[i]).After(latestExpiry(out[j]))
	})
	return out
}

// belongsToPod reports whether a connection was created for podName.
//
// The podName label is authoritative: connection ids are
// "<podName>-<retry>-<index>-<suffix>", and that encoding is ambiguous
// (pod "srvd-dc-b" with retry 2 produces the same id shape as pod
// "srvd-dc-b-2" with retry 1), so adopting on the id alone could hand one
// pod's datapath to another. The id is only consulted when a connection
// carries no label, where a wrong guess would at worst skip an adoption.
func belongsToPod(conn *networkservice.Connection, podName string) bool {
	if labelled, ok := conn.GetLabels()["podName"]; ok && labelled != "" {
		return labelled == podName
	}
	rest, ok := strings.CutPrefix(conn.GetPath().GetPathSegments()[0].GetId(), podName+"-")
	return ok && connIDTail.MatchString(rest)
}

// connIDTail matches what follows the pod name in a connection id: the network
// service index and then the pod UID (connectionID), or the older
// "<retry>-<index>-<random>" shape, since connections created before an upgrade
// are still out there and still have to be recognised as this pod's.
var connIDTail = regexp.MustCompile(`^[0-9]+-([0-9a-fA-F-]{36}|[0-9]+-)`)

func latestExpiry(conn *networkservice.Connection) time.Time {
	var newest time.Time
	for _, segment := range conn.GetPath().GetPathSegments() {
		if t := segment.GetExpires().AsTime(); t.After(newest) {
			newest = t
		}
	}
	return newest
}

// connectionID is the id a pod's connection carries, for every attempt, for as
// long as that pod exists.
//
// It used to be "<pod>-<retry>-<index>-<random>", which changed on every single
// attempt. A pod that reconnected -- and after a broker restart every pod on
// the node reconnects at once -- arrived as a stranger: a new connection, a
// newly allocated address, and the old id left behind for something to clean up
// later. That is where the churn came from. Every slice gateway changing
// address is why the slice router ended up forwarding to nexthops that no
// longer existed, and every abandoned id is one more thing to expire at the
// wrong moment.
//
// The pod's Kubernetes UID gives all three properties at once. It is identical
// across retries, so reconnecting is recognisably the same client; it is a UUID,
// so no two pods can collide, in this cluster or any other sharing the slice;
// and it changes when the pod is genuinely replaced, so a new incarnation --
// which has a different network namespace -- is correctly treated as new rather
// than inheriting a dead one's connection.
//
// The index distinguishes multiple network services requested by one pod.
func connectionID(podName, podUID string, index int) string {
	if podUID == "" {
		// Without a UID there is nothing stable to key on. Falling back to the
		// old shape keeps the pod working; it just loses the stability.
		return fmt.Sprintf("%s-%d-%s", podName, index, shortRandomSuffix())
	}
	return fmt.Sprintf("%s-%d-%s", podName, index, podUID)
}

func shortRandomSuffix() string {
	b := make([]byte, 6)
	_, err := rand.Read(b)
	if err != nil {
		// Very rare fallback — use timestamp + pid
		return fmt.Sprintf("t%x", time.Now().UnixNano()^(int64(os.Getpid())<<32))
	}
	return base64.RawURLEncoding.EncodeToString(b)[:8]
}

func main() {
	// Process wide setup, once (see handlensmtask).
	log.EnableTracing(true)
	logrus.SetFormatter(&nested.Formatter{})
	logrus.Info("Starting NetworkServiceMesh Client ...")

	rootConf := &config.Config{}
	if err := envconfig.Process("nsm", rootConf); err == nil {
		if level, levelErr := logrus.ParseLevel(rootConf.LogLevel); levelErr == nil {
			logrus.SetLevel(level)
		} else {
			logrus.Warnf("invalid log level %s, keeping %s", rootConf.LogLevel, logrus.GetLevel())
		}
	}

	if opentelemetry.IsEnabled() {
		otelCtx := context.Background()
		spanExporter := opentelemetry.InitSpanExporter(otelCtx, rootConf.OpenTelemetryEndpoint)
		metricExporter := opentelemetry.InitOPTLMetricExporter(otelCtx, rootConf.OpenTelemetryEndpoint, 60*time.Second)
		o := opentelemetry.Init(otelCtx, spanExporter, metricExporter, "nsc-grpc-server")
		defer func() {
			if closeErr := o.Close(); closeErr != nil {
				logrus.Error(closeErr.Error())
			}
		}()
	}

	config, err := rest.InClusterConfig()
	Logger := log.FromContext(context.Background())
	if err != nil {
		Logger.Fatalf("failed loading config: %v", err.Error())
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		Logger.Fatalf("failed creating clientset: %v", err.Error())
	}
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		Logger.Fatalf("failed to listen: %v", err.Error())
	}
	// A panic in one pod's handler must not take the datapath away from every
	// pod on the node, and a caller that disappears without closing its TCP
	// connection must be noticed in seconds rather than in grpc-go's default
	// two hours.
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.UnaryInterceptor(recoverPanics),
	)
	nscServer := &server{
		clientset: clientset,
		sessions:  make(map[string]*podSession),
	}
	nscpb.RegisterNSCServiceServer(grpcServer, nscServer)
	signalCtx, stopSignals := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	defer stopSignals()
	go func() {
		<-signalCtx.Done()
		Logger.Infof("shutting down, ending pod sessions and leaving their connections for the next broker")
		shuttingDown.Store(true)
		ended, live := nscServer.closeAllSessions(shutdownCloseTimeout)
		if ended < live {
			Logger.Errorf("ended %v of %v pod sessions before the shutdown deadline", ended, live)
		} else {
			Logger.Infof("ended %v pod sessions", ended)
		}
		// Stop rather than GracefulStop: ProcessPod does not return until its
		// pod is gone, so waiting for in-flight RPCs waits for ever and the
		// process is killed with its connections still registered -- the thing
		// this shutdown exists to prevent.
		grpcServer.Stop()
	}()

	fmt.Println("starting server at 50052")
	if err := grpcServer.Serve(lis); err != nil {
		Logger.Fatalf("failed to serve: %v", err.Error())
	}
}

// recoverPanics keeps one pod's request from killing the process. Anything
// that panics here would otherwise unwind through grpc-go, which installs no
// recovery of its own, and end the broker for every pod on the node.
func recoverPanics(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.FromContext(ctx).Errorf("panic in %v: %v\n%s", info.FullMethod, r, debug.Stack())
			err = fmt.Errorf("internal error handling %v", info.FullMethod)
		}
	}()
	return handler(ctx, req)
}

// podHasLabel reports whether the pod is on a slice, and returns its UID.
//
// The UID comes from the same lookup rather than a second one: it identifies
// this incarnation of the pod, so it is exactly what a connection id needs to
// be stable across retries and to change when the pod is genuinely replaced.
func (s *server) podHasLabel(podName string, namespace string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pod, err := s.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return false, "", err
	}

	if pod.Labels == nil {
		return false, string(pod.UID), nil
	}
	_, exists := pod.Labels["kubeslice.io/slice"]
	return exists, string(pod.UID), nil
}
func (s *server) ProcessPod(ctx context.Context, req *nscpb.PodRequest) (*nscpb.PodResponse, error) {

	clientSpec := nscClient{
		podName:        req.Name,
		namespace:      req.Namespace,
		nodeName:       req.NodeName,
		networkService: req.NetworkService,
		inodeUrl:       req.InodeURL,
		count:          req.RetryCount,
	}
	// This broker owns one node. Serving a pod from another node would create
	// its interface against the wrong nsmgr, using a netns inode that means
	// nothing here.
	if ownNode := os.Getenv("MY_NODE_NAME"); ownNode != "" && clientSpec.nodeName != "" && clientSpec.nodeName != ownNode {
		return &nscpb.PodResponse{Status: "Pod belongs to another node"},
			fmt.Errorf("pod %v is on node %v, this broker serves %v", clientSpec.podName, clientSpec.nodeName, ownNode)
	}

	check, uid, err := s.podHasLabel(clientSpec.podName, clientSpec.namespace)
	if err != nil {
		return &nscpb.PodResponse{Status: "Error checking pod labels"}, err
	}
	clientSpec.uid = uid
	if !check {
		return &nscpb.PodResponse{Status: "Pod does not have kubeslice.io/slice label"}, nil
	}
	fmt.Println("Processing pod:", clientSpec.podName, clientSpec.namespace, clientSpec.nodeName)
	fmt.Println("NetworkService: ", clientSpec.networkService)
	fmt.Println("InodeURL: ", clientSpec.inodeUrl)
	// Call your NSM handling logic
	superseded := &atomic.Bool{}
	sessionCtx, cancelSession := context.WithCancel(context.WithValue(ctx, supersededKey{}, superseded))
	defer cancelSession()
	release := s.takeOver(clientSpec.namespace+"/"+clientSpec.podName, cancelSession, superseded)
	defer release()

	if err := handlensmtask(sessionCtx, clientSpec); err != nil {
		fmt.Println("Failed to process pod", clientSpec.podName, err)
		return &nscpb.PodResponse{Status: "Failed to set up NSM connection"}, err
	}

	fmt.Println("Work done for pod", clientSpec.podName)
	return &nscpb.PodResponse{Status: "Pod processed successfully"}, nil
}

func (s *server) getPodIp(nodeName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ListOpts := metav1.ListOptions{
		LabelSelector: "app=nsc-grpc-server",
		FieldSelector: "spec.nodeName=" + nodeName,
	}
	pods, err := s.clientset.CoreV1().Pods("kubeslice-system").List(ctx, ListOpts)
	if err != nil {
		return "", err
	}
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || pod.DeletionTimestamp != nil {
			continue
		}
		ready := false
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}
		if !ready {
			continue
		}
		return pod.Status.PodIP + ":50052", nil
	}
	return "", fmt.Errorf("no pod with label app=nsc-grpc-server found on node %s", nodeName)
}
func (s *server) DiscoverServer(ctx context.Context, req *nscpb.ClientNode) (*nscpb.ServerAddr, error) {
	serverAddr, err := s.getPodIp(req.NodeName)
	return &nscpb.ServerAddr{Server_Ip: serverAddr}, err
}
