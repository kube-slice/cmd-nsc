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
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	vfiomech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vfio"
	"github.com/networkservicemesh/cmd-nsc/internal/config"
	nscpb "github.com/networkservicemesh/cmd-nsc/pkg/nsc/generated/nsc"
	"github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/mechanisms/vfio"
	sriovtoken "github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/token"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/clientinfo"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/excludedprefixes"
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
}

// takeOver stops any session already running for key and waits for it to
// finish, then registers this one. The returned release function unregisters
// it and wakes anything waiting.
func (s *server) takeOver(key string, cancel context.CancelFunc) func() {
	s.mu.Lock()
	previous := s.sessions[key]
	s.mu.Unlock()

	if previous != nil {
		previous.cancel()
		select {
		case <-previous.done:
		case <-time.After(sessionHandoverTimeout):
			log.FromContext(context.Background()).
				Warnf("previous session for %v did not finish within %v, continuing", key, sessionHandoverTimeout)
		}
	}

	current := &podSession{cancel: cancel, done: make(chan struct{})}
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
)

type nscClient struct {
	podName        string
	nodeName       string
	namespace      string
	networkService string
	inodeUrl       string
	count          int32
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

	// We do not heal here, and that is deliberate.
	//
	// This process is a broker: it issues NSM requests on behalf of *other* pods,
	// and the only thing that makes such a request land in the right place is the
	// inodeURL of the caller's netns, which arrives fresh on every ProcessPod call.
	//
	// Heal does not re-run that handshake. It replays the mechanism stored on the
	// connection -- and by the time it is stored, kernel.NewClient() has already
	// overwritten inodeURL with our own netns (it calls SetNetNSURL unconditionally,
	// and NetNSURL and InodeURL are the same map key). So every heal attempt rebuilds
	// the application pod's interface inside *this* pod instead, which is where the
	// stray nsm0 and the pile of dead veths come from.
	//
	// Recovery belongs to the client sidecar: when it sees its connection go away it
	// calls ProcessPod again, and that path re-resolves the target netns by
	// construction. upstreamrefresh is dropped for the same reason -- it is a second
	// internally-triggered replay of the same stale mechanism.
	nsmClient := client.NewClient(ctx,
		client.WithClientURL(&c.ConnectTo),
		client.WithName(c.Name),
		//client.WithAuthorizeClient(authorize.NewClient(authorize.Any())),
		client.WithHealClient(null.NewClient()),
		client.WithAdditionalFunctionality(
			//ensureexpires.NewClient(3*time.Minute),
			clientinfo.NewClient(),
			sriovtoken.NewClient(),
			mechanisms.NewClient(map[string]networkservice.NetworkServiceClient{
				vfiomech.MECHANISM:   chain.NewNetworkServiceClient(vfio.NewClient()),
				kernelmech.MECHANISM: chain.NewNetworkServiceClient(kernel.NewClient()),
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
		id := fmt.Sprintf("%s-%d-%d-%s", c.Name, clientConfig.count, i, shortRandomSuffix())
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

		// Close whatever the nsmgr still holds for this pod before asking for
		// a new connection.
		//
		// Every attempt gets a fresh id on purpose, so the connection the pod
		// had a moment ago is never refreshed again by anyone. Left alone it
		// stays registered until its token expires, and the teardown that
		// follows removes nsm0 from the pod -- by then the interface belongs
		// to the new connection. The pod's sidecar sees it vanish, asks for
		// another connection, strands that one in turn, and the mesh
		// reconnects itself once per token lifetime forever.
		//
		// This has to happen before the Request below and not after: the new
		// interface carries the same name in the same netns, so a Close that
		// lands afterwards deletes the interface that was just created. The
		// pod has no datapath at this point anyway, which is why its sidecar
		// called us.
		closeConnectionsForPod(ctx, nsmClient, monitorClient, c.Name, logger)

		// signalCtx, not ctx: this request must die with the pod that asked
		// for it. ctx is rooted at context.Background(), so when the pod is
		// deleted and its sidecar's RPC ends, a request issued on ctx keeps
		// being retried -- up to maxRetry times the request timeout -- for a
		// pod that no longer exists, against an endpoint that keeps
		// cancelling it.
		resp, err := nsmClient.Request(signalCtx, request)
		if err != nil {
			// Returning lets the pod's sidecar ask again straight away
			// instead of waiting for its 10s interface watchdog, and stops
			// this handler parking on a session that has no datapath.
			return fmt.Errorf("requesting connection for pod %v: %w", c.Name, err)
		}

		defer func() {
			// The session is over: either the pod is gone or its sidecar is
			// about to ask again. Leave nothing registered for it. Closing
			// only the connection this session created would leave behind
			// anything a failed Close left over earlier, and that leftover
			// expires later and takes the next incarnation's interface with
			// it.
			closeCtx, cancelClose := context.WithTimeout(ctx, staleCloseTimeout)
			_, _ = nsmClient.Close(closeCtx, resp)
			cancelClose()
			logger.Infof("closed connection to %v", u.NetworkService())

			closeConnectionsForPod(ctx, nsmClient, monitorClient, c.Name, logger)
			cancel()
		}()

		logger.Infof("successfully connected to %v. Response: %v", u.NetworkService(), resp)
	}

	// Wait for cancel event to terminate
	<-signalCtx.Done()
	fmt.Println("signalctx cancelled")
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
	podName string,
	logger log.Logger,
) {
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

var connIDTail = regexp.MustCompile(`^[0-9]+-[0-9]+-`)

func latestExpiry(conn *networkservice.Connection) time.Time {
	var newest time.Time
	for _, segment := range conn.GetPath().GetPathSegments() {
		if t := segment.GetExpires().AsTime(); t.After(newest) {
			newest = t
		}
	}
	return newest
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
	nscpb.RegisterNSCServiceServer(grpcServer, &server{
		clientset: clientset,
		sessions:  make(map[string]*podSession),
	})
	signalCtx, stopSignals := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	defer stopSignals()
	go func() {
		<-signalCtx.Done()
		Logger.Infof("shutting down")
		grpcServer.GracefulStop()
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

func (s *server) podHasLabel(podName string, namespace string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pod, err := s.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if pod.Labels == nil {
		return false, nil
	}
	_, exists := pod.Labels["kubeslice.io/slice"]
	return exists, nil
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

	check, err := s.podHasLabel(clientSpec.podName, clientSpec.namespace)
	if err != nil {
		return &nscpb.PodResponse{Status: "Error checking pod labels"}, err
	}
	if !check {
		return &nscpb.PodResponse{Status: "Pod does not have kubeslice.io/slice label"}, nil
	}
	fmt.Println("Processing pod:", clientSpec.podName, clientSpec.namespace, clientSpec.nodeName)
	fmt.Println("NetworkService: ", clientSpec.networkService)
	fmt.Println("InodeURL: ", clientSpec.inodeUrl)
	// Call your NSM handling logic
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	release := s.takeOver(clientSpec.namespace+"/"+clientSpec.podName, cancelSession)
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
