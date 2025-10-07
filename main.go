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
	"encoding/hex"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/kelseyhightower/envconfig"
	kernelheal "github.com/networkservicemesh/sdk-kernel/pkg/kernel/tools/heal"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	kernelmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	vfiomech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vfio"
	"github.com/networkservicemesh/cmd-nsc/internal/config"
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
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/upstreamrefresh"
	"github.com/networkservicemesh/sdk/pkg/networkservice/connectioncontext/dnscontext"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsconfig"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/cache"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/checkmsg"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/dnsconfigs"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/fanout"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/next"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/noloop"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/searches"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/nsurl"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"
)

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

func getNsmgrNodeLocalServiceName() string {
	// The nsmgr node local service name is generated by the nsmgr init container that runs a
	// bash script to get the md5 hash of the node name. It uses the echo command to pipe the
	// node name to md5sum command. The echo command appends a newline character automatically at
	// the end of the node name string, hence we need to do the same here to generate identical
	// hash values.
	nodeNameHash := md5.Sum([]byte(os.Getenv("MY_NODE_NAME") + "\n"))
	return "nsm-" + hex.EncodeToString(nodeNameHash[:])
}

// Checks if a successful connection can be made to the provided endpoint.
func checkPodNetworkConnectivity(endpoint string) error {
	var d net.Dialer
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Wait and retry if the connection attempt fails
	for i := 0; i < 4; i++ {
		conn, errN := d.DialContext(ctx, "tcp", endpoint)
		if errN == nil {
			conn.Close()
			return nil
		}
		err = errN
		time.Sleep(15 * time.Second)
	}

	return err
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ********************************************************************************
	// Setup logger
	// ********************************************************************************
	log.EnableTracing(true)
	logrus.Info("Starting NetworkServiceMesh Client ...")
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[:1]}))

	logger := log.FromContext(ctx)

	// ********************************************************************************
	// Get config from environment
	// ********************************************************************************
	c := &config.Config{}
	if err := envconfig.Usage("nsm", c); err != nil {
		logger.Fatal(err)
	}
	if err := envconfig.Process("nsm", c); err != nil {
		logger.Fatalf("error processing rootConf from env: %+v", err)
	}

	level, err := logrus.ParseLevel(c.LogLevel)
	if err != nil {
		logrus.Fatalf("invalid log level %s", c.LogLevel)
	}
	logrus.SetLevel(level)

	// TODO: Remove this once internalTrafficPolicyi=Local for the nsmgr service works reliably.
	c.ConnectTo = url.URL{Scheme: "tcp", Host: getNsmgrNodeLocalServiceName() + ".kubeslice-system.svc.cluster.local:5001"}
	// Resolve connect URL if the connection scheme is tcp or udp
	resolvedHost, err := resolveNsmConnectURL(ctx, &c.ConnectTo)
	if err != nil {
		logrus.Fatalf("error resolving nsm connect host: %v, err: %v", c.ConnectTo, err)
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
	err = checkPodNetworkConnectivity(resolvedHost)
	if err != nil {
		logrus.Fatalf("cannot connect to nsmgr over the pod network. host: %v, err: %v", resolvedHost, err)
	}

	// ********************************************************************************
	// Configure Open Telemetry
	// ********************************************************************************
	if opentelemetry.IsEnabled() {
		collectorAddress := c.OpenTelemetryEndpoint
		spanExporter := opentelemetry.InitSpanExporter(ctx, collectorAddress)
		metricExporter := opentelemetry.InitOPTLMetricExporter(ctx, collectorAddress, 60*time.Second)
		o := opentelemetry.Init(ctx, spanExporter, metricExporter, c.Name)
		defer func() {
			if err = o.Close(); err != nil {
				logger.Error(err.Error())
			}
		}()
	}

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
	if c.LocalDNSServerEnabled {
		dnsConfigsMap := new(dnsconfig.Map)
		dnsClient = dnscontext.NewClient(dnscontext.WithChainContext(ctx), dnscontext.WithDNSConfigsMap(dnsConfigsMap))
		dnsServerHandler := next.NewDNSHandler(
			checkmsg.NewDNSHandler(),
			dnsconfigs.NewDNSHandler(dnsConfigsMap),
			searches.NewDNSHandler(),
			noloop.NewDNSHandler(),
			cache.NewDNSHandler(),
			fanout.NewDNSHandler(),
		)

		go dnsutils.ListenAndServe(ctx, dnsServerHandler, c.LocalDNSServerAddress)
	}

	var healOptions = []heal.Option{heal.WithLivenessCheckInterval(c.LivenessCheckInterval),
		heal.WithLivenessCheckTimeout(c.LivenessCheckTimeout)}

	if c.LivenessCheckEnabled {
		healOptions = append(healOptions, heal.WithLivenessCheck(kernelheal.KernelLivenessCheck))
	}

	nsmClient := client.NewClient(ctx,
		client.WithClientURL(&c.ConnectTo),
		client.WithName(c.Name),
		//client.WithAuthorizeClient(authorize.NewClient(authorize.Any())),
		client.WithHealClient(heal.NewClient(ctx, healOptions...)),
		client.WithAdditionalFunctionality(
			//ensureexpires.NewClient(3*time.Minute),
			clientinfo.NewClient(),
			upstreamrefresh.NewClient(ctx),
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

	nsmClient = retry.NewClient(nsmClient, retry.WithTryTimeout(c.RequestTimeout), retry.WithInterval(5*time.Second))

	// ********************************************************************************
	// Configure signal handling context
	// ********************************************************************************
	signalCtx, cancelSignalCtx := signal.NotifyContext(
		ctx,
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancelSignalCtx()

	// ********************************************************************************
	// Create Network Service Manager monitorClient
	// ********************************************************************************
	dialCtx, cancelDial := context.WithTimeout(signalCtx, c.DialTimeout)
	defer cancelDial()
	defer cancelDial()

	logger.Infof("NSC: Connecting to Network Service Manager %v", c.ConnectTo.String())
	cc, err := grpc.DialContext(dialCtx, grpcutils.URLToTarget(&c.ConnectTo), dialOptions...)
	if err != nil {
		logger.Fatalf("failed dial to NSMgr: %v", err.Error())
	}

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
		id := fmt.Sprintf("%s-%d", c.Name, i)
		var monitoredConnections map[string]*networkservice.Connection
		monitorCtx, cancelMonitor := context.WithTimeout(signalCtx, c.RequestTimeout)
		defer cancelMonitor()

		stream, err := monitorClient.MonitorConnections(monitorCtx, &networkservice.MonitorScopeSelector{
			PathSegments: []*networkservice.PathSegment{
				{
					Id: id,
				},
			},
		})
		if err != nil {
			logger.Fatal("error from monitorConnectionClient ", err.Error())
		}

		event, err := stream.Recv()
		if err != nil {
			logger.Errorf("error from monitorConnection stream ", err.Error())
		} else {
			monitoredConnections = event.Connections
		}
		cancelMonitor()

		// Construct a request
		request := &networkservice.NetworkServiceRequest{
			Connection: &networkservice.Connection{
				Id:             id,
				NetworkService: u.NetworkService(),
				Labels:         u.Labels(),
			},
			MechanismPreferences: []*networkservice.Mechanism{
				u.Mechanism(),
			},
		}

		for _, conn := range monitoredConnections {
			path := conn.GetPath()
			if path.Index == 1 && path.PathSegments[0].Id == id && conn.Mechanism.Type == u.Mechanism().Type {
				request.Connection = conn
				request.Connection.Path.Index = 0
				request.Connection.Id = id
				break
			}
		}

		resp, err := nsmClient.Request(ctx, request)
		if err != nil {
			logger.Fatalf("failed connect to NSMgr: %v", err.Error())
		}

		defer func() {
			closeCtx, cancelClose := context.WithTimeout(ctx, c.RequestTimeout)
			defer cancelClose()
			_, _ = nsmClient.Close(closeCtx, resp)
		}()

		logger.Infof("successfully connected to %v. Response: %v", u.NetworkService(), resp)
	}

	// Wait for cancel event to terminate
	<-signalCtx.Done()
}
