// Copyright (c) 2022 Cisco Systems, Inc.
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

// Package fanout sends incoming queries in parallel to few endpoints
package fanout

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/miekg/dns"

	"github.com/networkservicemesh/sdk/pkg/tools/clienturlctx"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/next"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/searches"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

type fanoutHandler struct {
	dnsPort uint16
}

func (h *fanoutHandler) ServeDNS(ctx context.Context, rw dns.ResponseWriter, msg *dns.Msg) {
	var connectTO = clienturlctx.ClientURLs(ctx)
	var searchDomains = searches.SearchDomains(ctx)
	var responseCh = make(chan *dns.Msg, len(connectTO))
	var primaryDnsServerUrl *url.URL = nil

	deadline, _ := ctx.Deadline()
	timeout := time.Until(deadline)

	if len(connectTO) == 0 {
		log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Error("no urls to fanout")
		dns.HandleFailed(rw, msg)
		return
	}

	for iter, searchDomain := range searchDomains {
		if searchDomain == "slice.local" {
			if iter < len(connectTO) {
				primaryDnsServerUrl = &connectTO[iter]
			}
			break
		}
	}

	log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Debugf("Primary dns: %v", primaryDnsServerUrl)

	if primaryDnsServerUrl != nil {
		var client = dns.Client{
			Net:     primaryDnsServerUrl.Scheme,
			Timeout: timeout,
		}

		address := primaryDnsServerUrl.Host
		if primaryDnsServerUrl.Port() == "" {
			address += fmt.Sprintf(":%d", h.dnsPort)
		}

		var resp, _, err = client.Exchange(msg, address)
		if err != nil {
			log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Warnf("got an error during exchanging with primary %v: %v", address, err.Error())
		} else {
			if resp != nil {
				log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Debugf("recvd resp from primary: %v", resp)
				if resp.Rcode == dns.RcodeSuccess {
					if len(resp.Answer) > 0 {
						if err := rw.WriteMsg(resp); err != nil {
							log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Warnf("got an error during write the message: %v", err.Error())
							dns.HandleFailed(rw, msg)
							return
						}
						next.Handler(ctx).ServeDNS(ctx, rw, resp)
						return
					}
				}
			}
		}
	}

	for i := 0; i < len(connectTO); i++ {
		go func(u *url.URL, msg *dns.Msg) {
			var client = dns.Client{
				Net:     u.Scheme,
				Timeout: timeout,
			}

			address := u.Host
			if u.Port() == "" {
				address += fmt.Sprintf(":%d", h.dnsPort)
			}

			var resp, _, err = client.Exchange(msg, address)
			if err != nil {
				log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Warnf("got an error during exchanging with address %v: %v", address, err.Error())
				responseCh <- nil
				return
			}

			responseCh <- resp
		}(&connectTO[i], msg.Copy())
	}

	var resp = h.waitResponse(ctx, responseCh)

	if resp == nil {
		// TODO: The waitResponse() func needs to be improved to return the correct error code if none of the
		// queried nameservers return an answer. We need a way to aggregate the error codes and choose what error
		// to write in the dns response message if different nameservers returned different error codes.
		dns.HandleFailed(rw, msg)
		return
	}

	if err := rw.WriteMsg(resp); err != nil {
		log.FromContext(ctx).WithField("fanoutHandler", "ServeDNS").Warnf("got an error during write the message: %v", err.Error())
		dns.HandleFailed(rw, msg)
		return
	}

	next.Handler(ctx).ServeDNS(ctx, rw, resp)
}

func (h *fanoutHandler) waitResponse(ctx context.Context, respCh <-chan *dns.Msg) *dns.Msg {
	var respCount = cap(respCh)
	for {
		select {
		case resp, ok := <-respCh:
			if !ok {
				return nil
			}
			respCount--
			if resp == nil {
				if respCount == 0 {
					return nil
				}
				continue
			}
			if resp.Rcode == dns.RcodeSuccess {
				if len(resp.Answer) == 0 {
					if respCount == 0 {
						return resp
					}
					continue
				}
				return resp
			}
			if respCount == 0 {
				return nil
			}

		case <-ctx.Done():
			return nil
		}
	}
}

// NewDNSHandler creates a new dns handler instance that sends incoming queries in parallel to few endpoints
func NewDNSHandler(opts ...Option) dnsutils.Handler {
	var h = &fanoutHandler{
		dnsPort: 53,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}
