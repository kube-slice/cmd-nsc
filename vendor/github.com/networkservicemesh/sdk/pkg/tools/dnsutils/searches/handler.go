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

// Package searches makes requests to all subdomains received from DNS configs
package searches

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils"
	"github.com/networkservicemesh/sdk/pkg/tools/dnsutils/next"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

const (
	timeout = 3 * time.Second
)

type searchDomainsHandler struct {
}

func (h *searchDomainsHandler) ServeDNS(ctx context.Context, rw dns.ResponseWriter, m *dns.Msg) {
	domains := SearchDomains(ctx)

	r := &responseWriter{
		ResponseWriter: rw,
		Responses:      make([]*dns.Msg, len(domains)+1),
		index:          0,
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for i, d := range append([]string{""}, SearchDomains(ctx)...) {
		newMsg := m.Copy()
		newMsg.Question[0].Name = dns.Fqdn(newMsg.Question[0].Name + d)
		next.Handler(ctx).ServeDNS(ctx, r, newMsg)

		// If the response contains an answer section, return right away.
		if r.Responses[i] != nil && r.Responses[i].Rcode == dns.RcodeSuccess && len(r.Responses[i].Answer) > 0 {
			log.FromContext(ctx).WithField("searchDomainsHandler", "ServeDNS").Debugf("Returning response with ans section: %v", r.Responses[i])
			r.Responses[i].Question = m.Question
			if err := rw.WriteMsg(r.Responses[i]); err != nil {
				log.FromContext(ctx).WithField("searchDomainsHandler", "ServeDNS").Warnf("got an error during write the message: %v", err.Error())
				dns.HandleFailed(rw, r.Responses[i])
				return
			}
			return
		}
	}

	// If we are here, we have received responses without an answer section. Return the first response with an Rcode of success.
	// If there are no responses with RcodeSuccess, we fallthrough and return a failure message to the caller.
	for i, resp := range r.Responses {
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			log.FromContext(ctx).WithField("searchDomainsHandler", "ServeDNS").Debugf("Returning response without ans: %v", r.Responses[i])
			r.Responses[i].Question = m.Question
			if err := rw.WriteMsg(r.Responses[i]); err != nil {
				log.FromContext(ctx).WithField("searchDomainsHandler", "ServeDNS").Warnf("got an error during write the message: %v", err.Error())
				dns.HandleFailed(rw, r.Responses[i])
			}
			return
		}
	}

	dns.HandleFailed(rw, m)
}

// NewDNSHandler creates a new dns handler that makes requests to all subdomains received from dns configs
func NewDNSHandler() dnsutils.Handler {
	return new(searchDomainsHandler)
}
