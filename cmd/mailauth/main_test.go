package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"mailauthd/internal/dnsres"
)

// Table-driven tests for the sender identity extraction from RFC 5322
// headers.

func TestSenderIdentity(t *testing.T) {
	tests := []struct {
		name   string
		msg    string
		domain string
		sender string
		ok     bool
	}{
		{
			name:   "return-path-wins",
			msg:    "Return-Path: <bounce@example.com>\nFrom: Rick <rick@example.net>\n\nbody",
			domain: "example.com",
			sender: "bounce@example.com",
			ok:     true,
		},
		{
			name:   "from-fallback",
			msg:    "From: Rick <rick@example.net>\n\nbody",
			domain: "example.net",
			sender: "rick@example.net",
			ok:     true,
		},
		{
			name:   "bare-addr-from",
			msg:    "From: rick@example.net\n\n",
			domain: "example.net",
			sender: "rick@example.net",
			ok:     true,
		},
		{
			name:   "empty-local-part-is-postmaster",
			msg:    "Return-Path: <@example.net>\n\n",
			domain: "example.net",
			sender: "postmaster@example.net",
			ok:     true,
		},
		{
			name:   "null-return-path",
			msg:    "Return-Path: <>\nFrom: rick@example.net\n\n",
			domain: "", sender: "", ok: false,
		},
		{
			name:   "no-headers",
			msg:    "\nbody",
			domain: "", sender: "", ok: false,
		},
		{
			name:   "header-cases-insensitive",
			msg:    "RETURN-PATH: <a@Example.COM>\n\n",
			domain: "example.com",
			sender: "a@example.com",
			ok:     true,
		},
		{
			name:   "headers-stop-at-blank-line",
			msg:    "X-Not-Return-Path: fake\n\nReturn-Path: <real@example.com>\n",
			domain: "",
			ok:     false,
		},
		// RFC 5322 wire format uses CRLF, including the blank line.
		{
			name:   "crlf-message",
			msg:    "Return-Path: <bounce@example.com>\r\n\r\nReturn-Path: <body@attacker.com>\n",
			domain: "example.com",
			sender: "bounce@example.com",
			ok:     true,
		},
		{
			name:   "crlf-body-ignored",
			msg:    "From: <a@example.com>\r\n\r\nReturn-Path: <body@attacker.com>\r\n",
			domain: "example.com",
			sender: "a@example.com",
			ok:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, sender, ok := senderIdentity([]byte(tt.msg))
			if ok != tt.ok || domain != tt.domain || sender != tt.sender {
				t.Errorf("senderIdentity = (%q, %q, %v), want (%q, %q, %v)",
					domain, sender, ok, tt.domain, tt.sender, tt.ok)
			}
		})
	}
}

// singleZoneResolver is a minimal dnsres.Resolver fixture serving canned
// TXT records; everything else fails temporarily.
type singleZoneResolver struct {
	txt map[string][]string
}

func (r *singleZoneResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	recs, ok := r.txt[strings.ToLower(strings.TrimSuffix(name, "."))]
	if !ok {
		return nil, dnsres.ErrNotFound
	}
	return recs, nil
}

func (r *singleZoneResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return nil, dnsres.ErrTempError
}

func (r *singleZoneResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	return nil, dnsres.ErrTempError
}

// End-to-end test of the CLI evaluation path against a fixture resolver:
// message in, verdict.Result out.
func TestEvalSPF(t *testing.T) {
	msg := "" +
		"Return-Path: <bounce@example.com>\r\n" +
		"From: Someone <someone@example.com>\r\n" +
		"Subject: test\r\n" +
		"\r\n" +
		"Return-Path: <body@attacker.com>\r\n" +
		"body\r\n"

	fixture := &singleZoneResolver{txt: map[string][]string{
		"example.com": {"v=spf1 ip4:192.0.2.10 -all"},
	}}

	tests := []struct {
		name    string
		ip      string
		outcome string
	}{
		{"match-pass", "192.0.2.10", "pass"},
		{"no-match-fail", "192.0.3.1", "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evalSPF([]byte(msg), net.ParseIP(tt.ip), fixture)
			if result.Check != "spf" || result.Outcome != tt.outcome || result.Reason == "" {
				t.Errorf("evalSPF = %+v, want check=spf outcome=%q with reason", result, tt.outcome)
			}
		})
	}
}
