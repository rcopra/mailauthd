package main

import "testing"

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
