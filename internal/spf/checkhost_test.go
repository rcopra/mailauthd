package spf

import (
	"context"
	"net"
	"strings"
	"testing"

	"mailauthd/internal/dnsres"
)

// zone models one DNS name in a fixture: its TXT records, and whether
// lookups that match no records should fail temporarily (TIMEOUT marker
// in the open-spf.org test suite).
type zone struct {
	txt     []string
	timeout bool
}

// fixtureResolver serves canned zones; a zone marked timeout fails
// lookups with dnsres.ErrTempError only when it has no records (queries
// matching preceding records still succeed). Missing zones are NXDOMAIN.
type fixtureResolver struct {
	zones map[string]zone
}

func newFixtureResolver(txt map[string][]string) *fixtureResolver {
	r := &fixtureResolver{zones: map[string]zone{}}
	for name, records := range txt {
		r.zones[name] = zone{txt: records}
	}
	return r
}

func (f *fixtureResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	z, ok := f.zones[name]
	if !ok {
		return nil, dnsres.ErrNotFound
	}
	if len(z.txt) == 0 && z.timeout {
		return nil, dnsres.ErrTempError
	}
	return z.txt, nil
}

func (f *fixtureResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) {
	return nil, dnsres.ErrTempError
}

func (f *fixtureResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	return nil, dnsres.ErrTempError
}

// Table-driven tests for CheckHost, one row per RFC 7208 section or edge
// case. Fixture zones cover .example.net (policies) and .example.com
// (errors).

const v4ip = "192.0.2.10"

func TestCheckHost(t *testing.T) {
	tests := []struct {
		name   string
		zones  map[string][]string
		ip     string
		domain string
		want   string
	}{
		// --- Initial processing (RFC 7208 4.3) ---
		{
			name:   "malformed-domain-empty-label",
			zones:  map[string][]string{},
			ip:     v4ip,
			domain: "a..example.com",
			want:   None,
		},
		{
			name:   "malformed-domain-long-label",
			zones:  map[string][]string{},
			ip:     v4ip,
			domain: "A123456789012345678901234567890123456789012345678901234567890123.example.com",
			want:   None,
		},
		{
			name:   "max-label-is-fine",
			zones:  map[string][]string{"a12345678901234567890123456789012345678901234567890123456789012.example.com": {"v=spf1 -all"}},
			ip:     v4ip,
			domain: "a12345678901234567890123456789012345678901234567890123456789012.example.com",
			want:   Fail,
		},
		{
			name:   "domain-literal",
			zones:  map[string][]string{},
			ip:     v4ip,
			domain: "[192.0.2.1]",
			want:   None,
		},
		{
			name:   "not-fqdn",
			zones:  map[string][]string{},
			ip:     v4ip,
			domain: "localhost",
			want:   None,
		},
		{
			name:   "trailing-dot-ignored",
			zones:  map[string][]string{"example.com": {"v=spf1 -all"}},
			ip:     v4ip,
			domain: "example.com.",
			want:   Fail,
		},
		{
			name:   "domain-lookup-case-insensitive",
			zones:  map[string][]string{"example.com": {"v=spf1 -all"}},
			ip:     v4ip,
			domain: "EXAMPLE.COM",
			want:   Fail,
		},

		// --- Record lookup (RFC 7208 4.4) ---
		{
			name:   "nxdomain",
			zones:  map[string][]string{},
			ip:     v4ip,
			domain: "example.com",
			want:   None,
		},
		{
			name:   "temperror",
			zones:  map[string][]string{},
			ip:     v4ip,
			domain: "example.com",
			want:   TempError,
		},

		// --- Record selection (RFC 7208 4.5) ---
		{
			name:   "no-spf-record",
			zones:  map[string][]string{"example.com": {"hello world"}},
			ip:     v4ip,
			domain: "example.com",
			want:   None,
		},
		{
			name:   "multiple-spf-records",
			zones:  map[string][]string{"example.com": {"v=spf1 -all", "v=spf1 +all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   PermError,
		},
		{
			name:   "spf-among-other-records",
			zones:  map[string][]string{"example.com": {"v=spf10 x", "hello", "v=spf1 -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "syntax-error-anywhere-is-permerror",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.1 all:oops"}},
			ip:     v4ip,
			domain: "example.com",
			want:   PermError,
		},
		{
			name:   "unknown-mechanism-is-permerror",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.1 moo"}},
			ip:     v4ip,
			domain: "example.com",
			want:   PermError,
		},

		// --- Record evaluation (RFC 7208 4.6): qualifiers and mechanisms ---
		{
			name:   "no-match-defaults-to-neutral",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.1"}},
			ip:     "198.51.100.1",
			domain: "example.com",
			want:   Neutral,
		},
		{
			name:   "ip4-match",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.10 -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "ip4-cidr-match",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "ip4-cidr-no-match",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}},
			ip:     "192.0.3.1",
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "qualifier-fail",
			zones:  map[string][]string{"example.com": {"v=spf1 -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "qualifier-softfail",
			zones:  map[string][]string{"example.com": {"v=spf1 ~all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   SoftFail,
		},
		{
			name:   "qualifier-neutral",
			zones:  map[string][]string{"example.com": {"v=spf1 ?all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Neutral,
		},
		{
			name:   "first-match-wins",
			zones:  map[string][]string{"example.com": {"v=spf1 +ip4:192.0.2.10 -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "ip4-does-not-match-ipv6-connection",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}},
			ip:     "2001:db8::10",
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "ip6-match",
			zones:  map[string][]string{"example.com": {"v=spf1 ip6:2001:db8::/32 -all"}},
			ip:     "2001:db8::10",
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "ip6-cidr-no-match",
			zones:  map[string][]string{"example.com": {"v=spf1 ip6:2001:db8::/32 -all"}},
			ip:     "2001:db9::10",
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "ip6-zero-cidr-matches-all-v6",
			zones:  map[string][]string{"example.com": {"v=spf1 ip6:2001:db8::/0 -all"}},
			ip:     "2001:db9::10",
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "ip6-does-not-match-ipv4-connection",
			zones:  map[string][]string{"example.com": {"v=spf1 ip6:2001:db8::/0 -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "ipv4-mapped-connection-treated-as-ipv4",
			zones:  map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.10 -all"}},
			ip:     "::ffff:192.0.2.10",
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "record-syntax-case-insensitive",
			zones:  map[string][]string{"example.com": {"V=SPF1 IP4:192.0.2.10 -ALL"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Pass,
		},
		{
			name:   "unknown-modifier-ignored",
			zones:  map[string][]string{"example.com": {"v=spf1 moo=cow -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   Fail,
		},
		{
			name:   "unsupported-mechanism-is-permerror",
			zones:  map[string][]string{"example.com": {"v=spf1 a:example.net -all"}},
			ip:     v4ip,
			domain: "example.com",
			want:   PermError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newFixtureResolver(tt.zones)
			if tt.name == "temperror" {
				r.zones["example.com"] = zone{timeout: true}
			}
			outcome, reason := CheckHost(context.Background(), r, net.ParseIP(tt.ip), tt.domain, "foo@"+tt.domain)
			if outcome != tt.want {
				t.Errorf("CheckHost outcome = %q (reason %q), want %q", outcome, reason, tt.want)
			}
			if reason == "" {
				t.Errorf("CheckHost returned empty reason")
			}
		})
	}
}

func TestCheckHostReasonMentionsMechanism(t *testing.T) {	r := newFixtureResolver(map[string][]string{"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"}})
	_, reason := CheckHost(context.Background(), r, net.ParseIP(v4ip), "example.com", "foo@example.com")
		if !strings.Contains(reason, "ip4:192.0.2.0/24") {
		t.Errorf("reason %q does not mention the matching mechanism", reason)
		}
}
