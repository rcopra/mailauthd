// Package spf implements sender policy framework evaluation (RFC 7208).
package spf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"mailauthd/internal/dnsres"
)

// Result values for SPF evaluation, per RFC 7208 section 2.6.
const (
	None      = "none"
	Neutral   = "neutral"
	Pass      = "pass"
	Fail      = "fail"
	SoftFail  = "softfail"
	TempError = "temperror"
	PermError = "permerror"
)

// outcomeFor maps a mechanism qualifier to its result (RFC 7208 4.6.2).
func outcomeFor(qualifier byte) string {
	switch qualifier {
	case '-':
		return Fail
	case '~':
		return SoftFail
	case '?':
		return Neutral
	default:
		return Pass
	}
}

// maxDNSLabel is the maximum length of one DNS label (RFC 1035 2.3.1).
const maxDNSLabel = 63

// validFQDN implements the initial-processing domain check of RFC 7208
// 4.3: <domain> must be a fully qualified domain name with labels of at
// most 63 characters and no empty labels. A trailing dot is allowed.
func validFQDN(domain string) bool {
	if strings.HasPrefix(domain, "[") {
		return false // domain literal, e.g. [192.0.2.1]
	}
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || !strings.Contains(domain, ".") {
		return false // not fully qualified
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > maxDNSLabel {
			return false
		}
	}
	return true
}

// CheckHost evaluates the SPF policy for ip connecting as sender (the full
// MAIL FROM identity) in domain, per RFC 7208 section 4. It always returns
// one of the seven result values plus a human-readable reason: every way
// evaluation can terminate maps to a result, there is no error path
// (RFC 7208 4.6).
func CheckHost(ctx context.Context, r dnsres.Resolver, ip net.IP, domain, sender string) (outcome, reason string) {
	// RFC 7208 4.3: malformed or non-fully-qualified domains are none.
	if !validFQDN(domain) {
		return None, "domain " + domain + " is not a valid fully-qualified domain name"
	}

	records, err := r.LookupTXT(ctx, domain)
	if err != nil {
		if errors.Is(err, dnsres.ErrNotFound) {
			return None, "domain " + domain + " has no DNS records"
		}
		return TempError, "DNS lookup for " + domain + " failed temporarily"
	}

	// RFC 7208 4.5: evaluate exactly one SPF record among the TXT records.
	var spfRecords []string
	for _, rec := range records {
		if isSPF(rec) {
			spfRecords = append(spfRecords, rec)
		}
	}
	switch len(spfRecords) {
	case 0:
		return None, "no SPF record found for " + domain
	case 1:
	default:
		return PermError, "multiple SPF records found for " + domain
	}

	parsed, err := ParseRecord(spfRecords[0])
	if err != nil {
		// Unknown mechanisms are permerror too (RFC 7208 4.6.1), so
		// unsupported and invalid records end up in the same place.
		return PermError, err.Error()
	}

	for _, t := range parsed.Terms {
		var matched bool
		switch t.mech {
		case "all":
			matched = true
		case "ip4":
			matched = matchIP4(ip, t.arg)
		case "ip6":
			matched = matchIP6(ip, t.arg)
		}
		if matched {
			return outcomeFor(t.qualifier), "mechanism " + strings.TrimPrefix(t.String(), "+") + " matched"
		}
	}

	// RFC 7208 4.6/6: default result when no mechanism matched.
	return Neutral, "no mechanism matched for " + domain
}

// qualifierString renders the term qualifier, defaulting to '+' (which is
// implicit in records).
func (t term) qualifierString() string {
	if t.qualifier == '+' {
		return "+"
	}
	return string(t.qualifier)
}

// String renders the term as it would appear in a record.
func (t term) String() string {
	if t.arg == "" {
		return t.qualifierString() + t.mech
	}
	return t.qualifierString() + t.mech + ":" + t.arg
}

// matchIP4 reports whether ip is inside the ip4 mechanism argument
// (RFC 7208 5.6). The argument was validated at parse time.
func matchIP4(ip net.IP, arg string) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false // ip4 never matches an IPv6 connection
	}
	return matchIPNetwork(v4, arg, 32)
}

// matchIP6 reports whether ip is inside the ip6 mechanism argument
// (RFC 7208 5.6). IPv4 connections never match ip6.
func matchIP6(ip net.IP, arg string) bool {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return false // IPv4-mapped connections count as IPv4 (RFC 7208 5)
	}
	return matchIPNetwork(v6, arg, 128)
}

// matchIPNetwork reports whether the connection IP (as a byte slice of
// the right family) falls inside "addr[/bits]"; maxBits is the family's
// width. The argument was validated at parse time.
func matchIPNetwork(connectionBytes []byte, arg string, maxBits int) bool {
	addrStr, hasCIDR, cidrStr := cutCIDR(arg)
	bits := maxBits
	if hasCIDR {
		bits, _ = parseCIDRLen(cidrStr, maxBits)
	}
	network := netip.MustParseAddr(addrStr)
	connection, ok := netip.AddrFromSlice(connectionBytes)
	if !ok {
		return false
	}
	return netip.PrefixFrom(network, bits).Contains(connection)
}
