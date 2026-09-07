// Package spf implements sender policy framework evaluation (RFC 7208).
package spf

import (
	"context"
	"errors"
	"net"

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

// ErrNotImplemented marks unfinished RFC surface. It must disappear by the
// end of M1.
var ErrNotImplemented = errors.New("spf: not implemented")

// CheckHost evaluates the SPF policy for ip connecting as sender (the full
// MAIL FROM identity), per RFC 7208 section 4.
func CheckHost(ctx context.Context, r dnsres.Resolver, ip net.IP, domain, sender string) (string, error) {
	return "", ErrNotImplemented
}
