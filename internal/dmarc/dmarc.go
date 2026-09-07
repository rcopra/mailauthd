// Package dmarc implements DMARC policy discovery and evaluation (RFC 7489).
package dmarc

import (
	"context"
	"errors"

	"mailauthd/internal/dnsres"
	"mailauthd/internal/verdict"
)

// ErrNotImplemented marks unfinished RFC surface. It must disappear by the
// end of M2.
var ErrNotImplemented = errors.New("dmarc: not implemented")

// Evaluate performs DMARC policy discovery for fromDomain and applies the
// policy to the given SPF and DKIM Results, returning the Disposition.
func Evaluate(ctx context.Context, r dnsres.Resolver, fromDomain string, spf, dkim *verdict.Result) (verdict.Disposition, error) {
	return "", ErrNotImplemented
}
