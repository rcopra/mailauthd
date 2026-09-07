// Package dnsres abstracts DNS lookups so every auth check is testable
// against fixture data and cacheable.
package dnsres

import (
	"context"
	"errors"
	"net"
)

// Sentinel outcomes that resolvers should map DNS conditions onto, so
// consumers can distinguish them without importing net internals.
var (
	// ErrNotFound corresponds to NXDOMAIN: the name exists in no zone.
	ErrNotFound = errors.New("dnsres: name not found")
	// ErrTempError corresponds to a transient DNS failure (timeout,
	// SERVFAIL): the lookup may succeed on retry.
	ErrTempError = errors.New("dnsres: temporary DNS failure")
)

// mapNetError translates a *net.DNSError into a sentinel errors above,
// wrapping the original. Other errors pass through unchanged.
func mapNetError(err error) error {
	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
		switch {
		case dnsErr.IsNotFound:
			return ErrNotFound
		case dnsErr.IsTimeout, dnsErr.IsTemporary:
			return ErrTempError
		}
	}
	return err
}

// Resolver is the DNS surface needed by the auth checks.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIP(ctx context.Context, name string) ([]net.IP, error)
}

// NetResolver adapts net.Resolver to the Resolver interface.
type NetResolver struct {
	R *net.Resolver
}

func (n NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	recs, err := n.R.LookupTXT(ctx, name)
	return recs, mapNetError(err)
}

func (n NetResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	recs, err := n.R.LookupMX(ctx, name)
	return recs, mapNetError(err)
}

func (n NetResolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	addrs, err := n.R.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, mapNetError(err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}
