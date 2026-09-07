// Package dnsres abstracts DNS lookups so every auth check is testable
// against fixture data and cacheable.
package dnsres

import (
	"context"
	"net"
)

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
	return n.R.LookupTXT(ctx, name)
}

func (n NetResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return n.R.LookupMX(ctx, name)
}

func (n NetResolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	addrs, err := n.R.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}
