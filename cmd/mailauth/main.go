// Command mailauth evaluates a raw RFC 5322 message from stdin and prints
// the Verdict as JSON.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"mailauthd/internal/dnsres"
	"mailauthd/internal/spf"
	"mailauthd/internal/verdict"
)

func main() {
	ipFlag := flag.String("ip", "127.0.0.1", "IP address of the connecting client")
	flag.Parse()

	msg, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mailauth: reading stdin: %v\n", err)
		os.Exit(1)
	}

	ip := net.ParseIP(*ipFlag)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "mailauth: invalid -ip %q\n", *ipFlag)
		os.Exit(1)
	}

	result := evalSPF(msg, ip)
	out, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mailauth: encoding verdict: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

// evalSPF runs the SPF check for a message: the sender identity is the
// Return-Path (the SMTP MAIL FROM as recorded by the receiver), falling
// back to the From header domain.
func evalSPF(msg []byte, ip net.IP) verdict.Result {
	domain, sender, ok := senderIdentity(msg)
	if !ok {
		return verdict.Result{
			Check:   verdict.CheckSPF,
			Outcome: spf.None,
			Reason:  "message has no sender domain (no Return-Path or From header)",
		}
	}
	resolver := dnsres.NetResolver{R: net.DefaultResolver}
	outcome, reason := spf.CheckHost(context.Background(), resolver, ip, domain, sender)
	return verdict.Result{Check: verdict.CheckSPF, Outcome: outcome, Reason: reason}
}

// senderIdentity extracts (domain, sender) from a message's headers. ok is
// false when no usable sender domain can be derived.
func senderIdentity(msg []byte) (domain, sender string, ok bool) {
	header := headerLines(msg)
	value, found := findHeader(header, "return-path")
	if !found {
		value, found = findHeader(header, "from")
	}
	if !found {
		return "", "", false
	}
	addr := stripAngleAddr(value)
	d, local, ok := splitAddress(addr)
	if !ok {
		return "", "", false
	}
	sender = local + "@" + d
	if local == "" {
		// RFC 7208 4.3: identity with empty local part is postmaster.
		sender = "postmaster@" + d
	}
	return d, sender, true
}

// headerLines returns the header block of an RFC 5322 message (everything
// before the first empty line).
func headerLines(msg []byte) []string {
	text := string(msg)
	if i := strings.Index(text, "\n\n"); i >= 0 {
		text = text[:i]
	}
	return strings.Split(text, "\n")
}

// findHeader returns the value of the first header with the given
// (case-insensitive) field name.
func findHeader(lines []string, name string) (string, bool) {
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(strings.ToLower(line), strings.ToLower(name)+":"); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// stripAngleAddr extracts the address from "<addr>" if the value is
// angle-addr form, else returns the value as-is.
func stripAngleAddr(value string) string {
	if i := strings.IndexByte(value, '<'); i >= 0 {
		if j := strings.IndexByte(value[i:], '>'); j > 0 {
			return value[i+1 : i+j]
		}
	}
	return strings.TrimSpace(value)
}

// splitAddress splits user@domain. ok is false without a domain.
func splitAddress(addr string) (domain, local string, ok bool) {
	i := strings.LastIndex(addr, "@")
	if i < 0 || i == len(addr)-1 {
		return "", addr, false
	}
	return strings.ToLower(addr[i+1:]), addr[:i], true
}
