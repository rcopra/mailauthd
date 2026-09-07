package spf

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// term is one parsed SPF record term: a mechanism or a modifier (RFC 7208
// 4.6.1). Modifiers that matter later (redirect=, exp=) are rejected as
// unsupported until implemented.
type term struct {
	qualifier byte   // '+', '-', '~', '?'; mechanisms default to '+'
	mech      string // lowercased mechanism name, or modifier name
	arg       string // argument after ':' (empty for "all")
}

// ParseError marks an invalid SPF record; CheckHost maps it to permerror.
type ParseError struct {
	Record string
	Reason string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("spf: invalid record %q: %s", e.Record, e.Reason)
}

// UnsupportedError marks an otherwise well-formed record that uses RFC
// surface not implemented yet (e.g. the include mechanism or redirect
// modifier). The conformance harness uses it to scope which cases can run.
type UnsupportedError struct {
	Record string
	Reason string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("spf: unsupported record %q: %s", e.Record, e.Reason)
}

// IsUnsupported reports whether err marks a record that is valid RFC 7208
// but uses mechanisms or modifiers that are not implemented yet.
func IsUnsupported(err error) bool {
	_, ok := err.(*UnsupportedError)
	return ok
}

// Record is a parsed SPF record.
type Record struct {
	Terms []term
}

// isSPF reports whether a TXT record is an SPF record per RFC 7208 4.5:
// it starts with the version "v=spf1" terminated by a space or the end of
// the record. Mechanism and modifier names are case-insensitive.
func isSPF(record string) bool {
	if len(record) < len("v=spf1") {
		return false
	}
	if !strings.EqualFold(record[:len("v=spf1")], "v=spf1") {
		return false
	}
	rest := record[len("v=spf1"):]
	return rest == "" || rest[0] == ' '
}

// ParseRecord parses an SPF record body (the whole TXT record including
// the version) into its terms. Any syntax error anywhere in the record is
// detected here, so the evaluator can fail fast with permerror (RFC 7208
// 4.6).
func ParseRecord(record string) (*Record, error) {
	for _, r := range record {
		if r >= utf8.RuneSelf {
			return nil, &ParseError{record, "non-ASCII character"}
		}
	}

	fields := strings.Fields(record)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, &ParseError{record, `record does not start with version "v=spf1"`}
	}

	rec := &Record{Terms: make([]term, 0, len(fields)-1)}
	for _, f := range fields[1:] {
		t, err := parseTerm(record, f)
		if err != nil {
			return nil, err
		}
		if t == nil {
			continue // unknown modifier: ignored per RFC 7208 6
		}
		rec.Terms = append(rec.Terms, *t)
	}
	return rec, nil
}

// parseTerm parses one record term (mechanism or modifier). A nil term
// with no error means "unknown modifier, ignore".
func parseTerm(record, f string) (*term, error) {
	t := term{qualifier: '+'}
	if strings.IndexByte("+-~?", f[0]) >= 0 {
		t.qualifier = f[0]
		f = f[1:]
		if f == "" {
			return nil, &ParseError{record, "empty term after qualifier"}
		}
	}

	// Modifiers are name=value; mechanisms use name or name:arg.
	if i := strings.IndexByte(f, '='); i >= 0 && (strings.IndexByte(f, ':') < 0 || i < strings.IndexByte(f, ':')) {
		if t.qualifier != '+' {
			return nil, &ParseError{record, fmt.Sprintf("qualifier on modifier %q", f)}
		}
		name := f[:i]
		if !isModifierName(name) {
			return nil, &ParseError{record, fmt.Sprintf("invalid modifier name %q", name)}
		}
		switch strings.ToLower(name) {
		case "redirect", "exp":
			return nil, &UnsupportedError{record, fmt.Sprintf("modifier %q not implemented", strings.ToLower(name))}
		}
		if err := validateMacroString(f[i+1:]); err != nil {
			return nil, &ParseError{record, fmt.Sprintf("modifier %q: %v", name, err)}
		}
		return nil, nil // unknown modifier: ignore
	}

	name, arg, hasArg := strings.Cut(f, ":")
	t.mech = strings.ToLower(name)

	switch t.mech {
	case "all":
		if hasArg {
			return nil, &ParseError{record, fmt.Sprintf("mechanism %q takes no argument", f)}
		}
		return &t, nil
	case "ip4":
		if !hasArg {
			return nil, &ParseError{record, fmt.Sprintf("mechanism %q requires an argument", f)}
		}
		if err := validateIP4Arg(arg); err != nil {
			return nil, &ParseError{record, err.Error()}
		}
		t.arg = arg
		return &t, nil
	case "ip6":
		if !hasArg {
			return nil, &ParseError{record, fmt.Sprintf("mechanism %q requires an argument", f)}
		}
		if err := validateIP6Arg(arg); err != nil {
			return nil, &ParseError{record, err.Error()}
		}
		t.arg = arg
		return &t, nil
	default:
		return nil, &UnsupportedError{record, fmt.Sprintf("mechanism %q not implemented", name)}
	}
}

// isModifierName reports whether name is a valid modifier name per RFC
// 7208 4.6.1: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ).
func isModifierName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'):
		default:
			return false
		}
	}
	return true
}

// validateMacroString checks a macro-string per RFC 7208 7.1: literals
// are visible ASCII except '%'; '%' must start one of "%%", "%_", "%-",
// or "%{" macro-letter transformers *delimiter "}".
func validateMacroString(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			if s[i] < 0x21 || s[i] > 0x7e {
				return fmt.Errorf("invalid character in macro-string")
			}
			continue
		}
		if i+1 >= len(s) {
			return fmt.Errorf("dangling %%")
		}
		switch s[i+1] {
		case '%', '_', '-':
			i++
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return fmt.Errorf("unterminated macro expansion")
			}
			if err := validateMacroBody(s[i+2 : i+end]); err != nil {
				return err
			}
			i += end
		default:
			return fmt.Errorf("invalid %% escape %q", s[i:i+2])
		}
	}
	return nil
}

// validateMacroBody checks the body of a "%{...}" expansion:
// macro-letter transformers *delimiter "}" (RFC 7208 7.1).
func validateMacroBody(body string) error {
	if body == "" {
		return fmt.Errorf("empty macro expansion")
	}
	if !strings.ContainsRune("slodiphcrtvSLDIPHCRTV", rune(body[0])) {
		return fmt.Errorf("invalid macro letter %q", body[0])
	}
	i := 1
	for ; i < len(body) && body[i] >= '0' && body[i] <= '9'; i++ {
	}
	if i < len(body) && (body[i] == 'r' || body[i] == 'R') {
		i++
	}
	for ; i < len(body); i++ {
		if !strings.ContainsAny(body[i:i+1], ".,+-/_=") {
			return fmt.Errorf("invalid macro delimiter %q", body[i])
		}
	}
	return nil
}

// validateIP4Arg validates an ip4 mechanism argument:
// ip4-network = ip4-address ["/" ip4-cidr-length] (RFC 7208 5.6).
func validateIP4Arg(arg string) error {
	addrStr, hasCIDR, cidrStr := cutCIDR(arg)
	addr, err := netip.ParseAddr(addrStr)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("invalid ip4 address %q", addrStr)
	}
	if hasCIDR {
		if _, ok := parseCIDRLen(cidrStr, 32); !ok {
			return fmt.Errorf("invalid ip4 CIDR length %q", cidrStr)
		}
	}
	return nil
}

// validateIP6Arg validates an ip6 mechanism argument:
// ip6-network = ip6-address ["/" ip6-cidr-length] (RFC 7208 5.6).
func validateIP6Arg(arg string) error {
	addrStr, hasCIDR, cidrStr := cutCIDR(arg)
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return fmt.Errorf("invalid ip6 address %q", addrStr)
	}
	// ip4:1.2.3.4 goes through the ip4 mechanism, not ip6.
	if addr.Is4() {
		return fmt.Errorf("invalid ip6 address %q", addrStr)
	}
	if hasCIDR {
		if _, ok := parseCIDRLen(cidrStr, 128); !ok {
			return fmt.Errorf("invalid ip6 CIDR length %q", cidrStr)
		}
	}
	return nil
}

// cutCIDR splits "addr/bits" into its parts.
func cutCIDR(arg string) (addr string, hasCIDR bool, cidr string) {
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		return arg[:i], true, arg[i+1:]
	}
	return arg, false, ""
}

// parseCIDRLen parses a CIDR length: cidr-length = "/" ( "0" /
// %x31-39 *DIGIT ) (RFC 7208 5.6) — no leading zeros — with value in
// [0, max].
func parseCIDRLen(s string, max int) (int, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n > max {
			return 0, false
		}
	}
	return n, true
}
