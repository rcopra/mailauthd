package spf

import (
	"reflect"
	"strings"
	"testing"
)

// Table-driven tests for the SPF record parser, one row per RFC 7208
// section or edge case.

func TestParseRecordQualifiers(t *testing.T) {
	// RFC 7208 4.6.1: qualifier = "+" / "-" / "?" / "~"
	tests := []struct {
		name   string
		record string
		terms  int
		qual   byte // qualifier of the first mechanism
	}{
		{"plus", "v=spf1 ip4:1.2.3.4 -all", 2, '+'},
		{"minus", "v=spf1 -ip4:1.2.3.4", 1, '-'},
		{"tilde", "v=spf1 ~ip4:1.2.3.4", 1, '~'},
		{"question", "v=spf1 ?ip4:1.2.3.4", 1, '?'},
		{"default-plus", "v=spf1 ip4:1.2.3.4", 1, '+'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := ParseRecord(tt.record)
			if err != nil {
				t.Fatalf("ParseRecord(%q): %v", tt.record, err)
			}
			if len(rec.Terms) != tt.terms {
				t.Fatalf("got %d terms, want %d", len(rec.Terms), tt.terms)
			}
			if rec.Terms[0].qualifier != tt.qual {
				t.Errorf("qualifier = %q, want %q", rec.Terms[0].qualifier, tt.qual)
			}
		})
	}
}

func TestParseRecordMechanisms(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   []term
	}{
		{
			"all",
			"v=spf1 all",
			[]term{{mech: "all", qualifier: '+'}},
		},
		{
			"ip4",
			"v=spf1 ip4:192.0.2.0/24 -all",
			[]term{{mech: "ip4", qualifier: '+', arg: "192.0.2.0/24"}, {mech: "all", qualifier: '-'}},
		},
		{
			"ip6",
			"v=spf1 ip6:2001:db8::/32 ~all",
			[]term{{mech: "ip6", qualifier: '+', arg: "2001:db8::/32"}, {mech: "all", qualifier: '~'}},
		},
		{
			"ip4-mapped-ip6-arg",
			"v=spf1 ip6:::ffff:192.0.2.1 all",
			[]term{{mech: "ip6", qualifier: '+', arg: "::ffff:192.0.2.1"}, {mech: "all", qualifier: '+'}},
		},
		{
			// RFC 7208 4.6.1: terms are separated by 1*SP; extra SP allowed.
			"multiple-spaces",
			"v=spf1  ip4:192.0.2.1  -all  ",
			[]term{{mech: "ip4", qualifier: '+', arg: "192.0.2.1"}, {mech: "all", qualifier: '-'}},
		},
		{
			// RFC 7208 6: unknown modifiers are ignored.
			"unknown-modifier",
			"v=spf1 moo=cow all",
			[]term{{mech: "all", qualifier: '+'}},
		},
		{
			// RFC 7208 4.6.1: mechanism names are case-insensitive.
			"case-insensitive",
			"V=SPF1 IP4:192.0.2.1 ALL",
			[]term{{mech: "ip4", qualifier: '+', arg: "192.0.2.1"}, {mech: "all", qualifier: '+'}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := ParseRecord(tt.record)
			if err != nil {
				t.Fatalf("ParseRecord(%q): %v", tt.record, err)
			}
			if !reflect.DeepEqual(rec.Terms, tt.want) {
				t.Errorf("terms = %+v, want %+v", rec.Terms, tt.want)
			}
		})
	}
}

func TestParseRecordErrors(t *testing.T) {
	tests := []struct {
		name   string
		record string
	}{
		// RFC 7208 4.5: version must be exactly "v=spf1".
		{"no-version", "ip4:192.0.2.1 all"},
		{"wrong-version", "v=spf10 ip4:192.0.2.1"},
		{"version-glued", "v=spf1ip4:192.0.2.1"},
		// RFC 7208 5.2: all takes no argument.
		{"all-with-arg", "v=spf1 all:192.0.2.1"},
		{"all-with-cidr", "v=spf1 all/24"},
		// RFC 7208 5.6: ip4 syntax.
		{"ip4-bare", "v=spf1 ip4"},
		{"ip4-empty-arg", "v=spf1 ip4:"},
		{"ip4-bad-addr", "v=spf1 ip4:foo"},
		{"ip4-short-addr", "v=spf1 ip4:1.2.3"},
		{"ip4-cidr-33", "v=spf1 ip4:192.0.2.1/33"},
		{"ip4-cidr-leading-zero", "v=spf1 ip4:192.0.2.1/032"},
		{"ip4-cidr-negative", "v=spf1 ip4:192.0.2.1/-1"},
		{"ip4-cidr-non-numeric", "v=spf1 ip4:192.0.2.1/x"},
		{"ip4-cidr-empty", "v=spf1 ip4:192.0.2.1/"},
		{"ip4-port", "v=spf1 ip4:1.2.3.4:80"},
		{"ip4-dual-cidr", "v=spf1 ip4:1.2.3.4//64"},
		// RFC 7208 5.6: ip6 syntax.
		{"ip6-bare", "v=spf1 ip6"},
		{"ip6-empty-arg", "v=spf1 ip6:"},
		{"ip6-bad-addr", "v=spf1 ip6:foo"},
		{"ip6-v4-addr", "v=spf1 ip6:1.2.3.4"},
		{"ip6-cidr-129", "v=spf1 ip6:2001:db8::/129"},
		{"ip6-cidr-non-numeric", "v=spf1 ip6:2001:db8::/x"},
		// RFC 7208 3.1: records are restricted to ASCII.
		{"non-ascii", "v=spf1 ip4:192.0.2.1 ï»¿-all"},
		{"non-ascii-arg", "v=spf1 ip4:192.0.2.ï»¿1"},
		// RFC 7208 4.6.1: modifier names start with a letter.
		{"modifier-digit-initial", "v=spf1 1up=foo"},
		// RFC 7208 7.1: modifier values are macro-strings.
		{"modifier-bare-percent", "v=spf1 -all foo=%abc"},
		{"modifier-dangling-percent", "v=spf1 -all foo=%"},
		{"modifier-unterminated-macro", "v=spf1 -all foo=%{s"},
		{"modifier-bad-macro-letter", "v=spf1 -all foo=%{w}"},
		// Unknown mechanisms are a syntax error for the evaluator to map
		// to permerror (RFC 7208 4.6.1).
		{"unknown-mechanism", "v=spf1 moo"},
		{"unknown-mechanism-arg", "v=spf1 moo:cow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRecord(tt.record)
			if err == nil {
				t.Errorf("ParseRecord(%q): want error, got nil", tt.record)
			}
		})
	}
}

func TestParseRecordUnknownMechanismIsReported(t *testing.T) { // Unknown mechanisms must be distinguishable from plain syntax errors
	// so the conformance harness can scope which cases can run yet.
	_, err := ParseRecord("v=spf1 a:example.com -all")
	if !IsUnsupported(err) {
		t.Errorf("IsUnsupported(ParseRecord error) = false, want true (err = %v)", err)
	}
	_, err = ParseRecord("v=spf1 all:192.0.2.1")
	if IsUnsupported(err) {
		t.Errorf("IsUnsupported(syntax error) = true, want false")
	}
}

func TestParseRecordIsSPF(t *testing.T) {
	// RFC 7208 4.5: a record is an SPF record iff it starts with the
	// version "v=spf1" terminated by a space or end of record.
	tests := []struct {
		record string
		want   bool
	}{
		{"v=spf1 -all", true},
		{"V=SPF1 -all", true},
		{"v=spf1", true},
		{"v=spf1 ", true},
		{"v=spf10 -all", false},
		{"v=spf12", false},
		{"spf1 -all", false},
		{"", false},
		{"v=spf2.0/pra -all", false},
	}
	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			if got := isSPF(tt.record); got != tt.want {
				t.Errorf("isSPF(%q) = %v, want %v", tt.record, got, tt.want)
			}
		})
	}
}

func TestParseRecordErrorMessagesAreQuoted(t *testing.T) {
	// Errors should name the offending record fragment for debuggability.
	_, err := ParseRecord("v=spf1 all:192.0.2.1")
	if err != nil && !strings.Contains(err.Error(), "all:192.0.2.1") {
		t.Errorf("error %q does not mention the offending term", err)
	}
}
