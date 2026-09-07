package spf

import "testing"

// FuzzParseRecord hammers the record parser. The parser must never panic
// and must reject invalid records without producing partial garbage.
// Any crash becomes a table row in record_test.go

func FuzzParseRecord(f *testing.F) {
	seeds := []string{
		"v=spf1 -all",
		"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 ~all",
		"v=spf1 ?all moo=cow",
		"V=SPF1 -ALL",
		"v=spf1",
		"v=spf1  ip4:1.2.3.4  -all  ",
		"v=spf1 ip4:1.2.3.4/33",
		"v=spf1 redirect=example.com",
		"v=spf1 -all foo=%{s}",
		"v=spf10",
		"a b c",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, record string) {
		rec, err := ParseRecord(record)
		if err != nil {
			if rec != nil {
				t.Fatalf("ParseRecord(%q) returned both error %v and record", record, err)
			}
			return
		}
		if rec == nil {
			t.Fatalf("ParseRecord(%q) returned nil record and nil error", record)
		}
	})
}
