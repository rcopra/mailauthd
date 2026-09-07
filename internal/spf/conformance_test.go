package spf

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
)

// Conformance test against the open-spf.org RFC 7208 test suite (release
// 2014.04), stored as JSON in testdata/ alongside the original YAML and
// its license. See testdata/README.md for provenance.
//
// No cases are hand-picked: every case runs unless the SPF records in its
// zone use mechanisms or modifiers that are not implemented yet, in which
// case it is skipped with the reason. As more of RFC 7208 is implemented,
// the skipped set shrinks automatically.

type suiteTest struct {
	Spec        json.RawMessage `json:"spec"`
	Description string          `json:"description"`
	Helo        string          `json:"helo"`
	Host        string          `json:"host"`
	MailFrom    string          `json:"mailfrom"`
	Result      json.RawMessage `json:"result"`
}

type suiteSection struct {
	Description string                `json:"description"`
	Tests       map[string]suiteTest  `json:"tests"`
	Zonedata    map[string][]json.RawMessage `json:"zonedata"`
}

func loadSuite(t *testing.T) []suiteSection {
	t.Helper()
	data, err := os.ReadFile("testdata/rfc7208-tests.json")
	if err != nil {
		t.Fatalf("reading test suite: %v", err)
	}
	var sections []suiteSection
	if err := json.Unmarshal(data, &sections); err != nil {
		t.Fatalf("parsing test suite: %v", err)
	}
	return sections
}

// decodeStrings handles suite values that are either a string or a list of
// strings (TXT chunk lists, multi-result expectations).
func decodeStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	return nil
}

// buildZoneResolver turns a section's zonedata into a fixtureResolver
// with the driver rules above. Only TXT/SPF records are modelled; that is
// all the ip4/ip6/all subset consults.
func buildZoneResolver(section suiteSection) *fixtureResolver {
	r := newFixtureResolver(map[string][]string{})
	for name, entries := range section.Zonedata {
		zoneName := strings.ToLower(strings.TrimSuffix(name, "."))
		var txtRecords, spfRecords []string
		timeout := false
		txtGiven := false // any TXT entry, including "NONE"
		for _, entry := range entries {
			var rec map[string]json.RawMessage
			if err := json.Unmarshal(entry, &rec); err != nil {
				// Bare marker like "TIMEOUT".
				if strings.Contains(strings.ToUpper(string(entry)), "TIMEOUT") {
					timeout = true
				}
				continue
			}
			for kind, value := range rec {
				parts := decodeStrings(value)
				switch strings.ToUpper(kind) {
				case "TXT":
					txtGiven = true
					if len(parts) == 1 && parts[0] == "NONE" {
						continue // suppresses the SPF auto-copy
					}
					txtRecords = append(txtRecords, strings.Join(parts, ""))
				case "SPF":
					if len(parts) == 1 && parts[0] == "NONE" {
						continue
					}
					spfRecords = append(spfRecords, strings.Join(parts, ""))
				}
			}
		}
		// Auto-copy: SPF records only when no TXT records were given;
		// an explicit TXT: NONE suppresses the copy.
		records := txtRecords
		if !txtGiven {
			records = append(records, spfRecords...)
		}
		if len(records) > 0 || timeout {
			r.zones[zoneName] = zone{txt: records, timeout: timeout}
		}
	}
	return r
}

// checkDomain derives the check_host() domain for a suite test per RFC
// 7208 4.3: the MAIL FROM domain, or HELO when MAIL FROM is empty.
func checkDomain(tt suiteTest) string {
	if i := strings.LastIndex(tt.MailFrom, "@"); i >= 0 {
		return tt.MailFrom[i+1:]
	}
	return tt.Helo
}

func TestRFC7208Conformance(t *testing.T) {
	sections := loadSuite(t)
	for _, section := range sections {
		section := section
		for name, tt := range section.Tests {
			name, tt := name, tt
			t.Run(section.Description+"/"+name, func(t *testing.T) {
				t.Parallel()
				want := decodeStrings(tt.Result)
				if len(want) == 0 {
					t.Fatalf("test has no expected result")
				}

				domain := checkDomain(tt)
				r := buildZoneResolver(section)

				// Scope: the case can run only if every SPF record in
				// its zone parses with the implemented subset. Records
				// using unimplemented surface make us skip, not fail.
				zoneName := strings.ToLower(strings.TrimSuffix(domain, "."))
				for _, rec := range r.zones[zoneName].txt {
					if !isSPF(rec) {
						continue
					}
					_, err := ParseRecord(rec)
					if IsUnsupported(err) {
						t.Skipf("unimplemented SPF surface: %v", err)
					}
				}

				got, reason := CheckHost(context.Background(), r, net.ParseIP(tt.Host), domain, tt.MailFrom)
				for _, w := range want {
					if got == w {
						return
					}
				}
				t.Errorf("got %s (%s), want one of %v", got, reason, want)
			})
		}
	}
}
