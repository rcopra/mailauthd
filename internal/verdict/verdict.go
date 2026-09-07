// Package verdict defines the domain vocabulary of mailauthd: Verdict,
// Result, Check, and Disposition. See CONTEXT.md for the glossary.
package verdict

// Check names one standard email authentication mechanism.
type Check string

const (
	CheckSPF   Check = "spf"
	CheckDKIM  Check = "dkim"
	CheckDMARC Check = "dmarc"
)

// Result is the outcome of running one Check against a Message.
type Result struct {
	Check   Check  `json:"check"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// Disposition is the message fate derived from DMARC policy evaluation.
type Disposition string

const (
	DispositionPass       Disposition = "pass"
	DispositionQuarantine Disposition = "quarantine"
	DispositionReject     Disposition = "reject"
	DispositionNone       Disposition = "none"
)

// Verdict is the full response for one Message.
type Verdict struct {
	Disposition Disposition `json:"disposition"`
	Results     []Result    `json:"results"`
}
