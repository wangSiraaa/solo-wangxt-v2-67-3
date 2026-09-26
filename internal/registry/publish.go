package registry

import (
	"time"

	"protocompat/internal/compat"
)

// FindingView is one finding as returned over the API: the raw evidence
// exactly as the checker produced it, plus its stable fingerprint, a
// presentation-only source line and — when applicable — the exemption
// that currently waives it for the requesting consumer.
type FindingView struct {
	Code        string           `json:"code"`
	Severity    compat.Severity  `json:"severity"`
	Dimension   compat.Dimension `json:"dimension"`
	Message     string           `json:"message,omitempty"`
	Path        string           `json:"path,omitempty"`
	Detail      string           `json:"detail"`
	Line        int              `json:"line,omitempty"`
	Fingerprint string           `json:"fingerprint"`
	Exemption   *ExemptionRef    `json:"exemption,omitempty"`
}

// ExemptionRef explains which active exemption waived a finding.
type ExemptionRef struct {
	ID          int64  `json:"id"`
	Owner       string `json:"owner"`
	RequestedBy string `json:"requested_by"`
	ApprovedBy  string `json:"approved_by"`
	ExpiresAt   string `json:"expires_at"`
	Reason      string `json:"reason"`
}

// ReportView is the immutable report presented over the wire.
type ReportView struct {
	Verdict  compat.Verdict        `json:"verdict"`
	Findings []FindingView         `json:"findings"`
	Samples  []compat.SampleResult `json:"samples,omitempty"`
}

// PublishVerdict is the derived, possibly waiver-adjusted gate decision.
type PublishVerdict string

const (
	PublishCompatible   PublishVerdict = "COMPATIBLE"
	PublishNeedsReview  PublishVerdict = "NEEDS_REVIEW"
	PublishIncompatible PublishVerdict = "INCOMPATIBLE"
	// PublishExempted means raw evidence blocks or requires review, but
	// every blocking finding is covered by an in-force exemption for this
	// consumer (and at least one exemption was actually applied).
	PublishExempted PublishVerdict = "EXEMPTED"
)

// buildReportView renders a raw report with fingerprints and lines. It
// never mutates the input: historical reports are append-only.
func buildReportView(pkg string, report *compat.Report, lines []int) *ReportView {
	view := &ReportView{Verdict: report.Verdict, Samples: report.Samples}
	for i, f := range report.Findings {
		line := 0
		if i < len(lines) {
			line = lines[i]
		}
		view.Findings = append(view.Findings, FindingView{
			Code:        f.Code,
			Severity:    f.Severity,
			Dimension:   f.Dimension,
			Message:     f.Message,
			Path:        f.Path,
			Detail:      f.Detail,
			Line:        line,
			Fingerprint: compat.FindingFingerprint(pkg, f),
		})
	}
	return view
}

// projection is a finding projected onto a consumer plus the active
// exemption (if any) waiving it at instant now.
type projection struct {
	finding   FindingView
	exemption *Exemption
}

// projectFindings applies consumer dimension/usage filtering (the same
// rules as consumerImpact historically used), then annotates every
// surviving finding with any in-force exemption scoped to this consumer
// and matching its fingerprint.
func (s *Service) projectFindings(consumer string, view *ReportView, decl *ConsumerDecl, exemptions []*Exemption, now time.Time) []projection {
	active := map[string]*Exemption{}
	for _, e := range exemptions {
		if e.InForce(now) && e.AppliesTo(consumer) {
			active[e.Fingerprint] = e
		}
	}
	var out []projection
	for _, f := range view.Findings {
		if !dimensionRelevant(decl.Encoding, f.Dimension) {
			continue
		}
		if !usageCovers(decl.Usages, compat.Finding{Message: f.Message, Path: f.Path}) {
			continue
		}
		ex := active[f.Fingerprint]
		if ex != nil {
			f.Exemption = exemptionRef(ex)
		}
		out = append(out, projection{finding: f, exemption: ex})
	}
	return out
}

func exemptionRef(e *Exemption) *ExemptionRef {
	return &ExemptionRef{
		ID:          e.ID,
		Owner:       e.Owner,
		RequestedBy: e.RequestedBy,
		ApprovedBy:  e.ApprovedBy,
		ExpiresAt:   e.ExpiresAt.UTC().Format(time.RFC3339),
		Reason:      e.Reason,
	}
}

// publishDecision aggregates projected findings. The raw verdict ignores
// exemptions entirely; the publish verdict removes findings waived by an
// in-force, in-scope exemption and then re-aggregates. When any waiver is
// actually consumed and the residual surface would otherwise gate, the
// result is EXEMPTED rather than COMPATIBLE, so an exemption stays
// visible in the gate it silences.
func publishDecision(projected []projection) (compat.Verdict, PublishVerdict, []int64) {
	raw, gated := compat.VerdictCompatible, compat.VerdictCompatible
	var applied []int64
	for _, p := range projected {
		sev := p.finding.Severity
		switch sev {
		case compat.SeverityFail:
			raw = compat.VerdictIncompatible
		case compat.SeverityWarn:
			if raw != compat.VerdictIncompatible {
				raw = compat.VerdictNeedsReview
			}
		}
		if p.exemption != nil {
			applied = append(applied, p.exemption.ID)
			continue
		}
		switch sev {
		case compat.SeverityFail:
			gated = compat.VerdictIncompatible
		case compat.SeverityWarn:
			if gated != compat.VerdictIncompatible {
				gated = compat.VerdictNeedsReview
			}
		}
	}
	publish := PublishVerdict(gated)
	if len(applied) > 0 && gated == compat.VerdictCompatible && raw != compat.VerdictCompatible {
		publish = PublishExempted
	}
	return raw, publish, applied
}
