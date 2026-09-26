package registry

import (
	"time"

	"protocompat/internal/compat"
	"protocompat/internal/schema"
)

// --- API request/response types (JSON codec over ConnectRPC) ---

type RegisterVersionRequest struct {
	Package     string              `json:"package"`
	Version     string              `json:"version"`
	Files       []schema.SourceFile `json:"files"`
	BaseVersion string              `json:"base_version,omitempty"`
	Samples     []compat.Sample     `json:"samples,omitempty"`
	// RequireCompatible refuses registration when the check against the
	// base version proves an incompatibility (verdict INCOMPATIBLE).
	RequireCompatible bool `json:"require_compatible,omitempty"`
	// Consumer scopes the publish gate to one consumer: in-force
	// exemptions granted to that consumer may downgrade an otherwise
	// blocking verdict. The raw report is always returned unchanged.
	Consumer string `json:"consumer,omitempty"`
}

type RegisterVersionResponse struct {
	Package        string         `json:"package"`
	Version        string         `json:"version"`
	ContentHash    string         `json:"content_hash"`
	AlreadyExisted bool           `json:"already_existed"`
	BaseVersion    string         `json:"base_version,omitempty"`
	Compatibility  *compat.Report `json:"compatibility,omitempty"`
	// Report annotates the same immutable report with finding fingerprints
	// and source lines. It duplicates nothing mutable: the raw report above
	// is what is stored.
	Report *ReportView `json:"report,omitempty"`
	// Publish is the derived gate decision, optionally exemption-adjusted
	// for the requested consumer.
	Publish *PublishDecisionView `json:"publish,omitempty"`
}

type CheckRequest struct {
	Package          string              `json:"package"`
	BaseVersion      string              `json:"base_version"`
	CandidateVersion string              `json:"candidate_version,omitempty"`
	CandidateFiles   []schema.SourceFile `json:"candidate_files,omitempty"`
	Samples          []compat.Sample     `json:"samples,omitempty"`
	Consumer         string              `json:"consumer,omitempty"`
}

type CheckResponse struct {
	BaseVersion    string          `json:"base_version"`
	HeadVersion    string          `json:"head_version"`
	Report         *compat.Report  `json:"report"`
	ConsumerImpact *ConsumerImpact `json:"consumer_impact,omitempty"`
	// Annotated is the same report with fingerprints/source lines.
	Annotated *ReportView `json:"annotated,omitempty"`
	// ConsumerDecision is the exemption-aware projection for the named
	// consumer: raw verdict plus the waiver-adjusted publish verdict.
	ConsumerDecision *ConsumerDecisionView `json:"consumer_decision,omitempty"`
}

type ConsumerImpact struct {
	Consumer string           `json:"consumer"`
	Encoding string           `json:"encoding"`
	Verdict  compat.Verdict   `json:"verdict"`
	Findings []compat.Finding `json:"findings"`
}

type Usage struct {
	Message string   `json:"message"`          // fully-qualified message name
	Fields  []string `json:"fields,omitempty"` // field paths; empty = whole message
}

type DeclareConsumerRequest struct {
	Package  string  `json:"package"`
	Consumer string  `json:"consumer"`
	Encoding string  `json:"encoding"` // "wire", "json" or "both"
	Usages   []Usage `json:"usages,omitempty"`
}

type DeclareConsumerResponse struct {
	Declared bool `json:"declared"`
}

type ListVersionsRequest struct {
	Package string `json:"package"`
}

type VersionMeta struct {
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
	CreatedAt   string `json:"created_at"`
}

type ListVersionsResponse struct {
	Package  string        `json:"package"`
	Versions []VersionMeta `json:"versions"`
}

// PublishDecisionView is the gate verdict for a publish. When a consumer
// is named it is scoped to that consumer's declared surface and grants.
type PublishDecisionView struct {
	Consumer string `json:"consumer,omitempty"`
	// RawVerdict is the verdict the evidence dictates without exemptions.
	RawVerdict compat.Verdict `json:"raw_verdict"`
	// Verdict is the release verdict after exemptions: it can be EXEMPTED
	// where the raw verdict blocks.
	Verdict PublishVerdict `json:"verdict"`
	// Findings is the considered surface with each applied waiver shown.
	Findings   []FindingView `json:"findings,omitempty"`
	Exemptions []int64       `json:"applied_exemption_ids,omitempty"`
}

// ConsumerDecisionView is the consumer-projected equivalent of
// PublishDecisionView for ad-hoc CheckCompatibility calls.
type ConsumerDecisionView struct {
	Consumer   string         `json:"consumer"`
	Encoding   string         `json:"encoding"`
	RawVerdict compat.Verdict `json:"raw_verdict"`
	Verdict    PublishVerdict `json:"verdict"`
	Findings   []FindingView  `json:"findings,omitempty"`
	Exemptions []int64        `json:"applied_exemption_ids,omitempty"`
}

// --- exemption lifecycle ---

type RequestExemptionRequest struct {
	Package     string `json:"package"`
	BaseVersion string `json:"base_version"`
	HeadVersion string `json:"head_version"`
	// Fingerprint identifies the finding. Alternatively finding_index may
	// locate it within the stored report (0-based, findings array order).
	Fingerprint  string   `json:"fingerprint,omitempty"`
	FindingIndex *int     `json:"finding_index,omitempty"`
	Owner        string   `json:"owner"`
	Reason       string   `json:"reason"`
	Consumers    []string `json:"consumers"`
	// RequestedBy is the applicant identity. It cannot equal the approver.
	RequestedBy string `json:"requested_by"`
	// ExpiresAt is an RFC3339 instant; the waiver is in force strictly
	// before it.
	ExpiresAt string `json:"expires_at"`
}

type ExemptionView struct {
	ID               int64           `json:"id"`
	Package          string          `json:"package"`
	BaseVersion      string          `json:"base_version"`
	HeadVersion      string          `json:"head_version"`
	Fingerprint      string          `json:"fingerprint"`
	OriginalSeverity compat.Severity `json:"original_severity"`
	Owner            string          `json:"owner"`
	Reason           string          `json:"reason"`
	Consumers        []string        `json:"consumers"`
	RequestedBy      string          `json:"requested_by"`
	Status           ExemptionStatus `json:"status"`
	ApprovedBy       string          `json:"approved_by,omitempty"`
	RejectedBy       string          `json:"rejected_by,omitempty"`
	RevokedBy        string          `json:"revoked_by,omitempty"`
	ExpiresAt        string          `json:"expires_at,omitempty"`
	DecidedAt        string          `json:"decided_at,omitempty"`
	CreatedAt        string          `json:"created_at"`
	// Version is the optimistic-concurrency token to echo back on the
	// next transition.
	Version int64 `json:"version"`
}

func toExemptionView(e *Exemption) ExemptionView {
	v := ExemptionView{
		ID:               e.ID,
		Package:          e.Package,
		BaseVersion:      e.BaseVersion,
		HeadVersion:      e.HeadVersion,
		Fingerprint:      e.Fingerprint,
		OriginalSeverity: e.OriginalSeverity,
		Owner:            e.Owner,
		Reason:           e.Reason,
		Consumers:        append([]string{}, e.Consumers...),
		RequestedBy:      e.RequestedBy,
		Status:           e.Status,
		ApprovedBy:       e.ApprovedBy,
		RejectedBy:       e.RejectedBy,
		RevokedBy:        e.RevokedBy,
		Version:          e.Version,
		CreatedAt:        e.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if !e.ExpiresAt.IsZero() {
		v.ExpiresAt = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !e.DecidedAt.IsZero() {
		v.DecidedAt = e.DecidedAt.UTC().Format(time.RFC3339)
	}
	return v
}

type ExemptionResponse struct {
	Exemption      ExemptionView `json:"exemption"`
	AlreadyExisted bool          `json:"already_existed"`
}

type DecideExemptionRequest struct {
	ID int64 `json:"id"`
	// ExpectedVersion is the optimistic-concurrency token the caller read.
	ExpectedVersion int64 `json:"expected_version"`
	// Actor is the approver/rejecter identity. It must differ from the
	// requester.
	Actor string `json:"actor"`
}

type ApproveExemptionRequest = DecideExemptionRequest
type RejectExemptionRequest = DecideExemptionRequest

type RevokeExemptionRequest struct {
	ID              int64  `json:"id"`
	ExpectedVersion int64  `json:"expected_version"`
	Actor           string `json:"actor"`
	Reason          string `json:"reason,omitempty"`
}

type ListExemptionsRequest struct {
	Package     string `json:"package"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type ListExemptionsResponse struct {
	Package    string          `json:"package"`
	Exemptions []ExemptionView `json:"exemptions"`
}

type GetExemptionRequest struct {
	ID int64 `json:"id"`
}

type AuditEventView struct {
	ID          int64           `json:"id"`
	ExemptionID int64           `json:"exemption_id"`
	Action      string          `json:"action"`
	Actor       string          `json:"actor"`
	FromState   ExemptionStatus `json:"from_state,omitempty"`
	ToState     ExemptionStatus `json:"to_state"`
	Version     int64           `json:"version"`
	Detail      string          `json:"detail,omitempty"`
	CreatedAt   string          `json:"created_at"`
}

type ListAuditEventsRequest struct {
	Package     string `json:"package"`
	ExemptionID int64  `json:"exemption_id,omitempty"`
}

type ListAuditEventsResponse struct {
	Package string           `json:"package"`
	Events  []AuditEventView `json:"events"`
}
