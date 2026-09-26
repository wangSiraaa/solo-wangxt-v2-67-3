package registry

import (
	"time"

	"protocompat/internal/compat"
)

// ExemptionStatus is the lifecycle state of an exemption request.
type ExemptionStatus string

const (
	// ExemptionPending awaits approval by someone other than the requester.
	ExemptionPending ExemptionStatus = "PENDING"
	// ExemptionApproved is in force until its expires_at instant.
	ExemptionApproved ExemptionStatus = "APPROVED"
	// ExemptionRejected is terminal: an approver refused it.
	ExemptionRejected ExemptionStatus = "REJECTED"
	// ExemptionRevoked is terminal: an active exemption was withdrawn early.
	ExemptionRevoked ExemptionStatus = "REVOKED"
	// ExemptionExpired is terminal: the approved window elapsed. It is
	// derived lazily (no background job) and persisted once observed so the
	// transition appears in the audit trail.
	ExemptionExpired ExemptionStatus = "EXPIRED"
)

// Exemption is a time-bounded waiver for one deterministic finding in
// one package's compatibility reports. It never alters stored reports:
// reports stay immutable and the exemption only affects derived publish
// decisions at query time.
type Exemption struct {
	ID int64
	// Report coordinates the finding was first requested against.
	Package     string
	BaseVersion string
	HeadVersion string
	// Fingerprint is the position-independent identity of the finding
	// (compat.FindingFingerprint). Line shifts leave it intact; rule or
	// object changes produce a new fingerprint.
	Fingerprint string
	// OriginalSeverity snapshots the severity in the report the request
	// was filed against, so the response can always show the raw severity
	// alongside the waived publish decision.
	OriginalSeverity compat.Severity

	Owner       string // responsible person (a human identity)
	Reason      string
	Consumers   []string
	RequestedBy string
	CreatedAt   time.Time

	Status     ExemptionStatus
	ApprovedBy string
	RejectedBy string
	RevokedBy  string
	ExpiresAt  time.Time
	DecidedAt  time.Time // approval/rejection/expiry/revocation instant
	// Version is the optimistic-concurrency token. Every state transition
	// must present the version read by the caller and bumps it exactly
	// once; stale updates lose the race and change nothing.
	Version int64
}

// InForce reports whether the exemption actively waives at instant now:
// approved and the half-open window [approved, expires_at) still covers
// now. The exact boundary expires_at is treated as already expired, so a
// query arriving at that instant immediately restores the block.
func (e *Exemption) InForce(now time.Time) bool {
	return e.Status == ExemptionApproved && now.Before(e.ExpiresAt)
}

// AppliesTo reports whether this exemption covers the named consumer.
func (e *Exemption) AppliesTo(consumer string) bool {
	for _, c := range e.Consumers {
		if c == consumer {
			return true
		}
	}
	return false
}

// AuditEvent is an append-only record of one exemption lifecycle action.
// State transitions and their audit rows are written in one database
// transaction.
type AuditEvent struct {
	ID          int64
	ExemptionID int64
	Package     string
	// Action: REQUESTED | APPROVED | REJECTED | REVOKED | EXPIRED.
	Action    string
	Actor     string
	FromState ExemptionStatus
	ToState   ExemptionStatus
	Version   int64
	Detail    string
	CreatedAt time.Time
}
