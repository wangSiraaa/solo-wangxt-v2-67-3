package registry

import (
	"context"
	"errors"
	"time"

	"protocompat/internal/compat"
)

// ErrVersionConflict is returned when a (package, version) pair already
// exists with different content. Versions are immutable: same version,
// different content is always rejected, never overwritten.
var ErrVersionConflict = errors.New("version already exists with different content")

// ErrNotFound is returned for unknown packages, versions or consumers.
var ErrNotFound = errors.New("not found")

// ErrConcurrency is returned when an optimistic-concurrency transition is
// attempted against a stale version: someone else moved the row first.
var ErrConcurrency = errors.New("concurrent modification")

// ErrInvalidState is returned when a state transition is not allowed from
// the exemption's current status (e.g. approving an exemption another
// approver already approved, or approving a revoked one).
var ErrInvalidState = errors.New("invalid state for transition")

// Version is one immutable registered schema version.
type Version struct {
	Package       string
	Version       string
	ContentHash   []byte
	DescriptorSet []byte
	OwnedPaths    []string
	CreatedAt     time.Time
}

// ConsumerDecl is a consumer's declared usage of a package: which
// messages/fields it reads and over which encoding. Declarations let the
// service project global findings onto the surface a consumer actually
// depends on.
type ConsumerDecl struct {
	Package   string
	Consumer  string
	Encoding  string // "wire", "json" or "both"
	Usages    []Usage
	UpdatedAt time.Time
}

// StoredReport is a persisted compatibility verdict.
type StoredReport struct {
	Package     string
	BaseVersion string
	HeadVersion string
	Report      *compat.Report
	CreatedAt   time.Time
}

// Exemption status values. EXPIRED is never stored: it is derived at read
// time from an APPROVED exemption whose expires_at has passed, so blocking
// resumes the instant the boundary is reached, with no background job.
const (
	ExemptionPending  = "PENDING"
	ExemptionApproved = "APPROVED"
	ExemptionRevoked  = "REVOKED"
	ExemptionExpired  = "EXPIRED" // derived only, never persisted
)

// Exemption is a time-bound, consumer-scoped waiver for one semantic
// finding (identified by its fingerprint) in a package. It takes effect
// only after an approver other than the requester approves it. Every
// mutation is an optimistic-concurrency transition on Version.
type Exemption struct {
	ID          string         `json:"id"`
	Package     string         `json:"package"`
	Fingerprint string         `json:"fingerprint"`
	Finding     compat.Finding `json:"finding"` // snapshot at request time
	// BaseVersion/HeadVersion identify the report the exemption was
	// requested against. Matching at evaluation time is by fingerprint,
	// so the exemption carries over to later reports of the package as
	// long as the finding's semantic fingerprint is unchanged.
	BaseVersion string    `json:"base_version"`
	HeadVersion string    `json:"head_version"`
	Owner       string    `json:"owner"`
	Reason      string    `json:"reason"`
	Consumers   []string  `json:"consumers"` // "*" covers every consumer and unscoped checks
	RequestedBy string    `json:"requested_by"`
	ApprovedBy  string    `json:"approved_by,omitempty"`
	RevokedBy   string    `json:"revoked_by,omitempty"`
	Status      string    `json:"status"` // PENDING | APPROVED | REVOKED (EXPIRED derived)
	ExpiresAt   time.Time `json:"expires_at"`
	// RequestID is an optional idempotency key supplied by the caller;
	// a repeated create with the same key returns the existing row.
	RequestID string    `json:"request_id,omitempty"`
	Version   int64     `json:"version"` // optimistic concurrency token
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EffectiveStatus maps an APPROVED exemption past its expiry to EXPIRED.
// The stored status is never rewritten lazily; expiry is a function of
// time, evaluated on every read.
func (e *Exemption) EffectiveStatus(now time.Time) string {
	if e.Status == ExemptionApproved && !now.Before(e.ExpiresAt) {
		return ExemptionExpired
	}
	return e.Status
}

// Exemption event names written to the audit log on every transition.
const (
	ExemptionEventRequested = "REQUESTED"
	ExemptionEventApproved  = "APPROVED"
	ExemptionEventRevoked   = "REVOKED"
)

// ExemptionEvent is one audit-log entry for an exemption state
// transition. Events are written in the same transaction as the
// transition itself.
type ExemptionEvent struct {
	ID          int64
	ExemptionID string
	Event       string
	Actor       string
	Detail      string // JSON snapshot of the transition context
	CreatedAt   time.Time
}

// Store persists packages, versions, consumer declarations and reports.
type Store interface {
	// PutVersion registers an immutable version. It returns created=false
	// when the exact same content was already registered (idempotent
	// retry), and ErrVersionConflict when the version exists with
	// different content.
	PutVersion(ctx context.Context, v Version) (created bool, err error)
	GetVersion(ctx context.Context, pkg, version string) (*Version, error)
	// LatestVersion returns the most recently registered version.
	LatestVersion(ctx context.Context, pkg string) (*Version, error)
	ListVersions(ctx context.Context, pkg string) ([]Version, error)

	PutReport(ctx context.Context, rep StoredReport) error
	// GetReport returns the most recently stored report for a
	// (package, base, head) triple, or ErrNotFound. Reports are
	// append-only historical artifacts; nothing ever updates them.
	GetReport(ctx context.Context, pkg, baseVersion, headVersion string) (*StoredReport, error)

	UpsertConsumer(ctx context.Context, decl ConsumerDecl) error
	GetConsumer(ctx context.Context, pkg, consumer string) (*ConsumerDecl, error)

	// CreateExemption inserts a PENDING exemption and its REQUESTED
	// audit event. When ex.RequestID is set and already exists, the
	// stored exemption is returned unchanged (idempotent retry).
	CreateExemption(ctx context.Context, ex Exemption) (*Exemption, error)
	GetExemption(ctx context.Context, id string) (*Exemption, error)
	// ListExemptions returns every exemption of a package, oldest first.
	ListExemptions(ctx context.Context, pkg string) ([]Exemption, error)
	// ApproveExemption atomically moves PENDING -> APPROVED, guarded by
	// expectedVersion, and writes the APPROVED audit event. A retry by
	// the same approver of an already-approved exemption returns the
	// current state without error (idempotent); a different approver
	// gets ErrInvalidState, a stale version ErrConcurrency.
	ApproveExemption(ctx context.Context, id string, expectedVersion int64, approver string, now time.Time) (*Exemption, error)
	// RevokeExemption atomically moves PENDING|APPROVED -> REVOKED,
	// guarded by expectedVersion, and writes the REVOKED audit event.
	// Revoking an already-revoked exemption is an idempotent no-op.
	RevokeExemption(ctx context.Context, id string, expectedVersion int64, revoker, reason string, now time.Time) (*Exemption, error)
	// ListExemptionEvents returns the audit trail of one exemption.
	ListExemptionEvents(ctx context.Context, exemptionID string) ([]ExemptionEvent, error)
}
