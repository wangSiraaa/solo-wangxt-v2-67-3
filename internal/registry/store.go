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

// ErrConcurrentModification is returned when an exemption state
// transition presents a stale optimistic-concurrency version.
var ErrConcurrentModification = errors.New("exemption was modified concurrently; re-read and retry")

// ErrInvalidStateTransition is returned when an exemption is not in the
// state the operation requires (e.g. approving an already-rejected one).
var ErrInvalidStateTransition = errors.New("invalid exemption state transition")

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
	// (package, base, head) tuple.
	GetReport(ctx context.Context, pkg, base, head string) (*StoredReport, error)

	UpsertConsumer(ctx context.Context, decl ConsumerDecl) error
	GetConsumer(ctx context.Context, pkg, consumer string) (*ConsumerDecl, error)

	// CreateExemption stores a PENDING exemption and its REQUESTED audit
	// event atomically. Idempotency is enforced by (package, fingerprint,
	// requested_by) while the request is still open: a repeat request
	// returns the existing row with created=false.
	CreateExemption(ctx context.Context, e Exemption) (ex *Exemption, created bool, err error)
	GetExemption(ctx context.Context, id int64) (*Exemption, error)
	// ListExemptions returns the package's exemptions, newest first. When
	// fingerprint is non-empty only that finding's exemptions are returned.
	ListExemptions(ctx context.Context, pkg, fingerprint string) ([]Exemption, error)

	// TransitionExemption applies one optimistic-concurrency state move.
	// It succeeds only when the stored row is still at expectedVersion and
	// in state expectFrom; then it sets the fields given in want, bumps the
	// version and appends one audit event — all in one transaction.
	TransitionExemption(ctx context.Context, id, expectedVersion int64, expectFrom ExemptionStatus, want ExemptionPatch, event AuditEvent) (*Exemption, error)

	// ActiveExemptionsForPackage returns every APPROVED exemption in the
	// package (expiry is judged at query time by the service).
	ActiveExemptionsForPackage(ctx context.Context, pkg string) ([]Exemption, error)

	// ListAuditEvents returns a package's exemption audit trail, oldest
	// first, optionally narrowed to one exemption.
	ListAuditEvents(ctx context.Context, pkg string, exemptionID int64) ([]AuditEvent, error)
}

// ExemptionPatch carries the columns a transition writes. Fields left
// zero-valued are untouched (apart from state, which is always required).
type ExemptionPatch struct {
	Status     ExemptionStatus
	ApprovedBy string
	RejectedBy string
	RevokedBy  string
	DecidedAt  *time.Time
}
