package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"protocompat/internal/compat"
)

// PGStore is the PostgreSQL-backed Store. Packages, immutable versions,
// consumer declarations and compatibility reports live here.
type PGStore struct {
	db *sql.DB
}

func NewPGStore(db *sql.DB) *PGStore {
	return &PGStore{db: db}
}

// ensurePackage returns the package id, creating the row if needed.
func (s *PGStore) ensurePackage(ctx context.Context, tx *sql.Tx, name string) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
		WITH ins AS (
			INSERT INTO packages (name) VALUES ($1)
			ON CONFLICT (name) DO NOTHING
			RETURNING id
		)
		SELECT id FROM ins
		UNION ALL SELECT id FROM packages WHERE name = $1
		LIMIT 1`, name).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("ensure package %q: %w", name, err)
	}
	return id, nil
}

func (s *PGStore) PutVersion(ctx context.Context, v Version) (bool, error) {
	owned, err := json.Marshal(v.OwnedPaths)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	pkgID, err := s.ensurePackage(ctx, tx, v.Package)
	if err != nil {
		return false, err
	}

	var insertedID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO versions (package_id, version, content_hash, descriptor_set, owned_paths)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (package_id, version) DO NOTHING
		RETURNING id`, pkgID, v.Version, v.ContentHash, v.DescriptorSet, owned).Scan(&insertedID)
	switch {
	case err == nil:
		// New row inserted.
	case errors.Is(err, sql.ErrNoRows):
		// (package, version) exists: identical content is an idempotent
		// retry; different content is rejected, never overwritten.
		var existingHash []byte
		qerr := tx.QueryRowContext(ctx, `
			SELECT content_hash FROM versions WHERE package_id = $1 AND version = $2`,
			pkgID, v.Version).Scan(&existingHash)
		if qerr != nil {
			return false, fmt.Errorf("check existing version: %w", qerr)
		}
		if !bytes.Equal(existingHash, v.ContentHash) {
			return false, ErrVersionConflict
		}
		return false, nil
	default:
		return false, fmt.Errorf("insert version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *PGStore) GetVersion(ctx context.Context, pkg, version string) (*Version, error) {
	var v Version
	var owned []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT p.name, v.version, v.content_hash, v.descriptor_set, v.owned_paths, v.created_at
		FROM versions v JOIN packages p ON p.id = v.package_id
		WHERE p.name = $1 AND v.version = $2`, pkg, version).
		Scan(&v.Package, &v.Version, &v.ContentHash, &v.DescriptorSet, &owned, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(owned, &v.OwnedPaths); err != nil {
		return nil, fmt.Errorf("decode owned paths: %w", err)
	}
	return &v, nil
}

func (s *PGStore) LatestVersion(ctx context.Context, pkg string) (*Version, error) {
	var v Version
	var owned []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT p.name, v.version, v.content_hash, v.descriptor_set, v.owned_paths, v.created_at
		FROM versions v JOIN packages p ON p.id = v.package_id
		WHERE p.name = $1
		ORDER BY v.created_at DESC, v.id DESC
		LIMIT 1`, pkg).
		Scan(&v.Package, &v.Version, &v.ContentHash, &v.DescriptorSet, &owned, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(owned, &v.OwnedPaths); err != nil {
		return nil, fmt.Errorf("decode owned paths: %w", err)
	}
	return &v, nil
}

func (s *PGStore) ListVersions(ctx context.Context, pkg string) ([]Version, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.name, v.version, v.content_hash, v.owned_paths, v.created_at
		FROM versions v JOIN packages p ON p.id = v.package_id
		WHERE p.name = $1
		ORDER BY v.created_at, v.id`, pkg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var owned []byte
		if err := rows.Scan(&v.Package, &v.Version, &v.ContentHash, &owned, &v.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(owned, &v.OwnedPaths); err != nil {
			return nil, fmt.Errorf("decode owned paths: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PGStore) PutReport(ctx context.Context, rep StoredReport) error {
	body, err := json.Marshal(rep.Report)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	pkgID, err := s.ensurePackage(ctx, tx, rep.Package)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO reports (package_id, base_version, head_version, verdict, report)
		VALUES ($1, $2, $3, $4, $5)`,
		pkgID, rep.BaseVersion, rep.HeadVersion, string(rep.Report.Verdict), body)
	if err != nil {
		return fmt.Errorf("insert report: %w", err)
	}
	return tx.Commit()
}

func (s *PGStore) GetReport(ctx context.Context, pkg, baseVersion, headVersion string) (*StoredReport, error) {
	var rep StoredReport
	var body []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT p.name, r.base_version, r.head_version, r.report, r.created_at
		FROM reports r JOIN packages p ON p.id = r.package_id
		WHERE p.name = $1 AND r.base_version = $2 AND r.head_version = $3
		ORDER BY r.id DESC
		LIMIT 1`, pkg, baseVersion, headVersion).
		Scan(&rep.Package, &rep.BaseVersion, &rep.HeadVersion, &body, &rep.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rep.Report = &compat.Report{}
	if err := json.Unmarshal(body, rep.Report); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	return &rep, nil
}

func (s *PGStore) UpsertConsumer(ctx context.Context, decl ConsumerDecl) error {
	usages, err := json.Marshal(decl.Usages)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	pkgID, err := s.ensurePackage(ctx, tx, decl.Package)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO consumers (package_id, consumer, encoding, usages)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (package_id, consumer)
		DO UPDATE SET encoding = EXCLUDED.encoding, usages = EXCLUDED.usages, updated_at = now()`,
		pkgID, decl.Consumer, decl.Encoding, usages)
	if err != nil {
		return fmt.Errorf("upsert consumer: %w", err)
	}
	return tx.Commit()
}

func (s *PGStore) GetConsumer(ctx context.Context, pkg, consumer string) (*ConsumerDecl, error) {
	var d ConsumerDecl
	var usages []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT p.name, c.consumer, c.encoding, c.usages, c.updated_at
		FROM consumers c JOIN packages p ON p.id = c.package_id
		WHERE p.name = $1 AND c.consumer = $2`, pkg, consumer).
		Scan(&d.Package, &d.Consumer, &d.Encoding, &usages, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(usages, &d.Usages); err != nil {
		return nil, fmt.Errorf("decode usages: %w", err)
	}
	return &d, nil
}

// --- exemptions ---

const exemptionColumns = `
		e.id, p.name, e.fingerprint, e.finding, e.base_version, e.head_version,
		e.owner, e.reason, e.consumers, e.requested_by, e.approved_by, e.revoked_by,
		e.status, e.expires_at, COALESCE(e.request_id, ''), e.version, e.created_at, e.updated_at`

func scanExemption(row interface{ Scan(...any) error }) (*Exemption, error) {
	var ex Exemption
	var finding, consumers []byte
	err := row.Scan(
		&ex.ID, &ex.Package, &ex.Fingerprint, &finding, &ex.BaseVersion, &ex.HeadVersion,
		&ex.Owner, &ex.Reason, &consumers, &ex.RequestedBy, &ex.ApprovedBy, &ex.RevokedBy,
		&ex.Status, &ex.ExpiresAt, &ex.RequestID, &ex.Version, &ex.CreatedAt, &ex.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(finding, &ex.Finding); err != nil {
		return nil, fmt.Errorf("decode finding: %w", err)
	}
	if err := json.Unmarshal(consumers, &ex.Consumers); err != nil {
		return nil, fmt.Errorf("decode consumers: %w", err)
	}
	return &ex, nil
}

func (s *PGStore) CreateExemption(ctx context.Context, ex Exemption) (*Exemption, error) {
	finding, err := json.Marshal(ex.Finding)
	if err != nil {
		return nil, err
	}
	consumers, err := json.Marshal(ex.Consumers)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	pkgID, err := s.ensurePackage(ctx, tx, ex.Package)
	if err != nil {
		return nil, err
	}
	var requestID any
	if ex.RequestID != "" {
		requestID = ex.RequestID
	}
	row := tx.QueryRowContext(ctx, `
		INSERT INTO exemptions (id, package_id, fingerprint, finding, base_version, head_version,
			owner, reason, consumers, requested_by, status, expires_at, request_id, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1, $14, $14)
		ON CONFLICT (request_id) DO NOTHING
		RETURNING id`,
		ex.ID, pkgID, ex.Fingerprint, finding, ex.BaseVersion, ex.HeadVersion,
		ex.Owner, ex.Reason, consumers, ex.RequestedBy, ExemptionPending, ex.ExpiresAt, requestID, ex.CreatedAt)
	var insertedID string
	switch err := row.Scan(&insertedID); {
	case err == nil:
		// Inserted; fall through to the audit event.
	case errors.Is(err, sql.ErrNoRows) && ex.RequestID != "":
		// Idempotent retry: the request_id already exists. Return the
		// originally stored exemption without touching anything.
		existing, qerr := scanExemption(tx.QueryRowContext(ctx, `
			SELECT `+exemptionColumns+`
			FROM exemptions e JOIN packages p ON p.id = e.package_id
			WHERE e.request_id = $1`, ex.RequestID))
		if qerr != nil {
			return nil, fmt.Errorf("load existing exemption for request_id: %w", qerr)
		}
		return existing, tx.Commit()
	default:
		return nil, fmt.Errorf("insert exemption: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO exemption_events (exemption_id, event, actor, detail, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		ex.ID, ExemptionEventRequested, ex.RequestedBy, requestEventDetail(&ex), ex.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert request event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetExemption(ctx, ex.ID)
}

func (s *PGStore) GetExemption(ctx context.Context, id string) (*Exemption, error) {
	ex, err := scanExemption(s.db.QueryRowContext(ctx, `
		SELECT `+exemptionColumns+`
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE e.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return ex, err
}

func (s *PGStore) ListExemptions(ctx context.Context, pkg string) ([]Exemption, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+exemptionColumns+`
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE p.name = $1
		ORDER BY e.created_at, e.id`, pkg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exemption
	for rows.Next() {
		ex, err := scanExemption(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ex)
	}
	return out, rows.Err()
}

// transitionExemption runs one optimistic-concurrency state change inside
// a single transaction together with its audit event. The row is locked
// with FOR UPDATE, the business rules are evaluated against the locked
// state, and the guarded UPDATE double-checks the version so a stale
// expectedVersion can never win a race.
func (s *PGStore) transitionExemption(ctx context.Context, id string, expectedVersion int64, now time.Time,
	decide func(ex *Exemption) (newStatus, actor, detail string, err error)) (*Exemption, error) {

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	ex, err := scanExemption(tx.QueryRowContext(ctx, `
		SELECT `+exemptionColumns+`
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE e.id = $1
		FOR UPDATE OF e`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	newStatus, actor, detail, err := decide(ex)
	if err != nil {
		return nil, err
	}
	if newStatus == "" {
		return ex, tx.Commit() // idempotent no-op: current state returned
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE exemptions
		SET status = $2, approved_by = $3, revoked_by = $4, version = version + 1, updated_at = $5
		WHERE id = $1 AND version = $6`,
		id, newStatus, ex.ApprovedBy, ex.RevokedBy, now, expectedVersion)
	if err != nil {
		return nil, fmt.Errorf("update exemption: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrConcurrency
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO exemption_events (exemption_id, event, actor, detail, created_at)
		VALUES ($1, $2, $3, $4, $5)`, id, newStatus, actor, detail, now); err != nil {
		return nil, fmt.Errorf("insert %s event: %w", newStatus, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetExemption(ctx, id)
}

func (s *PGStore) ApproveExemption(ctx context.Context, id string, expectedVersion int64, approver string, now time.Time) (*Exemption, error) {
	return s.transitionExemption(ctx, id, expectedVersion, now, func(ex *Exemption) (string, string, string, error) {
		if ex.Status == ExemptionApproved && ex.ApprovedBy == approver {
			return "", "", "", nil // idempotent retry of an applied approval
		}
		if ex.Status != ExemptionPending {
			return "", "", "", ErrInvalidState
		}
		if ex.Version != expectedVersion {
			return "", "", "", ErrConcurrency
		}
		ex.ApprovedBy = approver
		ex.Status = ExemptionApproved
		ex.Version++
		return ExemptionApproved, approver, transitionEventDetail(ex), nil
	})
}

func (s *PGStore) RevokeExemption(ctx context.Context, id string, expectedVersion int64, revoker, reason string, now time.Time) (*Exemption, error) {
	return s.transitionExemption(ctx, id, expectedVersion, now, func(ex *Exemption) (string, string, string, error) {
		if ex.Status == ExemptionRevoked {
			return "", "", "", nil // idempotent retry
		}
		if ex.Version != expectedVersion {
			return "", "", "", ErrConcurrency
		}
		ex.RevokedBy = revoker
		ex.Status = ExemptionRevoked
		ex.Version++
		return ExemptionRevoked, revoker, transitionEventDetail(ex), nil
	})
}

func (s *PGStore) ListExemptionEvents(ctx context.Context, exemptionID string) ([]ExemptionEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, exemption_id, event, actor, detail, created_at
		FROM exemption_events
		WHERE exemption_id = $1
		ORDER BY id`, exemptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExemptionEvent
	for rows.Next() {
		var e ExemptionEvent
		if err := rows.Scan(&e.ID, &e.ExemptionID, &e.Event, &e.Actor, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
