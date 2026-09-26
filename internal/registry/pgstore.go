package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

// GetReport returns the most recently stored report for a
// (package, base, head) tuple.
func (s *PGStore) GetReport(ctx context.Context, pkg, base, head string) (*StoredReport, error) {
	var rep StoredReport
	var body []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT p.name, r.base_version, r.head_version, r.report, r.created_at
		FROM reports r JOIN packages p ON p.id = r.package_id
		WHERE p.name = $1 AND r.base_version = $2 AND r.head_version = $3
		ORDER BY r.id DESC
		LIMIT 1`, pkg, base, head).
		Scan(&rep.Package, &rep.BaseVersion, &rep.HeadVersion, &body, &rep.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &rep.Report); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	return &rep, nil
}

func scanExemption(row interface {
	Scan(dest ...any) error
}) (*Exemption, error) {
	var e Exemption
	var consumers []byte
	var approvedByS, rejectedByS, revokedByS sql.NullString
	var expiresAt, dAt sql.NullTime
	if err := row.Scan(
		&e.ID,
		&e.Package,
		&e.BaseVersion,
		&e.HeadVersion,
		&e.Fingerprint,
		&e.OriginalSeverity,
		&e.Owner,
		&e.Reason,
		&consumers,
		&e.RequestedBy,
		&e.Status,
		&approvedByS,
		&rejectedByS,
		&revokedByS,
		&expiresAt,
		&dAt,
		&e.Version,
		&e.CreatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(consumers, &e.Consumers); err != nil {
		return nil, fmt.Errorf("decode consumers: %w", err)
	}
	e.ApprovedBy = approvedByS.String
	e.RejectedBy = rejectedByS.String
	e.RevokedBy = revokedByS.String
	if expiresAt.Valid {
		e.ExpiresAt = expiresAt.Time
	}
	if dAt.Valid {
		e.DecidedAt = dAt.Time
	}
	return &e, nil
}

const exemptionColumns = `
	e.id, p.name, e.base_version, e.head_version, e.fingerprint, e.original_severity,
	e.owner, e.reason, e.consumers, e.requested_by, e.status,
	e.approved_by, e.rejected_by, e.revoked_by, e.expires_at, e.decided_at,
	e.version, e.created_at`

// CreateExemption inserts a PENDING exemption and its REQUESTED audit
// event. A repeat still-open request by the same requester for the same
// finding is idempotent: the existing row is returned with created=false.
func (s *PGStore) CreateExemption(ctx context.Context, in Exemption) (*Exemption, bool, error) {
	consumers, err := json.Marshal(in.Consumers)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	pkgID, err := s.ensurePackage(ctx, tx, in.Package)
	if err != nil {
		return nil, false, err
	}

	// Idempotent retry: an open exemption by the same requester already
	// exists. Return it without writing a second audit row.
	if existing, gerr := s.getExemptionForUpdate(ctx, tx, pkgID, in.Fingerprint, in.RequestedBy); gerr == nil {
		return existing, false, nil
	} else if !errors.Is(gerr, ErrNotFound) {
		return nil, false, gerr
	}

	var id int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO exemptions (
			package_id, base_version, head_version, fingerprint, original_severity,
			owner, reason, consumers, requested_by, status, expires_at, version
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'PENDING', $10, 1)
		RETURNING id`,
		pkgID, in.BaseVersion, in.HeadVersion, in.Fingerprint, string(in.OriginalSeverity),
		in.Owner, in.Reason, consumers, in.RequestedBy, in.ExpiresAt).Scan(&id)
	if err != nil {
		return nil, false, fmt.Errorf("insert exemption: %w", err)
	}
	if err := s.insertAudit(ctx, tx, AuditEvent{
		ExemptionID: id, Package: in.Package, Action: "REQUESTED",
		Actor: in.RequestedBy, FromState: "", ToState: ExemptionPending, Version: 1,
		Detail: fmt.Sprintf("owner=%s consumers=%v expires_at=%s", in.Owner, in.Consumers,
			in.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00")),
	}); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	ex, err := s.GetExemption(ctx, id)
	if err != nil {
		return nil, false, err
	}
	return ex, true, nil
}

// getExemptionForUpdate finds the requester's still-open exemption
// (PENDING/APPROVED) for one fingerprint, locking the row.
func (s *PGStore) getExemptionForUpdate(ctx context.Context, tx *sql.Tx, pkgID int64, fingerprint, requester string) (*Exemption, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT `+exemptionColumns+`
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE e.package_id = $1 AND e.fingerprint = $2 AND e.requested_by = $3
		  AND e.status IN ('PENDING', 'APPROVED')
		ORDER BY e.id DESC
		LIMIT 1
		FOR UPDATE`, pkgID, fingerprint, requester)
	ex, err := scanExemption(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return ex, nil
}

func (s *PGStore) GetExemption(ctx context.Context, id int64) (*Exemption, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+exemptionColumns+`
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE e.id = $1`, id)
	ex, err := scanExemption(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return ex, nil
}

func (s *PGStore) ListExemptions(ctx context.Context, pkg, fingerprint string) ([]Exemption, error) {
	q := `SELECT ` + exemptionColumns + `
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE p.name = $1`
	args := []any{pkg}
	if fingerprint != "" {
		q += ` AND e.fingerprint = $2`
		args = append(args, fingerprint)
	}
	q += ` ORDER BY e.id DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
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

func (s *PGStore) ActiveExemptionsForPackage(ctx context.Context, pkg string) ([]Exemption, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+exemptionColumns+`
		FROM exemptions e JOIN packages p ON p.id = e.package_id
		WHERE p.name = $1 AND e.status = 'APPROVED'
		ORDER BY e.id`, pkg)
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

// TransitionExemption is the single optimistic-concurrency primitive.
// The UPDATE matches only the row at (id, expectedVersion, expectFrom);
// zero rows affected means either a stale version or a changed state.
func (s *PGStore) TransitionExemption(ctx context.Context, id, expectedVersion int64, expectFrom ExemptionStatus, patch ExemptionPatch, event AuditEvent) (*Exemption, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var pkgName string
	var curVersion int64
	var curStatus ExemptionStatus
	err = tx.QueryRowContext(ctx, `
		SELECT p.name, e.version, e.status FROM exemptions e
		JOIN packages p ON p.id = e.package_id
		WHERE e.id = $1 FOR UPDATE`, id).Scan(&pkgName, &curVersion, &curStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// The optimistic token is the primary guard: a caller presenting a
	// version that no longer current has lost the race and must re-read,
	// regardless of the state the winner moved to.
	if curVersion != expectedVersion {
		return nil, fmt.Errorf("%w: version %d no longer current (now %d)", ErrConcurrentModification, expectedVersion, curVersion)
	}
	if curStatus != expectFrom {
		return nil, fmt.Errorf("%w: exemption %d is %s, expected %s", ErrInvalidStateTransition, id, curStatus, expectFrom)
	}

	var decided any
	if patch.DecidedAt != nil {
		decided = *patch.DecidedAt
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE exemptions SET
			status      = $2,
			approved_by = COALESCE($3, approved_by),
			rejected_by = COALESCE($4, rejected_by),
			revoked_by  = COALESCE($5, revoked_by),
			decided_at  = COALESCE($6, decided_at),
			version     = version + 1
		WHERE id = $1 AND version = $7 AND status = $8`,
		id, string(patch.Status), nullable(patch.ApprovedBy), nullable(patch.RejectedBy),
		nullable(patch.RevokedBy), decided, expectedVersion, string(expectFrom))
	if err != nil {
		return nil, fmt.Errorf("update exemption: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		// Lost the race between the lock check and the update.
		return nil, ErrConcurrentModification
	}

	event.ExemptionID = id
	event.Package = pkgName
	event.FromState = expectFrom
	event.ToState = patch.Status
	event.Version = expectedVersion + 1
	if err := s.insertAudit(ctx, tx, event); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetExemption(ctx, id)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *PGStore) insertAudit(ctx context.Context, tx *sql.Tx, ev AuditEvent) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO exemption_audit_events (
			exemption_id, package_id, action, actor, from_state, to_state, version, detail
		)
		SELECT $1, id, $2, $3, $4, $5, $6, $7 FROM packages WHERE name = $8`,
		ev.ExemptionID, ev.Action, ev.Actor, nullableState(ev.FromState), string(ev.ToState),
		ev.Version, ev.Detail, ev.Package)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func nullableState(s ExemptionStatus) any {
	if s == "" {
		return nil
	}
	return string(s)
}

func (s *PGStore) ListAuditEvents(ctx context.Context, pkg string, exemptionID int64) ([]AuditEvent, error) {
	q := `SELECT a.id, a.exemption_id, p.name, a.action, a.actor, a.from_state, a.to_state,
			a.version, a.detail, a.created_at
		FROM exemption_audit_events a JOIN packages p ON p.id = a.package_id
		WHERE p.name = $1`
	args := []any{pkg}
	if exemptionID != 0 {
		q += ` AND a.exemption_id = $2`
		args = append(args, exemptionID)
	}
	q += ` ORDER BY a.id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var fromState sql.NullString
		if err := rows.Scan(&ev.ID, &ev.ExemptionID, &ev.Package, &ev.Action, &ev.Actor,
			&fromState, &ev.ToState, &ev.Version, &ev.Detail, &ev.CreatedAt); err != nil {
			return nil, err
		}
		ev.FromState = ExemptionStatus(fromState.String)
		out = append(out, ev)
	}
	return out, rows.Err()
}
