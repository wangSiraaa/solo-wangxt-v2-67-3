package registry

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"protocompat/internal/compat"
)

// TestPGStore exercises the PostgreSQL store end to end. It is skipped
// unless DATABASE_URL points at a database (see docker-compose.yml).
func TestPGStore(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, SchemaSQL); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	// Isolate the test in its own package rows.
	pkg := "test.pgstore." + time.Now().Format("20060102150405.000000000")
	store := NewPGStore(db)

	v1 := Version{Package: pkg, Version: "v1", ContentHash: []byte("hash-v1"), DescriptorSet: []byte("set-v1"), OwnedPaths: []string{"a.proto"}}
	created, err := store.PutVersion(ctx, v1)
	if err != nil || !created {
		t.Fatalf("first put: created=%v err=%v", created, err)
	}
	// Identical retry is idempotent.
	created, err = store.PutVersion(ctx, v1)
	if err != nil || created {
		t.Fatalf("idempotent put: created=%v err=%v", created, err)
	}
	// Different content under the same version is rejected.
	created, err = store.PutVersion(ctx, Version{Package: pkg, Version: "v1", ContentHash: []byte("hash-other"), DescriptorSet: []byte("set-other"), OwnedPaths: []string{"a.proto"}})
	if err != ErrVersionConflict {
		t.Fatalf("conflicting put: created=%v err=%v, want ErrVersionConflict", created, err)
	}

	got, err := store.GetVersion(ctx, pkg, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ContentHash) != "hash-v1" || string(got.DescriptorSet) != "set-v1" {
		t.Fatalf("stored content changed: %+v", got)
	}
	if got.OwnedPaths[0] != "a.proto" {
		t.Fatalf("owned paths = %v", got.OwnedPaths)
	}

	if _, err := store.PutVersion(ctx, Version{Package: pkg, Version: "v2", ContentHash: []byte("hash-v2"), DescriptorSet: []byte("set-v2"), OwnedPaths: []string{"a.proto"}}); err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestVersion(ctx, pkg)
	if err != nil || latest.Version != "v2" {
		t.Fatalf("latest = %+v err=%v", latest, err)
	}
	list, err := store.ListVersions(ctx, pkg)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v err=%v", list, err)
	}

	if err := store.UpsertConsumer(ctx, ConsumerDecl{Package: pkg, Consumer: "svc", Encoding: "json", Usages: []Usage{{Message: "a.M", Fields: []string{"f"}}}}); err != nil {
		t.Fatal(err)
	}
	decl, err := store.GetConsumer(ctx, pkg, "svc")
	if err != nil {
		t.Fatal(err)
	}
	if decl.Encoding != "json" || len(decl.Usages) != 1 || decl.Usages[0].Fields[0] != "f" {
		t.Fatalf("decl = %+v", decl)
	}
}

// TestPGStoreExemptions exercises the exemption workflow against
// PostgreSQL: idempotent create, optimistic-concurrency transitions and
// the audit trail. Skipped unless DATABASE_URL is set.
func TestPGStoreExemptions(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, SchemaSQL); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	pkg := "test.pgexempt." + time.Now().Format("20060102150405.000000000")
	store := NewPGStore(db)
	now := time.Now().UTC().Truncate(time.Microsecond)

	exID := "ex_test_" + time.Now().Format("20060102150405.000000000")
	ex := Exemption{
		ID: exID, Package: pkg,
		Fingerprint: "fp-1", Finding: compat.Finding{Code: "FIELD_TYPE_CHANGED", Severity: compat.SeverityFail, Message: "a.M", Path: "f"},
		BaseVersion: "v1", HeadVersion: "v2", Owner: "team", Reason: "window",
		Consumers: []string{"ledger"}, RequestedBy: "alice", ExpiresAt: now.Add(time.Hour),
		RequestID: "req-" + exID, CreatedAt: now, UpdatedAt: now,
	}
	created, err := store.CreateExemption(ctx, ex)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Status != ExemptionPending || created.Version != 1 {
		t.Fatalf("created = %+v", created)
	}
	// Idempotent retry via request_id returns the same row.
	again, err := store.CreateExemption(ctx, ex)
	if err != nil || again.ID != created.ID {
		t.Fatalf("idempotent create: %+v err=%v", again, err)
	}

	// Stale version loses.
	if _, err := store.ApproveExemption(ctx, ex.ID, 99, "bob", now); err != ErrConcurrency {
		t.Fatalf("stale approve: err=%v, want ErrConcurrency", err)
	}
	approved, err := store.ApproveExemption(ctx, ex.ID, 1, "bob", now)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != ExemptionApproved || approved.Version != 2 || approved.ApprovedBy != "bob" {
		t.Fatalf("approved = %+v", approved)
	}
	// Same approver retrying is idempotent; a different approver is not.
	if _, err := store.ApproveExemption(ctx, ex.ID, 1, "bob", now); err != nil {
		t.Fatalf("idempotent approve retry: %v", err)
	}
	if _, err := store.ApproveExemption(ctx, ex.ID, 2, "carol", now); err != ErrInvalidState {
		t.Fatalf("second approver: err=%v, want ErrInvalidState", err)
	}

	// Revoke with the stale version fails; with the current one succeeds.
	if _, err := store.RevokeExemption(ctx, ex.ID, 1, "carol", "gone", now); err != ErrConcurrency {
		t.Fatalf("stale revoke: err=%v, want ErrConcurrency", err)
	}
	revoked, err := store.RevokeExemption(ctx, ex.ID, 2, "carol", "gone", now)
	if err != nil || revoked.Status != ExemptionRevoked {
		t.Fatalf("revoke: %+v err=%v", revoked, err)
	}

	// The audit trail recorded every transition in order.
	events, err := store.ListExemptionEvents(ctx, ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ExemptionEventRequested, ExemptionEventApproved, ExemptionEventRevoked}
	if len(events) != len(want) {
		t.Fatalf("events = %+v, want %v", events, want)
	}
	for i, e := range events {
		if e.Event != want[i] {
			t.Fatalf("event[%d] = %s, want %s", i, e.Event, want[i])
		}
	}
	if events[0].Actor != "alice" || events[1].Actor != "bob" || events[2].Actor != "carol" {
		t.Fatalf("event actors = %s/%s/%s", events[0].Actor, events[1].Actor, events[2].Actor)
	}

	// Listing round-trips the stored finding snapshot and consumers.
	listed, err := store.ListExemptions(ctx, pkg)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %+v err=%v", listed, err)
	}
	if listed[0].Finding.Code != "FIELD_TYPE_CHANGED" || listed[0].Consumers[0] != "ledger" {
		t.Fatalf("listed = %+v", listed[0])
	}
}
