package registry

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
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

// TestPGStoreExemptions exercises exemption persistence, the
// optimistic-concurrency transition under real concurrent transactions,
// and the append-only audit trail. Skipped without DATABASE_URL.
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

	expires := time.Now().Add(time.Hour).UTC()
	first, created, err := store.CreateExemption(ctx, Exemption{
		Package: pkg, BaseVersion: "v1", HeadVersion: "v2",
		Fingerprint: "fp-1", OriginalSeverity: "FAIL",
		Owner: "owen", Reason: "quiescence", Consumers: []string{"alpha"},
		RequestedBy: "alice", ExpiresAt: expires,
	})
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	if first.Status != ExemptionPending || first.Version != 1 {
		t.Fatalf("new exemption = %+v", first)
	}

	// Idempotent repeat of the open request.
	again, created, err := store.CreateExemption(ctx, Exemption{
		Package: pkg, BaseVersion: "v1", HeadVersion: "v2",
		Fingerprint: "fp-1", OriginalSeverity: "FAIL",
		Owner: "owen", Reason: "changed", Consumers: []string{"alpha"},
		RequestedBy: "alice", ExpiresAt: expires.Add(time.Hour),
	})
	if err != nil || created || again.ID != first.ID {
		t.Fatalf("idempotent reopen: id=%d created=%v err=%v", again.ID, created, err)
	}

	// Two transactions both read version 1 then decide: only one commits.
	start := make(chan struct{})
	var wg sync.WaitGroup
	commitErrs := make([]error, 2)
	for i := range commitErrs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			actor := "bob"
			if i == 1 {
				actor = "carol"
			}
			_, commitErrs[i] = store.TransitionExemption(ctx, first.ID, 1, ExemptionPending, ExemptionPatch{
				Status: ExemptionApproved, ApprovedBy: actor, DecidedAt: &expires,
			}, AuditEvent{Action: "APPROVED", Actor: actor})
		}(i)
	}
	close(start)
	wg.Wait()
	wins, losses := 0, 0
	for _, e := range commitErrs {
		switch {
		case e == nil:
			wins++
		case errors.Is(e, ErrConcurrentModification):
			losses++
		default:
			t.Fatalf("unexpected concurrent transition error: %v", e)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("concurrent approval: %d wins %d losses, want 1/1 (%v)", wins, losses, commitErrs)
	}

	got, err := store.GetExemption(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ExemptionApproved || got.Version != 2 {
		t.Fatalf("approved row = %+v", got)
	}
	if got.ApprovedBy != "bob" && got.ApprovedBy != "carol" {
		t.Fatalf("unexpected approver %q", got.ApprovedBy)
	}
	// The loser re-reads and revokes with the fresh version.
	now := time.Now()
	revoked, err := store.TransitionExemption(ctx, got.ID, 2, ExemptionApproved, ExemptionPatch{
		Status: ExemptionRevoked, RevokedBy: "dave", DecidedAt: &now,
	}, AuditEvent{Action: "REVOKED", Actor: "dave", Detail: "rollback"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != ExemptionRevoked || revoked.Version != 3 || revoked.RevokedBy != "dave" {
		t.Fatalf("revoked row = %+v", revoked)
	}
	// A stale revoke is rejected.
	if _, err := store.TransitionExemption(ctx, got.ID, 2, ExemptionApproved, ExemptionPatch{
		Status: ExemptionRevoked, DecidedAt: &now,
	}, AuditEvent{Action: "REVOKED", Actor: "dave"}); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("stale revoke: err=%v, want ErrConcurrentModification", err)
	}

	events, err := store.ListAuditEvents(ctx, pkg, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantSeq := []struct {
		action  string
		version int64
		to      ExemptionStatus
	}{
		{"REQUESTED", 1, ExemptionPending},
		{"APPROVED", 2, ExemptionApproved},
		{"REVOKED", 3, ExemptionRevoked},
	}
	if len(events) != len(wantSeq) {
		t.Fatalf("audit events = %d, want %d: %+v", len(events), len(wantSeq), events)
	}
	for i, w := range wantSeq {
		if events[i].Action != w.action || events[i].Version != w.version || events[i].ToState != w.to {
			t.Fatalf("audit[%d] = %+v, want %+v", i, events[i], w)
		}
	}

	// After revocation a fresh request is allowed (the open-row unique
	// index only covers PENDING/APPROVED).
	reborn, created, err := store.CreateExemption(ctx, Exemption{
		Package: pkg, BaseVersion: "v1", HeadVersion: "v2",
		Fingerprint: "fp-1", OriginalSeverity: "FAIL",
		Owner: "owen", Reason: "second window", Consumers: []string{"alpha"},
		RequestedBy: "alice", ExpiresAt: expires.Add(2 * time.Hour),
	})
	if err != nil || !created || reborn.ID == first.ID {
		t.Fatalf("re-apply after revocation: created=%v id=%d err=%v", created, reborn.ID, err)
	}
}
