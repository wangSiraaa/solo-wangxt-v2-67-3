package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"protocompat/internal/compat"
	"protocompat/internal/schema"
)

// Schemas for the exemption scenarios. v1 -> v2 changes total int32 ->
// int64 (a proven FAIL on both dimensions). v3 keeps the exact same
// finding but moves its source line. v4 reuses field #2 under a new name
// and kind, producing a different rule code (different fingerprint).
const (
	exV1 = `syntax = "proto3"; package acme.pay; message Invoice { string id = 1; int32 total = 2; string note = 3; }`
	exV2 = `syntax = "proto3"; package acme.pay; message Invoice { string id = 1; int64 total = 2; reserved 3; reserved "note"; }`
	// total moved down by three lines: same semantic fingerprint, different line.
	exV3 = `syntax = "proto3"; package acme.pay;

// extra lines shift the declaration without changing any semantics



message Invoice { string id = 1; int64 total = 2; reserved 3; reserved "note"; }`
	// #2 renamed total -> amount (FIELD_NUMBER_REUSED): same object path,
	// different rule code, hence a different fingerprint.
	exV4 = `syntax = "proto3"; package acme.pay; message Invoice { string id = 1; int64 amount = 2; reserved 3; reserved "note"; }`
)

type gateFixture struct {
	svc      *Service
	t        *testing.T
	pkg      string
	failFP   string
	failLine int
}

func setupGate(t *testing.T, pkg string, clock func() time.Time) *gateFixture {
	t.Helper()
	svc := NewService(NewMemStore())
	if clock != nil {
		svc.now = clock
	}
	ctx := context.Background()
	if _, err := svc.RegisterVersion(ctx, registerReq(pkg, "v1", exV1, false)); err != nil {
		t.Fatalf("register v1: %v", err)
	}
	resp, err := svc.RegisterVersion(ctx, registerReq(pkg, "v2", exV2, false))
	if err != nil {
		t.Fatalf("register v2: %v", err)
	}
	fx := &gateFixture{svc: svc, t: t, pkg: pkg}
	for _, f := range resp.Msg.Report.Findings {
		if f.Severity == compat.SeverityFail {
			fx.failFP = f.Fingerprint
			fx.failLine = f.Line
		}
	}
	if fx.failFP == "" {
		t.Fatalf("expected a FAIL finding with fingerprint in %+v", resp.Msg.Report)
	}
	return fx
}

func declare(t *testing.T, svc *Service, pkg, consumer, encoding string, fields ...string) {
	t.Helper()
	_, err := svc.DeclareConsumer(context.Background(), connect.NewRequest(&DeclareConsumerRequest{
		Package: pkg, Consumer: consumer, Encoding: encoding,
		Usages: []Usage{{Message: "acme.pay.Invoice", Fields: fields}},
	}))
	if err != nil {
		t.Fatalf("declare consumer %s: %v", consumer, err)
	}
}

func (fx *gateFixture) check(consumer, candidate string) *ConsumerDecisionView {
	resp, err := fx.svc.CheckCompatibility(context.Background(), connect.NewRequest(&CheckRequest{
		Package: fx.pkg, BaseVersion: "v1", CandidateVersion: candidate, Consumer: consumer,
	}))
	if err != nil {
		fx.t.Fatalf("check v1..%s for %s: %v", candidate, consumer, err)
	}
	return resp.Msg.ConsumerDecision
}

func requestExemption(t *testing.T, svc *Service, pkg, fp, requester string, consumers []string, expires time.Time) *Exemption {
	t.Helper()
	resp, err := svc.RequestExemption(context.Background(), connect.NewRequest(&RequestExemptionRequest{
		Package: pkg, BaseVersion: "v1", HeadVersion: "v2", Fingerprint: fp,
		Owner: "team-pay", Reason: "legacy quiescence window", Consumers: consumers,
		RequestedBy: requester, ExpiresAt: expires.UTC().Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatalf("request exemption: %v", err)
	}
	if resp.Msg.Exemption.Status != ExemptionPending || resp.Msg.Exemption.Version != 1 {
		t.Fatalf("new exemption = %+v, want PENDING version 1", resp.Msg.Exemption)
	}
	ex, _ := svc.store.GetExemption(context.Background(), resp.Msg.Exemption.ID)
	return ex
}

func approve(t *testing.T, svc *Service, id, version int64, actor string) (*connect.Response[ExemptionResponse], error) {
	t.Helper()
	return svc.ApproveExemption(context.Background(), connect.NewRequest(&ApproveExemptionRequest{
		ID: id, ExpectedVersion: version, Actor: actor,
	}))
}

// TestExemptionScopedToConsumer: an in-force exemption waives only the
// consumer it names; another consumer on the identical surface and the
// raw report stay blocked.
func TestExemptionScopedToConsumer(t *testing.T) {
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	cur := now
	fx := setupGate(t, "acme.scoped", func() time.Time { return cur })
	declare(t, fx.svc, fx.pkg, "alpha", "wire", "total")
	declare(t, fx.svc, fx.pkg, "beta", "wire", "total")

	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, now.Add(time.Hour))
	if resp, err := approve(t, fx.svc, ex.ID, 1, "bob"); err != nil {
		t.Fatalf("approve: %v", err)
	} else if resp.Msg.Exemption.Status != ExemptionApproved || resp.Msg.Exemption.Version != 2 {
		t.Fatalf("approved exemption = %+v", resp.Msg.Exemption)
	}

	alpha := fx.check("alpha", "v2")
	if alpha.RawVerdict != compat.VerdictIncompatible {
		t.Fatalf("raw verdict = %s, want INCOMPATIBLE regardless of waiver", alpha.RawVerdict)
	}
	if alpha.Verdict != PublishExempted || len(alpha.Exemptions) != 1 || alpha.Exemptions[0] != ex.ID {
		t.Fatalf("alpha decision = %+v, want EXEMPTED with exemption %d", alpha, ex.ID)
	}

	beta := fx.check("beta", "v2")
	if beta.Verdict != PublishIncompatible || len(beta.Exemptions) != 0 {
		t.Fatalf("beta decision = %+v, want INCOMPATIBLE with no waiver", beta)
	}

	// The stored report is untouched: no exemption annotations, raw verdict.
	stored, err := fx.svc.store.GetReport(context.Background(), fx.pkg, "v1", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Report.Verdict != compat.VerdictIncompatible {
		t.Fatalf("stored report verdict changed to %s", stored.Report.Verdict)
	}
	for _, f := range stored.Report.Findings {
		// compat.Finding carries no exemption field; mutating reports is
		// impossible by construction. Assert the FAIL severity survives.
		if f.Code == "FIELD_TYPE_CHANGED" && f.Severity != compat.SeverityFail {
			t.Fatalf("finding severity was altered: %+v", f)
		}
	}
}

// TestExemptionExpiryBoundary: strictly before expires_at the waiver is
// in force; at the exact boundary instant a query restores the block and
// records the EXPIRED transition in the audit trail.
func TestExemptionExpiryBoundary(t *testing.T) {
	boundary := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	cur := boundary.Add(-time.Minute)
	fx := setupGate(t, "acme.expiry", func() time.Time { return cur })
	declare(t, fx.svc, fx.pkg, "alpha", "wire", "total")
	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, boundary)
	if _, err := approve(t, fx.svc, ex.ID, 1, "bob"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	cur = boundary.Add(-time.Nanosecond)
	if d := fx.check("alpha", "v2"); d.Verdict != PublishExempted {
		t.Fatalf("one nanosecond before boundary: verdict = %s, want EXEMPTED", d.Verdict)
	}

	cur = boundary // exact boundary: half-open interval is closed
	d := fx.check("alpha", "v2")
	if d.Verdict != PublishIncompatible {
		t.Fatalf("at boundary: verdict = %s, want blocking restored", d.Verdict)
	}
	if len(d.Exemptions) != 0 {
		t.Fatalf("expired waiver must not be applied: %+v", d.Exemptions)
	}
	got, _ := fx.svc.store.GetExemption(context.Background(), ex.ID)
	if got.Status != ExemptionExpired {
		t.Fatalf("status = %s, want EXPIRED", got.Status)
	}
	events, _ := fx.svc.store.ListAuditEvents(context.Background(), fx.pkg, ex.ID)
	var sawExpiry bool
	for _, e := range events {
		if e.Action == "EXPIRED" && e.ToState == ExemptionExpired && e.Version == 3 {
			sawExpiry = true
		}
	}
	if !sawExpiry {
		t.Fatalf("no EXPIRED audit event at version 3: %+v", events)
	}

	// And it stays blocked afterwards.
	cur = boundary.Add(time.Hour)
	if d := fx.check("alpha", "v2"); d.Verdict != PublishIncompatible {
		t.Fatalf("after boundary: verdict = %s", d.Verdict)
	}
}

// TestExemptionSelfApprovalDenied: the requester cannot approve their
// own request; the error is permission denied, state and version remain
// exactly PENDING/1 and no APPROVED audit row is written.
func TestExemptionSelfApprovalDenied(t *testing.T) {
	cur := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	fx := setupGate(t, "acme.self", func() time.Time { return cur })
	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, cur.Add(time.Hour))

	for i := 0; i < 2; i++ {
		_, err := approve(t, fx.svc, ex.ID, 1, "alice")
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("self-approval attempt %d: code = %s (%v), want PermissionDenied", i+1, connect.CodeOf(err), err)
		}
	}
	got, _ := fx.svc.store.GetExemption(context.Background(), ex.ID)
	if got.Status != ExemptionPending || got.Version != 1 || got.ApprovedBy != "" {
		t.Fatalf("state changed after denied self-approval: %+v", got)
	}
	events, _ := fx.svc.store.ListAuditEvents(context.Background(), fx.pkg, ex.ID)
	for _, e := range events {
		if e.Action == "APPROVED" {
			t.Fatalf("an APPROVED audit event was written despite denial: %+v", e)
		}
	}
}

// TestExemptionOptimisticConcurrency: two approvers acting on the same
// stale version: exactly one transition wins, the other is aborted and
// must retry against the new version.
func TestExemptionOptimisticConcurrency(t *testing.T) {
	cur := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	fx := setupGate(t, "acme.occ", func() time.Time { return cur })
	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, cur.Add(time.Hour))

	// Store-level: two decisions both read version 1 and submit it.
	// Against PostgreSQL these are two row-locked transactions; the
	// in-memory store serializes the same critical section, so call them
	// sequentially to deterministically reproduce the loser's outcome.
	err0 := transitionApprove(fx.svc.store, ex.ID, 1, "bob", cur)
	err1 := transitionApprove(fx.svc.store, ex.ID, 1, "carol", cur)
	if err0 != nil {
		t.Fatalf("first approval failed: %v", err0)
	}
	if !errors.Is(err1, ErrConcurrentModification) {
		t.Fatalf("second approval on the same stale version: err = %v, want ErrConcurrentModification", err1)
	}
	got, _ := fx.svc.store.GetExemption(context.Background(), ex.ID)
	if got.Status != ExemptionApproved || got.Version != 2 {
		t.Fatalf("exemption after race = %+v, want APPROVED v2", got)
	}
	winner := got.ApprovedBy
	if winner != "bob" {
		t.Fatalf("approver = %q, want bob (the first transition to commit)", winner)
	}
	events, _ := fx.svc.store.ListAuditEvents(context.Background(), fx.pkg, ex.ID)
	approvals := 0
	for _, e := range events {
		if e.Action == "APPROVED" {
			approvals++
		}
	}
	if approvals != 1 {
		t.Fatalf("APPROVED audit events = %d, want exactly 1", approvals)
	}

	// Service-level: the losing approver re-read nothing and retries with
	// the stale version -> ABORTED, both via the optimistic token path and
	// via the post-decision conflict path.
	loser := map[string]bool{"bob": true, "carol": true}
	delete(loser, winner)
	var loserName string
	for k := range loser {
		loserName = k
	}
	staleResp, err := approve(t, fx.svc, ex.ID, 1, loserName)
	if connect.CodeOf(err) != connect.CodeAborted || staleResp != nil {
		t.Fatalf("loser stale approval: code = %s (%v), want Aborted", connect.CodeOf(err), err)
	}

	// Idempotency is defined for the same actor's retry: the winner
	// re-sending their decision gets the current row back, version 2, with
	// no second audit event.
	idem, err := approve(t, fx.svc, ex.ID, 2, winner)
	if err != nil {
		t.Fatalf("winner re-approval should be idempotent: %v", err)
	}
	if idem.Msg.Exemption.Status != ExemptionApproved || idem.Msg.Exemption.Version != 2 ||
		idem.Msg.Exemption.ApprovedBy != winner {
		t.Fatalf("idempotent approval altered state: %+v", idem.Msg.Exemption)
	}
	events, _ = fx.svc.store.ListAuditEvents(context.Background(), fx.pkg, ex.ID)
	approvals = 0
	for _, e := range events {
		if e.Action == "APPROVED" {
			approvals++
		}
	}
	if approvals != 1 {
		t.Fatalf("duplicate approval must be idempotent, found %d APPROVED events", approvals)
	}

	// A loser retry carrying a version number at all is rejected; so is
	// the loser approving with the current version after someone else
	// already decided.
	late, err := approve(t, fx.svc, ex.ID, 2, loserName)
	if connect.CodeOf(err) != connect.CodeAborted || late != nil {
		t.Fatalf("loser late approval: code = %s (%v), want Aborted", connect.CodeOf(err), err)
	}
}

func transitionApprove(store Store, id, version int64, actor string, now time.Time) error {
	_, err := store.TransitionExemption(context.Background(), id, version, ExemptionPending, ExemptionPatch{
		Status: ExemptionApproved, ApprovedBy: actor, DecidedAt: &now,
	}, AuditEvent{Action: "APPROVED", Actor: actor})
	return err
}

// TestExemptionFingerprintContinuity: a line-only change in a new report
// keeps the same fingerprint and the exemption carries over; a rule/object
// change produces a new fingerprint that blocks until a fresh exemption
// is requested and approved.
func TestExemptionFingerprintContinuity(t *testing.T) {
	cur := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	fx := setupGate(t, "acme.fp", func() time.Time { return cur })
	declare(t, fx.svc, fx.pkg, "alpha", "wire", "total")
	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, cur.Add(24*time.Hour))
	if _, err := approve(t, fx.svc, ex.ID, 1, "bob"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Register v3: line-shifted, same semantics.
	register3, err := fx.svc.RegisterVersion(context.Background(), registerReq(fx.pkg, "v3", exV3, false))
	if err != nil {
		t.Fatalf("register v3: %v", err)
	}
	_ = register3
	// The v1..v3 report (requested explicitly; default base for the v3
	// registration was v2) must carry the same fingerprint at another line.
	resp3, err := fx.svc.CheckCompatibility(context.Background(), connect.NewRequest(&CheckRequest{
		Package: fx.pkg, BaseVersion: "v1", CandidateVersion: "v3", Consumer: "alpha",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var shiftedLine int
	var found bool
	for _, f := range resp3.Msg.Annotated.Findings {
		if f.Fingerprint == fx.failFP {
			found = true
			shiftedLine = f.Line
		}
	}
	if !found {
		t.Fatalf("v1..v3 report no longer contains fingerprint %s; findings: %+v", fx.failFP, resp3.Msg.Annotated.Findings)
	}
	if shiftedLine == fx.failLine {
		t.Fatalf("expected a changed source line, both reports show line %d", shiftedLine)
	}
	if d := resp3.Msg.ConsumerDecision; d.Verdict != PublishExempted {
		t.Fatalf("line-shifted report: verdict = %s, want the existing exemption to carry over (raw=%s)",
			d.Verdict, d.RawVerdict)
	}

	// Register v4: field #2 renamed and re-typed -> different rule code.
	if _, err := fx.svc.RegisterVersion(context.Background(), registerReq(fx.pkg, "v4", exV4, false)); err != nil {
		t.Fatalf("register v4: %v", err)
	}
	resp4, err := fx.svc.CheckCompatibility(context.Background(), connect.NewRequest(&CheckRequest{
		Package: fx.pkg, BaseVersion: "v1", CandidateVersion: "v4", Consumer: "alpha",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var newFP string
	for _, f := range resp4.Msg.Annotated.Findings {
		if f.Severity == compat.SeverityFail {
			newFP = f.Fingerprint
		}
	}
	if newFP == "" || newFP == fx.failFP {
		t.Fatalf("v4 fingerprint = %q, want a non-empty fingerprint different from %q", newFP, fx.failFP)
	}
	if d := resp4.Msg.ConsumerDecision; d.Verdict != PublishIncompatible || len(d.Exemptions) != 0 {
		t.Fatalf("changed rule must require a new request: decision = %+v", d)
	}

	// A fresh exemption for the new fingerprint restores the waiver.
	r2, err := fx.svc.RequestExemption(context.Background(), connect.NewRequest(&RequestExemptionRequest{
		Package: fx.pkg, BaseVersion: "v1", HeadVersion: "v4", Fingerprint: newFP,
		Owner: "team-pay", Reason: "renamed field, same deprecation window", Consumers: []string{"alpha"},
		RequestedBy: "alice", ExpiresAt: cur.Add(24 * time.Hour).Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatalf("re-request: %v", err)
	}
	if _, err := approve(t, fx.svc, r2.Msg.Exemption.ID, 1, "bob"); err != nil {
		t.Fatalf("approve re-request: %v", err)
	}
	resp4b, err := fx.svc.CheckCompatibility(context.Background(), connect.NewRequest(&CheckRequest{
		Package: fx.pkg, BaseVersion: "v1", CandidateVersion: "v4", Consumer: "alpha",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if d := resp4b.Msg.ConsumerDecision; d.Verdict != PublishExempted {
		t.Fatalf("after re-request verdict = %s, want EXEMPTED", d.Verdict)
	}
}

// TestExemptionRevocationRestoresBlock: revoking an approved waiver
// re-blocks on the very next query.
func TestExemptionRevocationRestoresBlock(t *testing.T) {
	cur := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	fx := setupGate(t, "acme.revoke", func() time.Time { return cur })
	declare(t, fx.svc, fx.pkg, "alpha", "wire", "total")
	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, cur.Add(time.Hour))
	approved, err := approve(t, fx.svc, ex.ID, 1, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if d := fx.check("alpha", "v2"); d.Verdict != PublishExempted {
		t.Fatalf("pre-revoke: %s", d.Verdict)
	}
	if _, err := fx.svc.RevokeExemption(context.Background(), connect.NewRequest(&RevokeExemptionRequest{
		ID: ex.ID, ExpectedVersion: approved.Msg.Exemption.Version, Actor: "bob", Reason: "rollback",
	})); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if d := fx.check("alpha", "v2"); d.Verdict != PublishIncompatible {
		t.Fatalf("post-revoke: verdict = %s, want blocking restored", d.Verdict)
	}
}

// TestExemptionRequestIdempotency: duplicate open requests collapse to
// the same row; once decided terminally a new request is permitted again.
func TestExemptionRequestIdempotency(t *testing.T) {
	cur := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	fx := setupGate(t, "acme.idem", func() time.Time { return cur })
	first := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, cur.Add(time.Hour))
	r2, err := fx.svc.RequestExemption(context.Background(), connect.NewRequest(&RequestExemptionRequest{
		Package: fx.pkg, BaseVersion: "v1", HeadVersion: "v2", Fingerprint: fx.failFP,
		Owner: "team-pay", Reason: "different reason text on retry", Consumers: []string{"alpha"},
		RequestedBy: "alice", ExpiresAt: cur.Add(2 * time.Hour).Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Msg.AlreadyExisted != true || r2.Msg.Exemption.ID != first.ID {
		t.Fatalf("duplicate request not idempotent: %+v", r2.Msg)
	}
	events, _ := fx.svc.store.ListAuditEvents(context.Background(), fx.pkg, first.ID)
	if len(events) != 1 {
		t.Fatalf("duplicate request wrote audit events: %+v", events)
	}

	// Reject, then re-apply: a new row is allowed.
	if _, err := fx.svc.RejectExemption(context.Background(), connect.NewRequest(&RejectExemptionRequest{
		ID: first.ID, ExpectedVersion: 1, Actor: "bob",
	})); err != nil {
		t.Fatal(err)
	}
	r3, err := fx.svc.RequestExemption(context.Background(), connect.NewRequest(&RequestExemptionRequest{
		Package: fx.pkg, BaseVersion: "v1", HeadVersion: "v2", Fingerprint: fx.failFP,
		Owner: "team-pay", Reason: "addressed review", Consumers: []string{"alpha"},
		RequestedBy: "alice", ExpiresAt: cur.Add(2 * time.Hour).Format(time.RFC3339),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if r3.Msg.AlreadyExisted || r3.Msg.Exemption.ID == first.ID || r3.Msg.Exemption.Status != ExemptionPending {
		t.Fatalf("re-apply after rejection must open a new request: %+v", r3.Msg)
	}
}

// TestRequireCompatibleHonorsConsumerExemption: the publish gate refuses
// an incompatible version without a consumer waiver, and accepts it once
// the named consumer's finding has an approved exemption. We model this
// with v2 -> v3, where v3 reverses the type change (same rule/object
// fingerprint) — global registration stays blocked, the waived consumer
// passes.
func TestRequireCompatibleHonorsConsumerExemption(t *testing.T) {
	cur := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	fx := setupGate(t, "acme.gate", func() time.Time { return cur })
	declare(t, fx.svc, fx.pkg, "alpha", "wire", "total")
	declare(t, fx.svc, fx.pkg, "beta", "wire", "total")

	ex := requestExemption(t, fx.svc, fx.pkg, fx.failFP, "alice", []string{"alpha"}, cur.Add(time.Hour))
	if _, err := approve(t, fx.svc, ex.ID, 1, "bob"); err != nil {
		t.Fatal(err)
	}

	// v3 (int64 -> int32) fails against v2 with the same fingerprint.
	gatedReq := func(consumer string) *connect.Request[RegisterVersionRequest] {
		return connect.NewRequest(&RegisterVersionRequest{
			Package: fx.pkg, Version: "v3",
			Files:             []schema.SourceFile{{Path: "pay/invoice.proto", Content: exV3Alt}},
			Consumer:          consumer,
			RequireCompatible: true,
		})
	}
	if _, err := fx.svc.RegisterVersion(context.Background(), gatedReq("beta")); err == nil ||
		connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unwaived consumer gate: code = %s (%v), want FailedPrecondition", connect.CodeOf(err), err)
	}
	if _, err := fx.svc.RegisterVersion(context.Background(), gatedReq("alpha")); err != nil {
		t.Fatalf("waived consumer should pass the gate: %v", err)
	}
}

// exV3Alt reverses v2's change: total int64 -> int32, same code/object.
const exV3Alt = `syntax = "proto3"; package acme.pay; message Invoice { string id = 1; int32 total = 2; reserved 3; reserved "note"; string currency = 4; }`
