package registry

import (
	"context"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"protocompat/internal/compat"
	"protocompat/internal/schema"
)

// v2Shifted is v2Proto with comment lines prepended: the descriptors are
// identical, only source line numbers move.
const v2ShiftedProto = `// heading comment
// another comment line
syntax = "proto3"; package acme.pay; message Invoice { string id = 1; int64 total = 2; reserved 3; reserved "note"; }`

// v4Proto keeps the v2 break on total and adds a second, different break
// on id (string -> bytes changes the JSON form).
const v4Proto = `syntax = "proto3"; package acme.pay; message Invoice { bytes id = 1; int64 total = 2; reserved 3; reserved "note"; }`

// v5Proto drops total entirely without reserving it: same object as the
// v2 break, but a different rule fires.
const v5Proto = `syntax = "proto3"; package acme.pay; message Invoice { string id = 1; reserved 3; reserved "note"; }`

// fakeClock is a manually advanced clock for expiry boundary tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newExemptionService() (*Service, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)}
	svc := NewService(NewMemStore())
	svc.now = clock.now
	return svc, clock
}

// registerPair registers v1 and v2 and returns the FAIL finding of the
// stored v1 -> v2 report.
func registerPair(t *testing.T, svc *Service) compat.Finding {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.RegisterVersion(ctx, registerReq("acme.pay", "v1", v1Proto, false)); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.RegisterVersion(ctx, registerReq("acme.pay", "v2", v2Proto, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range resp.Msg.Compatibility.Findings {
		if f.Severity == compat.SeverityFail {
			return f
		}
	}
	t.Fatalf("no FAIL finding in v1 -> v2 report: %+v", resp.Msg.Compatibility.Findings)
	return compat.Finding{}
}

func requestExemption(t *testing.T, svc *Service, fp string, consumers []string, expires time.Time, by string) *Exemption {
	t.Helper()
	resp, err := svc.RequestExemption(context.Background(), connect.NewRequest(&RequestExemptionRequest{
		Package: "acme.pay", BaseVersion: "v1", HeadVersion: "v2",
		Fingerprint: fp, Owner: "owner-" + by, Reason: "migration window",
		Consumers: consumers, ExpiresAt: expires.UTC().Format(time.RFC3339), RequestedBy: by,
	}))
	if err != nil {
		t.Fatalf("request exemption: %v", err)
	}
	return resp.Msg.Exemption
}

func approve(t *testing.T, svc *Service, id string, version int64, approver string) *Exemption {
	t.Helper()
	resp, err := svc.ApproveExemption(context.Background(), connect.NewRequest(&ApproveExemptionRequest{
		ID: id, ExpectedVersion: version, Approver: approver,
	}))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return resp.Msg.Exemption
}

func checkRelease(t *testing.T, svc *Service, consumer string, candidateFiles ...schema.SourceFile) *ReleaseDecision {
	t.Helper()
	req := &CheckRequest{Package: "acme.pay", BaseVersion: "v1", Consumer: consumer}
	if len(candidateFiles) > 0 {
		req.CandidateFiles = candidateFiles
	} else {
		req.CandidateVersion = "v2"
	}
	resp, err := svc.CheckCompatibility(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if resp.Msg.Release == nil {
		t.Fatal("release decision missing from check response")
	}
	return resp.Msg.Release
}

func candidate(content string) []schema.SourceFile {
	return []schema.SourceFile{{Path: "pay/invoice.proto", Content: content}}
}

func declareJSONConsumer(t *testing.T, svc *Service, name string) {
	t.Helper()
	if _, err := svc.DeclareConsumer(context.Background(), connect.NewRequest(&DeclareConsumerRequest{
		Package: "acme.pay", Consumer: name, Encoding: "json",
		Usages: []Usage{{Message: "acme.pay.Invoice"}},
	})); err != nil {
		t.Fatal(err)
	}
}

// A valid exemption lifts the block only for the consumers named in it.
func TestExemptionAppliesOnlyToListedConsumer(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)
	declareJSONConsumer(t, svc, "ledger")
	declareJSONConsumer(t, svc, "dashboard")

	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	approve(t, svc, ex.ID, ex.Version, "bob")

	// The exempted consumer is released; the raw verdict is untouched.
	rel := checkRelease(t, svc, "ledger")
	if rel.RawVerdict != compat.VerdictIncompatible {
		t.Fatalf("ledger raw verdict = %s, want INCOMPATIBLE", rel.RawVerdict)
	}
	if rel.EffectiveVerdict != compat.VerdictCompatible {
		t.Fatalf("ledger effective verdict = %s, want COMPATIBLE", rel.EffectiveVerdict)
	}
	var sawExempted bool
	for _, fd := range rel.Findings {
		if fd.Fingerprint == finding.Fingerprint() {
			sawExempted = true
			if !fd.Exempted || fd.ExemptionID != ex.ID {
				t.Fatalf("finding decision = %+v, want exempted by %s", fd, ex.ID)
			}
			if fd.Severity != compat.SeverityFail {
				t.Fatalf("original severity rewritten: %+v", fd)
			}
		}
	}
	if !sawExempted {
		t.Fatal("exempted finding missing from release decision")
	}

	// Another consumer of the same surface is still blocked.
	if rel := checkRelease(t, svc, "dashboard"); rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("dashboard effective verdict = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}
	// And so is the unscoped publish decision.
	if rel := checkRelease(t, svc, ""); rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("unscoped effective verdict = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}
}

// The moment the expiry boundary is reached, queries block again — with
// no background job and without touching the stored exemption.
func TestExemptionExpiryRestoresBlocking(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)
	declareJSONConsumer(t, svc, "ledger")

	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	approve(t, svc, ex.ID, ex.Version, "bob")

	clock.t = clock.t.Add(30 * time.Minute) // before expiry: released
	if rel := checkRelease(t, svc, "ledger"); rel.EffectiveVerdict != compat.VerdictCompatible {
		t.Fatalf("before expiry: effective = %s, want COMPATIBLE", rel.EffectiveVerdict)
	}

	clock.t = clock.t.Add(30 * time.Minute) // exactly at the boundary: expired
	rel := checkRelease(t, svc, "ledger")
	if rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("at expiry boundary: effective = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}

	// The stored row is not rewritten; the effective status is derived.
	listed, err := svc.ListExemptions(context.Background(), connect.NewRequest(&ListExemptionsRequest{
		Package: "acme.pay", IncludeInactive: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Msg.Exemptions) != 1 || listed.Msg.Exemptions[0].Status != ExemptionExpired {
		t.Fatalf("exemptions = %+v, want one EXPIRED", listed.Msg.Exemptions)
	}
	stored, err := svc.store.GetExemption(context.Background(), ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ExemptionApproved {
		t.Fatalf("stored status = %s, want APPROVED (expiry is derived, not written)", stored.Status)
	}
}

// The requester can never approve their own exemption; the attempt is
// rejected and the state is untouched.
func TestSelfApprovalRejected(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)

	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	_, err := svc.ApproveExemption(context.Background(), connect.NewRequest(&ApproveExemptionRequest{
		ID: ex.ID, ExpectedVersion: ex.Version, Approver: "alice",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("self-approval: code = %s (%v), want PermissionDenied", connect.CodeOf(err), err)
	}
	stored, err := svc.store.GetExemption(context.Background(), ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ExemptionPending || stored.Version != ex.Version || stored.ApprovedBy != "" {
		t.Fatalf("state changed after rejected self-approval: %+v", stored)
	}
	events, err := svc.store.ListExemptionEvents(context.Background(), ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Event != ExemptionEventRequested {
		t.Fatalf("events = %+v, want only REQUESTED", events)
	}
}

// Two approvers working from the same stale version cannot both succeed;
// the winner's retry is idempotent.
func TestConcurrentApprovalOnlyOneSucceeds(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)
	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")

	var wg sync.WaitGroup
	results := make([]error, 2)
	approvers := []string{"bob", "carol"}
	for i, who := range approvers {
		wg.Add(1)
		go func(i int, who string) {
			defer wg.Done()
			_, err := svc.ApproveExemption(context.Background(), connect.NewRequest(&ApproveExemptionRequest{
				ID: ex.ID, ExpectedVersion: ex.Version, Approver: who,
			}))
			results[i] = err
		}(i, who)
	}
	wg.Wait()

	succeeded := 0
	for i, err := range results {
		if err == nil {
			succeeded++
		} else if code := connect.CodeOf(err); code != connect.CodeAborted && code != connect.CodeFailedPrecondition {
			t.Fatalf("approver %s: unexpected error code %s (%v)", approvers[i], code, err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d approvals succeeded, want exactly 1", succeeded)
	}

	stored, err := svc.store.GetExemption(context.Background(), ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ExemptionApproved || stored.Version != ex.Version+1 {
		t.Fatalf("stored = %+v, want APPROVED at version %d", stored, ex.Version+1)
	}

	// The winner retrying the same approval — even with the stale
	// version — is an idempotent success and records no extra event.
	winner := stored.ApprovedBy
	resp, err := svc.ApproveExemption(context.Background(), connect.NewRequest(&ApproveExemptionRequest{
		ID: ex.ID, ExpectedVersion: ex.Version, Approver: winner,
	}))
	if err != nil {
		t.Fatalf("idempotent approval retry: %v", err)
	}
	if resp.Msg.Exemption.Version != stored.Version {
		t.Fatalf("retry bumped version to %d", resp.Msg.Exemption.Version)
	}
	events, err := svc.store.ListExemptionEvents(context.Background(), ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Event != ExemptionEventRequested || events[1].Event != ExemptionEventApproved {
		t.Fatalf("events = %+v, want REQUESTED + APPROVED", events)
	}
}

// A repeated request with the same request_id returns the original
// exemption instead of creating a duplicate.
func TestIdempotentRequest(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)

	req := &RequestExemptionRequest{
		Package: "acme.pay", BaseVersion: "v1", HeadVersion: "v2",
		Fingerprint: finding.Fingerprint(), Owner: "owner", Reason: "migration window",
		Consumers: []string{"ledger"}, ExpiresAt: clock.t.Add(time.Hour).Format(time.RFC3339),
		RequestedBy: "alice", RequestID: "req-123",
	}
	first, err := svc.RequestExemption(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.RequestExemption(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	if first.Msg.Exemption.ID != second.Msg.Exemption.ID {
		t.Fatalf("idempotent retry created %s, want %s", second.Msg.Exemption.ID, first.Msg.Exemption.ID)
	}
	listed, err := svc.store.ListExemptions(context.Background(), "acme.pay")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("%d exemptions stored, want 1", len(listed))
	}
}

// Revocation restores blocking immediately; revoking twice is idempotent.
func TestRevokeRestoresBlocking(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)
	declareJSONConsumer(t, svc, "ledger")

	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	approved := approve(t, svc, ex.ID, ex.Version, "bob")
	if rel := checkRelease(t, svc, "ledger"); rel.EffectiveVerdict != compat.VerdictCompatible {
		t.Fatalf("approved: effective = %s, want COMPATIBLE", rel.EffectiveVerdict)
	}

	revoked, err := svc.RevokeExemption(context.Background(), connect.NewRequest(&RevokeExemptionRequest{
		ID: ex.ID, ExpectedVersion: approved.Version, Revoker: "carol", Reason: "no longer acceptable",
	}))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Msg.Exemption.Status != ExemptionRevoked {
		t.Fatalf("status = %s, want REVOKED", revoked.Msg.Exemption.Status)
	}
	if rel := checkRelease(t, svc, "ledger"); rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("after revoke: effective = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}

	// Idempotent retry of the revoke.
	if _, err := svc.RevokeExemption(context.Background(), connect.NewRequest(&RevokeExemptionRequest{
		ID: ex.ID, ExpectedVersion: approved.Version, Revoker: "carol",
	})); err != nil {
		t.Fatalf("idempotent revoke retry: %v", err)
	}
	events, err := svc.store.ListExemptionEvents(context.Background(), ex.ID)
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
}

// A PENDING exemption has no effect on any decision.
func TestPendingExemptionHasNoEffect(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)
	declareJSONConsumer(t, svc, "ledger")
	requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	if rel := checkRelease(t, svc, "ledger"); rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("pending exemption: effective = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}
}

// Line-number shifts keep the semantic fingerprint, so an approved
// exemption carries over to new reports; a changed rule or object
// produces a new fingerprint and blocks again until re-requested.
func TestFingerprintCarryOverAndChange(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)

	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"*"}, clock.t.Add(time.Hour), "alice")
	approve(t, svc, ex.ID, ex.Version, "bob")

	// Same descriptors, shifted line numbers: the exemption follows.
	rel := checkRelease(t, svc, "", candidate(v2ShiftedProto)...)
	if rel.RawVerdict != compat.VerdictIncompatible {
		t.Fatalf("shifted: raw = %s, want INCOMPATIBLE", rel.RawVerdict)
	}
	if rel.EffectiveVerdict != compat.VerdictCompatible {
		t.Fatalf("shifted: effective = %s, want COMPATIBLE (fingerprint must carry over)", rel.EffectiveVerdict)
	}

	// A new break on a different object: new fingerprint, blocked again.
	rel = checkRelease(t, svc, "", candidate(v4Proto)...)
	if rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("object changed: effective = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}
	var exemptedCount int
	for _, fd := range rel.Findings {
		if fd.Exempted {
			exemptedCount++
		}
	}
	if exemptedCount != 1 {
		t.Fatalf("object changed: %d exempted findings, want exactly 1 (only the original)", exemptedCount)
	}

	// Same object, different rule (unreserved deletion instead of a type
	// change): also a new fingerprint.
	rel = checkRelease(t, svc, "", candidate(v5Proto)...)
	if rel.EffectiveVerdict != compat.VerdictIncompatible {
		t.Fatalf("rule changed: effective = %s, want INCOMPATIBLE", rel.EffectiveVerdict)
	}
	for _, fd := range rel.Findings {
		if fd.Exempted {
			t.Fatalf("rule changed: finding %+v must not inherit the exemption", fd)
		}
	}
}

// The publish gate (require_compatible) yields only to wildcard
// exemptions; consumer-scoped ones never lift the global gate.
func TestPublishGateHonorsOnlyWildcardExemptions(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)

	// Consumer-scoped exemption: the gate still refuses.
	ex := requestExemption(t, svc, finding.Fingerprint(), []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	approve(t, svc, ex.ID, ex.Version, "bob")
	v3 := `syntax = "proto3"; package acme.pay; message Invoice { string id = 1; int64 total = 2; reserved 3; reserved "note"; string currency = 4; }`
	gateReq := connect.NewRequest(&RegisterVersionRequest{
		Package: "acme.pay", Version: "v3", BaseVersion: "v1",
		Files: candidate(v3), RequireCompatible: true,
	})
	if _, err := svc.RegisterVersion(context.Background(), gateReq); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("consumer-scoped exemption: gate code = %s (%v), want FailedPrecondition", connect.CodeOf(err), err)
	}

	// Wildcard exemption: the gate accepts, and the response carries both
	// the raw report and the release decision.
	ex2 := requestExemption(t, svc, finding.Fingerprint(), []string{"*"}, clock.t.Add(time.Hour), "alice")
	approve(t, svc, ex2.ID, ex2.Version, "bob")
	resp, err := svc.RegisterVersion(context.Background(), gateReq)
	if err != nil {
		t.Fatalf("wildcard exemption: gate refused: %v", err)
	}
	if resp.Msg.Compatibility.Verdict != compat.VerdictIncompatible {
		t.Fatalf("raw verdict = %s, want INCOMPATIBLE (report is never rewritten)", resp.Msg.Compatibility.Verdict)
	}
	if resp.Msg.Release == nil || resp.Msg.Release.EffectiveVerdict != compat.VerdictCompatible {
		t.Fatalf("release = %+v, want effective COMPATIBLE", resp.Msg.Release)
	}
}

// Request validation: stored report and finding must exist, expiry must
// be in the future, and an expired pending exemption cannot be approved.
func TestRequestExemptionValidation(t *testing.T) {
	svc, clock := newExemptionService()
	finding := registerPair(t, svc)
	fp := finding.Fingerprint()

	base := RequestExemptionRequest{
		Package: "acme.pay", BaseVersion: "v1", HeadVersion: "v2",
		Fingerprint: fp, Owner: "owner", Reason: "reason",
		Consumers: []string{"ledger"}, ExpiresAt: clock.t.Add(time.Hour).Format(time.RFC3339), RequestedBy: "alice",
	}
	cases := []struct {
		name   string
		mutate func(r *RequestExemptionRequest)
		code   connect.Code
	}{
		{"unknown report", func(r *RequestExemptionRequest) { r.HeadVersion = "v9" }, connect.CodeNotFound},
		{"unknown fingerprint", func(r *RequestExemptionRequest) { r.Fingerprint = "deadbeef" }, connect.CodeNotFound},
		{"past expiry", func(r *RequestExemptionRequest) { r.ExpiresAt = clock.t.Add(-time.Hour).Format(time.RFC3339) }, connect.CodeInvalidArgument},
		{"no consumers", func(r *RequestExemptionRequest) { r.Consumers = nil }, connect.CodeInvalidArgument},
		{"no reason", func(r *RequestExemptionRequest) { r.Reason = "" }, connect.CodeInvalidArgument},
		{"no requester", func(r *RequestExemptionRequest) { r.RequestedBy = "" }, connect.CodeInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.mutate(&r)
			_, err := svc.RequestExemption(context.Background(), connect.NewRequest(&r))
			if connect.CodeOf(err) != tc.code {
				t.Fatalf("code = %s (%v), want %s", connect.CodeOf(err), err, tc.code)
			}
		})
	}

	// An exemption that expired while still pending cannot be approved.
	ex := requestExemption(t, svc, fp, []string{"ledger"}, clock.t.Add(time.Hour), "alice")
	clock.t = clock.t.Add(2 * time.Hour)
	_, err := svc.ApproveExemption(context.Background(), connect.NewRequest(&ApproveExemptionRequest{
		ID: ex.ID, ExpectedVersion: ex.Version, Approver: "bob",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("approve expired: code = %s (%v), want FailedPrecondition", connect.CodeOf(err), err)
	}
}
