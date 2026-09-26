package registry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"protocompat/internal/compat"
)

// actorHeader lets CLI/curl callers supply the acting identity without
// putting it in every body; body fields take precedence.
const actorHeader = "X-Actor"

func actorFrom(req connect.AnyRequest, bodyActor string) string {
	if bodyActor != "" {
		return bodyActor
	}
	return req.Header().Get(actorHeader)
}

// RequestExemption files a PENDING exemption for one deterministic finding
// in an already-produced report. The report itself is never modified: only
// its finding fingerprint is referenced.
func (s *Service) RequestExemption(ctx context.Context, req *connect.Request[RequestExemptionRequest]) (*connect.Response[ExemptionResponse], error) {
	r := req.Msg
	if r.Package == "" || r.BaseVersion == "" || r.HeadVersion == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("package, base_version and head_version are required"))
	}
	// Resolve the applicant identity (body field wins, header fallback)
	// before validating required fields.
	r.RequestedBy = actorFrom(req, r.RequestedBy)
	if r.Owner == "" || r.Reason == "" || r.RequestedBy == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("owner, reason and requested_by (or X-Actor header) are required"))
	}
	consumers := dedupe(r.Consumers)
	if len(consumers) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at least one consumer is required; exemptions never apply globally"))
	}
	expires, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("expires_at must be RFC3339: %w", err))
	}
	if !expires.After(s.now()) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("expires_at must be in the future"))
	}

	stored, err := s.store.GetReport(ctx, r.Package, r.BaseVersion, r.HeadVersion)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no stored report for %s %s..%s; run a registered-version check first", r.Package, r.BaseVersion, r.HeadVersion))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	finding, err := locateFinding(stored.Report, r.Fingerprint, r.FindingIndex, r.Package)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	ex, created, err := s.store.CreateExemption(ctx, Exemption{
		Package:          r.Package,
		BaseVersion:      r.BaseVersion,
		HeadVersion:      r.HeadVersion,
		Fingerprint:      compat.FindingFingerprint(r.Package, finding),
		OriginalSeverity: finding.Severity,
		Owner:            r.Owner,
		Reason:           r.Reason,
		Consumers:        consumers,
		RequestedBy:      r.RequestedBy,
		ExpiresAt:        expires.UTC(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ExemptionResponse{Exemption: toExemptionView(ex), AlreadyExisted: !created}), nil
}

// locateFinding resolves the finding a request targets: by fingerprint,
// or by 0-based index inside the stored report. A fingerprint that
// references no finding, or mismatches the index, is rejected.
func locateFinding(report *compat.Report, fingerprint string, index *int, pkg string) (compat.Finding, error) {
	if index != nil {
		if *index < 0 || *index >= len(report.Findings) {
			return compat.Finding{}, fmt.Errorf("finding_index %d out of range (report has %d findings)", *index, len(report.Findings))
		}
		f := report.Findings[*index]
		if fingerprint != "" && fingerprint != compat.FindingFingerprint(pkg, f) {
			return compat.Finding{}, fmt.Errorf("fingerprint does not match finding at index %d", *index)
		}
		return f, nil
	}
	if fingerprint == "" {
		return compat.Finding{}, errors.New("fingerprint or finding_index is required")
	}
	for _, f := range report.Findings {
		if compat.FindingFingerprint(pkg, f) == fingerprint {
			return f, nil
		}
	}
	return compat.Finding{}, fmt.Errorf("fingerprint %s not found in the stored report", fingerprint)
}

// ApproveExemption moves PENDING -> APPROVED. The approver must be a
// different identity from the requester (no self-approval). A repeated
// approval of an already-approved exemption is idempotent: it returns the
// current row without a second transition.
func (s *Service) ApproveExemption(ctx context.Context, req *connect.Request[ApproveExemptionRequest]) (*connect.Response[ExemptionResponse], error) {
	r := req.Msg
	actor := actorFrom(req, r.Actor)
	if actor == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("actor (or X-Actor header) is required"))
	}
	ex, err := s.store.GetExemption(ctx, r.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %d not found", r.ID))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	switch ex.Status {
	case ExemptionApproved:
		// A repeated approval request is idempotent for the same actor
		// (a network retry by the approver who already decided). A
		// different approver arriving second is a lost optimistic-concurrency
		// race: they must see the conflict, not a silent success.
		if ex.ApprovedBy == actor {
			return connect.NewResponse(&ExemptionResponse{Exemption: toExemptionView(ex)}), nil
		}
		return nil, connect.NewError(connect.CodeAborted,
			fmt.Errorf("exemption %d was approved by %q while actor %q was deciding; re-read the current version",
				r.ID, ex.ApprovedBy, actor))
	case ExemptionPending:
	default:
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("exemption %d is %s, only PENDING exemptions can be approved", r.ID, ex.Status))
	}
	if actor == ex.RequestedBy {
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("requester %q cannot approve their own exemption %d", actor, r.ID))
	}
	if !ex.ExpiresAt.After(s.now()) {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("exemption %d expires_at %s is already in the past", r.ID, ex.ExpiresAt.Format(time.RFC3339)))
	}

	now := s.now()
	updated, err := s.store.TransitionExemption(ctx, ex.ID, r.ExpectedVersion, ExemptionPending, ExemptionPatch{
		Status: ExemptionApproved, ApprovedBy: actor, DecidedAt: &now,
	}, AuditEvent{Action: "APPROVED", Actor: actor})
	return s.decisionResponse(r.ID, ex, updated, err)
}

// RejectExemption moves PENDING -> REJECTED; the requester may withdraw
// their own request this way, a different approver may refuse it too.
func (s *Service) RejectExemption(ctx context.Context, req *connect.Request[RejectExemptionRequest]) (*connect.Response[ExemptionResponse], error) {
	r := req.Msg
	actor := actorFrom(req, r.Actor)
	if actor == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("actor (or X-Actor header) is required"))
	}
	ex, err := s.store.GetExemption(ctx, r.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %d not found", r.ID))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if ex.Status == ExemptionRejected {
		return connect.NewResponse(&ExemptionResponse{Exemption: toExemptionView(ex)}), nil
	}
	if ex.Status != ExemptionPending {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("exemption %d is %s, only PENDING exemptions can be rejected", r.ID, ex.Status))
	}
	now := s.now()
	updated, err := s.store.TransitionExemption(ctx, ex.ID, r.ExpectedVersion, ExemptionPending, ExemptionPatch{
		Status: ExemptionRejected, RejectedBy: actor, DecidedAt: &now,
	}, AuditEvent{Action: "REJECTED", Actor: actor})
	return s.decisionResponse(r.ID, ex, updated, err)
}

// RevokeExemption withdraws an APPROVED exemption early; blocking resumes
// on the next query. Any identity other than an empty actor may revoke.
func (s *Service) RevokeExemption(ctx context.Context, req *connect.Request[RevokeExemptionRequest]) (*connect.Response[ExemptionResponse], error) {
	r := req.Msg
	actor := actorFrom(req, r.Actor)
	if actor == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("actor (or X-Actor header) is required"))
	}
	ex, err := s.store.GetExemption(ctx, r.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %d not found", r.ID))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if ex.Status == ExemptionRevoked {
		return connect.NewResponse(&ExemptionResponse{Exemption: toExemptionView(ex)}), nil
	}
	if ex.Status != ExemptionApproved {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("exemption %d is %s, only APPROVED exemptions can be revoked", r.ID, ex.Status))
	}
	now := s.now()
	updated, err := s.store.TransitionExemption(ctx, ex.ID, r.ExpectedVersion, ExemptionApproved, ExemptionPatch{
		Status: ExemptionRevoked, RevokedBy: actor, DecidedAt: &now,
	}, AuditEvent{Action: "REVOKED", Actor: actor, Detail: r.Reason})
	return s.decisionResponse(r.ID, ex, updated, err)
}

// decisionResponse maps optimistic-concurrency failures to ABORTED and
// keeps stale-state surprises as FailedPrecondition.
func (s *Service) decisionResponse(id int64, read, updated *Exemption, err error) (*connect.Response[ExemptionResponse], error) {
	switch {
	case err == nil:
		return connect.NewResponse(&ExemptionResponse{Exemption: toExemptionView(updated)}), nil
	case errors.Is(err, ErrConcurrentModification):
		return nil, connect.NewError(connect.CodeAborted,
			fmt.Errorf("exemption %d changed concurrently (supplied version is stale); re-read and retry: %v", id, err))
	case errors.Is(err, ErrInvalidStateTransition):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, ErrNotFound):
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %d not found", id))
	default:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
}

// GetExemptionRPC fetches one exemption.
func (s *Service) GetExemptionRPC(ctx context.Context, req *connect.Request[GetExemptionRequest]) (*connect.Response[ExemptionResponse], error) {
	ex, err := s.store.GetExemption(ctx, req.Msg.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %d not found", req.Msg.ID))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ExemptionResponse{Exemption: toExemptionView(ex)}), nil
}

// ListExemptionsRPC lists a package's exemptions.
func (s *Service) ListExemptionsRPC(ctx context.Context, req *connect.Request[ListExemptionsRequest]) (*connect.Response[ListExemptionsResponse], error) {
	if req.Msg.Package == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("package is required"))
	}
	list, err := s.store.ListExemptions(ctx, req.Msg.Package, req.Msg.Fingerprint)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &ListExemptionsResponse{Package: req.Msg.Package}
	for i := range list {
		resp.Exemptions = append(resp.Exemptions, toExemptionView(&list[i]))
	}
	return connect.NewResponse(resp), nil
}

// ListAuditEventsRPC returns the append-only audit trail.
func (s *Service) ListAuditEventsRPC(ctx context.Context, req *connect.Request[ListAuditEventsRequest]) (*connect.Response[ListAuditEventsResponse], error) {
	if req.Msg.Package == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("package is required"))
	}
	events, err := s.store.ListAuditEvents(ctx, req.Msg.Package, req.Msg.ExemptionID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &ListAuditEventsResponse{Package: req.Msg.Package}
	for _, ev := range events {
		resp.Events = append(resp.Events, AuditEventView{
			ID: ev.ID, ExemptionID: ev.ExemptionID, Action: ev.Action, Actor: ev.Actor,
			FromState: ev.FromState, ToState: ev.ToState, Version: ev.Version, Detail: ev.Detail,
			CreatedAt: ev.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return connect.NewResponse(resp), nil
}

// sweepExpired lazily transitions APPROVED exemptions whose window has
// elapsed to EXPIRED, writing audit events. Transition races are re-read,
// so the returned slice always reflects the current truth at time now.
func (s *Service) sweepExpired(ctx context.Context, list []Exemption, now time.Time) []Exemption {
	out := make([]Exemption, 0, len(list))
	for i := range list {
		e := list[i]
		if e.Status == ExemptionApproved && !e.ExpiresAt.After(now) {
			_, err := s.store.TransitionExemption(ctx, e.ID, e.Version, ExemptionApproved, ExemptionPatch{
				Status: ExemptionExpired, DecidedAt: &now,
			}, AuditEvent{Action: "EXPIRED", Actor: "system"})
			switch {
			case err == nil:
				e.Status = ExemptionExpired
				e.DecidedAt = now
				e.Version++
			case errors.Is(err, ErrConcurrentModification) || errors.Is(err, ErrInvalidStateTransition):
				fresh, gerr := s.store.GetExemption(ctx, e.ID)
				if gerr == nil {
					e = *fresh
				}
			}
		}
		out = append(out, e)
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
