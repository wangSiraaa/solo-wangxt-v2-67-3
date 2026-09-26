package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"protocompat/internal/compat"
)

// --- API request/response types for the exemption endpoints ---

type RequestExemptionRequest struct {
	Package     string   `json:"package"`
	BaseVersion string   `json:"base_version"`
	HeadVersion string   `json:"head_version"`
	Fingerprint string   `json:"fingerprint"` // Finding.Fingerprint of a finding in the report
	Owner       string   `json:"owner"`
	Reason      string   `json:"reason"`
	Consumers   []string `json:"consumers"`  // affected consumers; "*" = all
	ExpiresAt   string   `json:"expires_at"` // RFC3339
	RequestedBy string   `json:"requested_by"`
	// RequestID is an optional idempotency key: a retry with the same key
	// returns the originally created exemption instead of a duplicate.
	RequestID string `json:"request_id,omitempty"`
}

type RequestExemptionResponse struct {
	Exemption *Exemption `json:"exemption"`
}

type ApproveExemptionRequest struct {
	ID string `json:"id"`
	// ExpectedVersion is the exemption version the approver reviewed;
	// the transition fails with Aborted when the row moved on.
	ExpectedVersion int64  `json:"expected_version"`
	Approver        string `json:"approver"`
}

type ApproveExemptionResponse struct {
	Exemption *Exemption `json:"exemption"`
}

type RevokeExemptionRequest struct {
	ID              string `json:"id"`
	ExpectedVersion int64  `json:"expected_version"`
	Revoker         string `json:"revoker"`
	Reason          string `json:"reason,omitempty"`
}

type RevokeExemptionResponse struct {
	Exemption *Exemption `json:"exemption"`
}

type ListExemptionsRequest struct {
	Package string `json:"package"`
	// IncludeInactive also returns revoked, expired and still-pending
	// exemptions; the default lists only currently effective ones.
	IncludeInactive bool `json:"include_inactive,omitempty"`
}

type ListExemptionsResponse struct {
	Exemptions []*Exemption `json:"exemptions"`
}

// ReleaseDecision is the exemption-aware publish judgement for one check.
// The raw report is never rewritten; this sits next to it and states what
// the findings mean for a release after applying active exemptions.
type ReleaseDecision struct {
	// Consumer is the evaluation context ("" = unscoped check, where only
	// wildcard "*" exemptions apply).
	Consumer         string            `json:"consumer,omitempty"`
	RawVerdict       compat.Verdict    `json:"raw_verdict"`
	EffectiveVerdict compat.Verdict    `json:"effective_verdict"`
	Findings         []FindingDecision `json:"findings,omitempty"`
}

// FindingDecision pairs a finding's original severity with the exemption
// outcome for this evaluation.
type FindingDecision struct {
	Fingerprint string          `json:"fingerprint"`
	Code        string          `json:"code"`
	Severity    compat.Severity `json:"severity"` // original severity, never rewritten
	Exempted    bool            `json:"exempted"`
	ExemptionID string          `json:"exemption_id,omitempty"`
}

// --- RPC handlers ---

// RequestExemption files a PENDING exemption for one finding of a stored
// report. It has no effect on any verdict until a different identity
// approves it.
func (s *Service) RequestExemption(ctx context.Context, req *connect.Request[RequestExemptionRequest]) (*connect.Response[RequestExemptionResponse], error) {
	r := req.Msg
	if r.Package == "" || r.BaseVersion == "" || r.HeadVersion == "" || r.Fingerprint == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("package, base_version, head_version and fingerprint are required"))
	}
	if r.Owner == "" || r.Reason == "" || r.RequestedBy == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("owner, reason and requested_by are required"))
	}
	if len(r.Consumers) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("consumers must name at least one consumer (or \"*\" for all)"))
	}
	for _, c := range r.Consumers {
		if c == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("consumers must not contain empty entries"))
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("expires_at must be RFC3339: %v", err))
	}
	now := s.now()
	if !expiresAt.After(now) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("expires_at must be in the future"))
	}

	// The exemption is anchored to a finding of a stored report; the
	// report itself is a historical artifact and is never modified.
	rep, err := s.store.GetReport(ctx, r.Package, r.BaseVersion, r.HeadVersion)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no stored report for %s %s -> %s; run CheckCompatibility with registered versions first", r.Package, r.BaseVersion, r.HeadVersion))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	var finding *compat.Finding
	for i := range rep.Report.Findings {
		if rep.Report.Findings[i].Fingerprint() == r.Fingerprint {
			finding = &rep.Report.Findings[i]
			break
		}
	}
	if finding == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no finding with fingerprint %s in report %s %s -> %s", r.Fingerprint, r.Package, r.BaseVersion, r.HeadVersion))
	}

	ex := Exemption{
		ID:          newExemptionID(),
		Package:     r.Package,
		Fingerprint: r.Fingerprint,
		Finding:     *finding,
		BaseVersion: r.BaseVersion,
		HeadVersion: r.HeadVersion,
		Owner:       r.Owner,
		Reason:      r.Reason,
		Consumers:   append([]string{}, r.Consumers...),
		RequestedBy: r.RequestedBy,
		ExpiresAt:   expiresAt.UTC(),
		RequestID:   r.RequestID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	stored, err := s.store.CreateExemption(ctx, ex)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&RequestExemptionResponse{Exemption: s.view(stored)}), nil
}

// ApproveExemption activates a PENDING exemption. The requester may never
// approve their own request. The transition is guarded by the exemption's
// version: two approvers working from the same stale version cannot both
// succeed. Repeating an already-applied approval by the same approver is
// an idempotent success.
func (s *Service) ApproveExemption(ctx context.Context, req *connect.Request[ApproveExemptionRequest]) (*connect.Response[ApproveExemptionResponse], error) {
	r := req.Msg
	if r.ID == "" || r.Approver == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("id and approver are required"))
	}
	ex, err := s.store.GetExemption(ctx, r.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %s not found", r.ID))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// requested_by is immutable, so this check is race-free.
	if ex.RequestedBy == r.Approver {
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("approver %q is the requester of exemption %s; exemptions require a second identity", r.Approver, r.ID))
	}
	if ex.Status == ExemptionPending && !s.now().Before(ex.ExpiresAt) {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("exemption %s expired at %s; request a new one", r.ID, ex.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	updated, err := s.store.ApproveExemption(ctx, r.ID, r.ExpectedVersion, r.Approver, s.now())
	if err != nil {
		return nil, transitionError(err, r.ID)
	}
	return connect.NewResponse(&ApproveExemptionResponse{Exemption: s.view(updated)}), nil
}

// RevokeExemption withdraws an exemption immediately; the next check
// evaluates the finding as blocked again.
func (s *Service) RevokeExemption(ctx context.Context, req *connect.Request[RevokeExemptionRequest]) (*connect.Response[RevokeExemptionResponse], error) {
	r := req.Msg
	if r.ID == "" || r.Revoker == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("id and revoker are required"))
	}
	updated, err := s.store.RevokeExemption(ctx, r.ID, r.ExpectedVersion, r.Revoker, r.Reason, s.now())
	if errors.Is(err, ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %s not found", r.ID))
	}
	if err != nil {
		return nil, transitionError(err, r.ID)
	}
	return connect.NewResponse(&RevokeExemptionResponse{Exemption: s.view(updated)}), nil
}

// ListExemptions returns the exemptions of a package. Statuses are
// reported effective at read time: an approved exemption past its expiry
// shows EXPIRED without any background job having to rewrite it.
func (s *Service) ListExemptions(ctx context.Context, req *connect.Request[ListExemptionsRequest]) (*connect.Response[ListExemptionsResponse], error) {
	if req.Msg.Package == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("package is required"))
	}
	all, err := s.store.ListExemptions(ctx, req.Msg.Package)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &ListExemptionsResponse{}
	for i := range all {
		v := s.view(&all[i])
		if !req.Msg.IncludeInactive && v.Status != ExemptionApproved {
			continue
		}
		resp.Exemptions = append(resp.Exemptions, v)
	}
	return connect.NewResponse(resp), nil
}

// --- evaluation ---

// releaseDecision computes the exemption-aware publish judgement over the
// given findings (the full report for an unscoped check, or the consumer
// projection when a consumer is named). The report itself is untouched.
func (s *Service) releaseDecision(ctx context.Context, pkg, consumer string, considered []compat.Finding) (*ReleaseDecision, error) {
	exemptions, err := s.store.ListExemptions(ctx, pkg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	now := s.now()
	active := map[string]*Exemption{} // fingerprint -> exemption effective for this consumer
	for i := range exemptions {
		ex := &exemptions[i]
		if ex.EffectiveStatus(now) != ExemptionApproved {
			continue
		}
		if !consumerCovered(ex.Consumers, consumer) {
			continue
		}
		active[ex.Fingerprint] = ex
	}

	decision := &ReleaseDecision{Consumer: consumer, RawVerdict: compat.VerdictOf(considered)}
	var remaining []compat.Finding
	for _, f := range considered {
		fd := FindingDecision{Fingerprint: f.Fingerprint(), Code: f.Code, Severity: f.Severity}
		if ex, ok := active[fd.Fingerprint]; ok {
			fd.Exempted = true
			fd.ExemptionID = ex.ID
		} else {
			remaining = append(remaining, f)
		}
		decision.Findings = append(decision.Findings, fd)
	}
	decision.EffectiveVerdict = compat.VerdictOf(remaining)
	return decision, nil
}

// consumerCovered reports whether an exemption scoped to consumers
// applies to an evaluation for consumer. The wildcard "*" covers every
// consumer including unscoped checks; an unscoped check (consumer == "")
// is covered by nothing else.
func consumerCovered(consumers []string, consumer string) bool {
	for _, c := range consumers {
		if c == "*" || (consumer != "" && c == consumer) {
			return true
		}
	}
	return false
}

// view returns the API view of an exemption: the stored status mapped to
// its effective status at read time (APPROVED past expiry -> EXPIRED).
func (s *Service) view(ex *Exemption) *Exemption {
	cp := *ex
	cp.Status = cp.EffectiveStatus(s.now())
	return &cp
}

// transitionError maps store transition errors to Connect codes.
func transitionError(err error, id string) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("exemption %s not found", id))
	case errors.Is(err, ErrConcurrency):
		return connect.NewError(connect.CodeAborted,
			fmt.Errorf("exemption %s was modified concurrently; reload and retry with the current version", id))
	case errors.Is(err, ErrInvalidState):
		return connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("exemption %s is no longer pending; reload to see its current state", id))
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func newExemptionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return "ex_" + hex.EncodeToString(b[:])
}

// --- audit event detail snapshots (shared by both stores) ---

func requestEventDetail(ex *Exemption) string {
	return mustJSON(map[string]any{
		"fingerprint":  ex.Fingerprint,
		"finding":      ex.Finding,
		"base_version": ex.BaseVersion,
		"head_version": ex.HeadVersion,
		"owner":        ex.Owner,
		"reason":       ex.Reason,
		"consumers":    ex.Consumers,
		"expires_at":   ex.ExpiresAt.UTC().Format(time.RFC3339),
		"request_id":   ex.RequestID,
	})
}

func transitionEventDetail(ex *Exemption) string {
	return mustJSON(map[string]any{
		"fingerprint": ex.Fingerprint,
		"from_status": prevStatus(ex.Status),
		"to_status":   ex.Status,
		"version":     ex.Version,
	})
}

func prevStatus(status string) string {
	if status == ExemptionRevoked {
		return "PENDING|APPROVED"
	}
	return ExemptionPending
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
