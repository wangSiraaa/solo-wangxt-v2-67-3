package registry

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store with the same semantics as the
// PostgreSQL store. It backs unit tests and local dry-runs.
type MemStore struct {
	mu         sync.Mutex
	versions   map[string]map[string]*Version // package -> version -> record
	reports    []StoredReport
	consumers  map[string]map[string]*ConsumerDecl // package -> consumer -> decl
	exemptions map[string]*Exemption               // id -> exemption
	byRequest  map[string]string                   // request_id -> exemption id
	events     []ExemptionEvent
}

func NewMemStore() *MemStore {
	return &MemStore{
		versions:   map[string]map[string]*Version{},
		consumers:  map[string]map[string]*ConsumerDecl{},
		exemptions: map[string]*Exemption{},
		byRequest:  map[string]string{},
	}
}

func (m *MemStore) PutVersion(_ context.Context, v Version) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pkg, ok := m.versions[v.Package]
	if !ok {
		pkg = map[string]*Version{}
		m.versions[v.Package] = pkg
	}
	if existing, ok := pkg[v.Version]; ok {
		if bytes.Equal(existing.ContentHash, v.ContentHash) {
			return false, nil // idempotent re-registration of identical content
		}
		return false, ErrVersionConflict
	}
	cp := v
	cp.CreatedAt = time.Now()
	pkg[v.Version] = &cp
	return true, nil
}

func (m *MemStore) GetVersion(_ context.Context, pkg, version string) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.versions[pkg]; ok {
		if v, ok := p[version]; ok {
			cp := *v
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) LatestVersion(_ context.Context, pkg string) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.versions[pkg]
	if !ok {
		return nil, ErrNotFound
	}
	var latest *Version
	for _, v := range p {
		if latest == nil || v.CreatedAt.After(latest.CreatedAt) {
			latest = v
		}
	}
	if latest == nil {
		return nil, ErrNotFound
	}
	cp := *latest
	return &cp, nil
}

func (m *MemStore) ListVersions(_ context.Context, pkg string) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Version
	for _, v := range m.versions[pkg] {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) PutReport(_ context.Context, rep StoredReport) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rep.CreatedAt = time.Now()
	m.reports = append(m.reports, rep)
	return nil
}

func (m *MemStore) GetReport(_ context.Context, pkg, baseVersion, headVersion string) (*StoredReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Reports are append-only; the latest entry for the triple wins.
	for i := len(m.reports) - 1; i >= 0; i-- {
		r := m.reports[i]
		if r.Package == pkg && r.BaseVersion == baseVersion && r.HeadVersion == headVersion {
			cp := r
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) UpsertConsumer(_ context.Context, decl ConsumerDecl) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pkg, ok := m.consumers[decl.Package]
	if !ok {
		pkg = map[string]*ConsumerDecl{}
		m.consumers[decl.Package] = pkg
	}
	decl.UpdatedAt = time.Now()
	cp := decl
	pkg[decl.Consumer] = &cp
	return nil
}

func (m *MemStore) GetConsumer(_ context.Context, pkg, consumer string) (*ConsumerDecl, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.consumers[pkg]; ok {
		if d, ok := p[consumer]; ok {
			cp := *d
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// --- exemptions ---

// appendEvent records an audit event. Callers hold the lock; events and
// the transition they describe are one atomic critical section, matching
// the PostgreSQL store's single-transaction guarantee.
func (m *MemStore) appendEvent(exemptionID, event, actor, detail string, now time.Time) {
	m.events = append(m.events, ExemptionEvent{
		ID:          int64(len(m.events) + 1),
		ExemptionID: exemptionID,
		Event:       event,
		Actor:       actor,
		Detail:      detail,
		CreatedAt:   now,
	})
}

func (m *MemStore) CreateExemption(_ context.Context, ex Exemption) (*Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ex.RequestID != "" {
		if id, ok := m.byRequest[ex.RequestID]; ok {
			cp := *m.exemptions[id]
			return &cp, nil // idempotent retry of the same request
		}
	}
	ex.Version = 1
	ex.Status = ExemptionPending
	cp := ex
	m.exemptions[ex.ID] = &cp
	if ex.RequestID != "" {
		m.byRequest[ex.RequestID] = ex.ID
	}
	m.appendEvent(ex.ID, ExemptionEventRequested, ex.RequestedBy, requestEventDetail(&ex), ex.CreatedAt)
	out := *m.exemptions[ex.ID]
	return &out, nil
}

func (m *MemStore) GetExemption(_ context.Context, id string) (*Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ex, ok := m.exemptions[id]; ok {
		cp := *ex
		return &cp, nil
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListExemptions(_ context.Context, pkg string) ([]Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Exemption
	for _, ex := range m.exemptions {
		if ex.Package == pkg {
			out = append(out, *ex)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (m *MemStore) ApproveExemption(_ context.Context, id string, expectedVersion int64, approver string, now time.Time) (*Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ex, ok := m.exemptions[id]
	if !ok {
		return nil, ErrNotFound
	}
	if ex.Status == ExemptionApproved && ex.ApprovedBy == approver {
		cp := *ex
		return &cp, nil // idempotent retry of an approval already applied
	}
	if ex.Status != ExemptionPending {
		return nil, ErrInvalidState
	}
	if ex.Version != expectedVersion {
		return nil, ErrConcurrency
	}
	ex.Status = ExemptionApproved
	ex.ApprovedBy = approver
	ex.Version++
	ex.UpdatedAt = now
	m.appendEvent(id, ExemptionEventApproved, approver, transitionEventDetail(ex), now)
	cp := *ex
	return &cp, nil
}

func (m *MemStore) RevokeExemption(_ context.Context, id string, expectedVersion int64, revoker, reason string, now time.Time) (*Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ex, ok := m.exemptions[id]
	if !ok {
		return nil, ErrNotFound
	}
	if ex.Status == ExemptionRevoked {
		cp := *ex
		return &cp, nil // idempotent retry
	}
	if ex.Version != expectedVersion {
		return nil, ErrConcurrency
	}
	ex.Status = ExemptionRevoked
	ex.RevokedBy = revoker
	ex.Version++
	ex.UpdatedAt = now
	m.appendEvent(id, ExemptionEventRevoked, revoker, transitionEventDetail(ex), now)
	cp := *ex
	return &cp, nil
}

func (m *MemStore) ListExemptionEvents(_ context.Context, exemptionID string) ([]ExemptionEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ExemptionEvent
	for _, e := range m.events {
		if e.ExemptionID == exemptionID {
			out = append(out, e)
		}
	}
	return out, nil
}
