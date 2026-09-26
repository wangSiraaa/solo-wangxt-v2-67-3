package registry

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store with the same semantics as the
// PostgreSQL store. It backs unit tests and local dry-runs.
type MemStore struct {
	mu         sync.Mutex
	versions   map[string]map[string]*Version      // package -> version -> record
	reports    map[string][]StoredReport           // pkg|base|head -> reports
	consumers  map[string]map[string]*ConsumerDecl // package -> consumer -> decl
	exemptions map[int64]*Exemption
	audit      []AuditEvent
	nextID     int64
}

func NewMemStore() *MemStore {
	return &MemStore{
		versions:   map[string]map[string]*Version{},
		reports:    map[string][]StoredReport{},
		consumers:  map[string]map[string]*ConsumerDecl{},
		exemptions: map[int64]*Exemption{},
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
	key := rep.Package + "|" + rep.BaseVersion + "|" + rep.HeadVersion
	m.reports[key] = append(m.reports[key], rep)
	return nil
}

func (m *MemStore) GetReport(_ context.Context, pkg, base, head string) (*StoredReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.reports[pkg+"|"+base+"|"+head]
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	cp := list[len(list)-1]
	return &cp, nil
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

func (m *MemStore) CreateExemption(_ context.Context, in Exemption) (*Exemption, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Idempotent open request by the same requester for the same finding.
	for _, e := range m.exemptions {
		if e.Package == in.Package && e.Fingerprint == in.Fingerprint &&
			e.RequestedBy == in.RequestedBy &&
			(e.Status == ExemptionPending || e.Status == ExemptionApproved) {
			cp := *e
			return &cp, false, nil
		}
	}
	m.nextID++
	e := in
	e.ID = m.nextID
	e.Status = ExemptionPending
	e.Version = 1
	e.CreatedAt = time.Now()
	cpConsumers := append([]string{}, in.Consumers...)
	e.Consumers = cpConsumers
	m.exemptions[e.ID] = &e
	m.appendAuditLocked(AuditEvent{
		ExemptionID: e.ID, Package: e.Package, Action: "REQUESTED",
		Actor: e.RequestedBy, FromState: "", ToState: ExemptionPending, Version: 1,
	})
	cp := e
	return &cp, true, nil
}

func (m *MemStore) GetExemption(_ context.Context, id int64) (*Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.exemptions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *e
	return &cp, nil
}

func (m *MemStore) ListExemptions(_ context.Context, pkg, fingerprint string) ([]Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Exemption
	for _, e := range m.exemptions {
		if e.Package != pkg || (fingerprint != "" && e.Fingerprint != fingerprint) {
			continue
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func (m *MemStore) ActiveExemptionsForPackage(_ context.Context, pkg string) ([]Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Exemption
	for _, e := range m.exemptions {
		if e.Package == pkg && e.Status == ExemptionApproved {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) TransitionExemption(_ context.Context, id, expectedVersion int64, expectFrom ExemptionStatus, patch ExemptionPatch, event AuditEvent) (*Exemption, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.exemptions[id]
	if !ok {
		return nil, ErrNotFound
	}
	if e.Version != expectedVersion {
		return nil, errConcurrent(expectedVersion, e.Version)
	}
	if e.Status != expectFrom {
		return nil, errInvalidTransition(id, e.Status, expectFrom)
	}
	from := e.Status
	e.Status = patch.Status
	if patch.ApprovedBy != "" {
		e.ApprovedBy = patch.ApprovedBy
	}
	if patch.RejectedBy != "" {
		e.RejectedBy = patch.RejectedBy
	}
	if patch.RevokedBy != "" {
		e.RevokedBy = patch.RevokedBy
	}
	if patch.DecidedAt != nil {
		e.DecidedAt = *patch.DecidedAt
	}
	e.Version++
	event.ExemptionID = id
	event.Package = e.Package
	event.FromState = from
	event.ToState = patch.Status
	event.Version = e.Version
	m.appendAuditLocked(event)
	cp := *e
	return &cp, nil
}

func (m *MemStore) ListAuditEvents(_ context.Context, pkg string, exemptionID int64) ([]AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AuditEvent
	for _, a := range m.audit {
		if a.Package != pkg || (exemptionID != 0 && a.ExemptionID != exemptionID) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (m *MemStore) appendAuditLocked(ev AuditEvent) {
	ev.ID = int64(len(m.audit) + 1)
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now()
	}
	m.audit = append(m.audit, ev)
}

func errInvalidTransition(id int64, got, want ExemptionStatus) error {
	return fmt.Errorf("%w: exemption %d is %s, expected %s", ErrInvalidStateTransition, id, got, want)
}

func errConcurrent(expected, current int64) error {
	return fmt.Errorf("%w: version %d no longer current (expected %d)", ErrConcurrentModification, expected, current)
}
