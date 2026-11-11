// Package memory is a fully implemented, thread-safe in-process Store.
//
// It is the default driver (STORAGE=memory) and the reference implementation of
// the tenant-isolation rules: every read and write is scoped by the explicit
// tenant id, and a resource owned by another tenant is invisible.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ffuf-online/platform/internal/audit"
	"github.com/ffuf-online/platform/internal/domain"
	"github.com/ffuf-online/platform/internal/idgen"
	"github.com/ffuf-online/platform/internal/store"
)

// Store is an in-memory implementation of store.Store.
type Store struct {
	mu sync.RWMutex

	tenants   map[string]domain.Tenant
	tenantSlug map[string]string
	users     map[string]domain.User
	userEmail map[string]string
	members   map[string]domain.Membership // key tenantID|userID

	projects map[string]domain.Project
	programs map[string]domain.Program
	authz    map[string]domain.AuthorizationEvidence

	scopeVersions map[string]domain.ScopeVersion // key tenant|project|version
	scopeRules    map[string][]domain.ScopeRule   // key tenant|project|version

	assets    map[string]domain.Asset
	endpoints map[string]domain.Endpoint
	findings  map[string]domain.Finding

	tasks     map[string]domain.Task
	taskIdem  map[string]string // tenant|idempotency_key -> task id
	attempts  map[string][]domain.TaskAttempt

	events map[string]domain.DomainEvent
	execs  map[string]domain.ToolExecution

	workflows map[string]domain.Workflow
	wfNodes   map[string]map[string]domain.WorkflowNode

	workers         map[string]domain.Worker
	workerByToken   map[string]string // token hash -> worker id

	usage []domain.UsageRecord

	auditEntries []audit.Entry
	auditSeq     int64
}

// New returns an empty store.
func New() *Store {
	return &Store{
		tenants:       map[string]domain.Tenant{},
		tenantSlug:    map[string]string{},
		users:         map[string]domain.User{},
		userEmail:     map[string]string{},
		members:       map[string]domain.Membership{},
		projects:      map[string]domain.Project{},
		programs:      map[string]domain.Program{},
		authz:         map[string]domain.AuthorizationEvidence{},
		scopeVersions: map[string]domain.ScopeVersion{},
		scopeRules:    map[string][]domain.ScopeRule{},
		assets:        map[string]domain.Asset{},
		endpoints:     map[string]domain.Endpoint{},
		findings:      map[string]domain.Finding{},
		tasks:         map[string]domain.Task{},
		taskIdem:      map[string]string{},
		attempts:      map[string][]domain.TaskAttempt{},
		events:        map[string]domain.DomainEvent{},
		execs:         map[string]domain.ToolExecution{},
		workflows:     map[string]domain.Workflow{},
		wfNodes:       map[string]map[string]domain.WorkflowNode{},
		workers:       map[string]domain.Worker{},
		workerByToken: map[string]string{},
	}
}

// Ping implements store.Store.
func (s *Store) Ping(context.Context) error { return nil }

// Close implements store.Store.
func (s *Store) Close() error { return nil }

// ---------------------------------------------------------------- tenants

// CreateTenant implements store.Store.
func (s *Store) CreateTenant(_ context.Context, t domain.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[t.ID]; ok {
		return store.ErrConflict
	}
	if slug, ok := s.tenantSlug[strings.ToLower(t.Slug)]; ok && slug != t.ID {
		return store.ErrConflict
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = "active"
	}
	s.tenants[t.ID] = t
	s.tenantSlug[strings.ToLower(t.Slug)] = t.ID
	return nil
}

// GetTenant implements store.Store.
func (s *Store) GetTenant(_ context.Context, id string) (domain.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return domain.Tenant{}, store.ErrNotFound
	}
	return t, nil
}

// GetTenantBySlug implements store.Store.
func (s *Store) GetTenantBySlug(_ context.Context, slug string) (domain.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.tenantSlug[strings.ToLower(slug)]
	if !ok {
		return domain.Tenant{}, store.ErrNotFound
	}
	return s.tenants[id], nil
}

// ListTenants implements store.Store. It spans every tenant and is used only
// by the platform administrator surface.
func (s *Store) ListTenants(_ context.Context, limit, offset int) ([]domain.Tenant, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		items = append(items, t)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- users

// CreateUser implements store.Store.
func (s *Store) CreateUser(_ context.Context, u domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; ok {
		return store.ErrConflict
	}
	email := strings.ToLower(u.Email)
	if _, ok := s.userEmail[email]; ok {
		return store.ErrConflict
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	s.users[u.ID] = u
	s.userEmail[email] = u.ID
	return nil
}

// GetUser implements store.Store.
func (s *Store) GetUser(_ context.Context, id string) (domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return domain.User{}, store.ErrNotFound
	}
	return u, nil
}

// GetUserByEmail implements store.Store.
func (s *Store) GetUserByEmail(_ context.Context, email string) (domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.userEmail[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return domain.User{}, store.ErrNotFound
	}
	return s.users[id], nil
}

// CreateMembership implements store.Store.
func (s *Store) CreateMembership(_ context.Context, m domain.Membership) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := m.TenantID + "|" + m.UserID
	if _, ok := s.members[key]; ok {
		return store.ErrConflict
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	s.members[key] = m
	return nil
}

// GetMembership implements store.Store.
func (s *Store) GetMembership(_ context.Context, tenantID, userID string) (domain.Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.members[tenantID+"|"+userID]
	if !ok {
		return domain.Membership{}, store.ErrNotFound
	}
	return m, nil
}

// UpdateMembershipRole implements store.Store.
func (s *Store) UpdateMembershipRole(_ context.Context, tenantID, userID, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenantID + "|" + userID
	m, ok := s.members[key]
	if !ok {
		return store.ErrNotFound
	}
	m.Role = role
	s.members[key] = m
	return nil
}

// ListMemberships implements store.Store.
func (s *Store) ListMemberships(_ context.Context, tenantID string, limit, offset int) ([]domain.Membership, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Membership, 0, len(s.members))
	for _, m := range s.members {
		if m.TenantID != tenantID {
			continue
		}
		if u, ok := s.users[m.UserID]; ok {
			m.Email = u.Email
		}
		items = append(items, m)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- projects

// CreateProject implements store.Store.
func (s *Store) CreateProject(_ context.Context, p domain.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[p.ID]; ok {
		return store.ErrConflict
	}
	if t, ok := s.tenants[p.TenantID]; !ok || t.Status == "" {
		return store.ErrNotFound
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.projects[p.ID] = p
	return nil
}

// GetProject implements store.Store.
func (s *Store) GetProject(_ context.Context, tenantID, id string) (domain.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	if !ok || p.TenantID != tenantID {
		return domain.Project{}, store.ErrNotFound
	}
	return p, nil
}

// ListProjects implements store.Store.
func (s *Store) ListProjects(_ context.Context, tenantID string, limit, offset int) ([]domain.Project, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Project, 0)
	for _, p := range s.projects {
		if p.TenantID != tenantID {
			continue
		}
		items = append(items, p)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// CreateProgram implements store.Store.
func (s *Store) CreateProgram(_ context.Context, p domain.Program) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(p.TenantID, p.ProjectID); err != nil {
		return err
	}
	if _, ok := s.programs[p.ID]; ok {
		return store.ErrConflict
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.Source == "" {
		p.Source = "manual"
	}
	s.programs[p.ID] = p
	return nil
}

// ListPrograms implements store.Store.
func (s *Store) ListPrograms(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.Program, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Program, 0)
	for _, p := range s.programs {
		if p.TenantID != tenantID || p.ProjectID != projectID {
			continue
		}
		items = append(items, p)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// CreateAuthorizationEvidence implements store.Store.
func (s *Store) CreateAuthorizationEvidence(_ context.Context, e domain.AuthorizationEvidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(e.TenantID, e.ProjectID); err != nil {
		return err
	}
	if _, ok := s.authz[e.ID]; ok {
		return store.ErrConflict
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	s.authz[e.ID] = e
	return nil
}

// ListAuthorizationEvidence implements store.Store.
func (s *Store) ListAuthorizationEvidence(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.AuthorizationEvidence, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.AuthorizationEvidence, 0)
	for _, e := range s.authz {
		if e.TenantID != tenantID || e.ProjectID != projectID {
			continue
		}
		items = append(items, e)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- scope

// CreateScopeVersion implements store.Store.
func (s *Store) CreateScopeVersion(_ context.Context, sv domain.ScopeVersion, rules []domain.ScopeRule) (domain.ScopeVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(sv.TenantID, sv.ProjectID); err != nil {
		return domain.ScopeVersion{}, err
	}
	prev, ok := s.latestScopeLocked(sv.TenantID, sv.ProjectID)
	if ok {
		sv.Version = prev.Version + 1
		sv.PolicyVersion = prev.PolicyVersion + 1
	} else {
		sv.Version = 1
		if sv.PolicyVersion == 0 {
			sv.PolicyVersion = 1
		}
	}
	if sv.PolicyVersion == 0 {
		sv.PolicyVersion = 1
	}
	if sv.MaxRPS == 0 {
		sv.MaxRPS = 5
	}
	if sv.MaxConcurrency == 0 {
		sv.MaxConcurrency = 2
	}
	if sv.PolicyProfile == "" {
		sv.PolicyProfile = "passive"
	}
	if sv.ID == "" {
		sv.ID = idgen.New("scope")
	}
	if sv.CreatedAt.IsZero() {
		sv.CreatedAt = time.Now().UTC()
	}
	sv.Authorized = false
	sv.AuthorizedAt = nil
	sv.AuthorizedBy = ""

	key := scopeKey(sv.TenantID, sv.ProjectID, sv.Version)
	stored := make([]domain.ScopeRule, 0, len(rules))
	for _, r := range rules {
		if r.ID == "" {
			r.ID = idgen.New("rule")
		}
		r.TenantID = sv.TenantID
		r.ProjectID = sv.ProjectID
		r.ScopeVersionID = sv.ID
		if r.Note == "" {
			r.Note = ""
		}
		if r.CreatedAt.IsZero() {
			r.CreatedAt = time.Now().UTC()
		}
		stored = append(stored, r)
	}
	s.scopeVersions[key] = sv
	s.scopeRules[key] = stored
	return sv, nil
}

// GetScopeVersion implements store.Store.
func (s *Store) GetScopeVersion(_ context.Context, tenantID, projectID string, version int) (domain.ScopeVersion, []domain.ScopeRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := scopeKey(tenantID, projectID, version)
	sv, ok := s.scopeVersions[key]
	if !ok {
		return domain.ScopeVersion{}, nil, store.ErrNotFound
	}
	return sv, append([]domain.ScopeRule(nil), s.scopeRules[key]...), nil
}

// GetCurrentScope implements store.Store.
func (s *Store) GetCurrentScope(_ context.Context, tenantID, projectID string) (domain.ScopeVersion, []domain.ScopeRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sv, ok := s.latestScopeLocked(tenantID, projectID)
	if !ok {
		return domain.ScopeVersion{}, nil, store.ErrNotFound
	}
	key := scopeKey(tenantID, projectID, sv.Version)
	return sv, append([]domain.ScopeRule(nil), s.scopeRules[key]...), nil
}

// AuthorizeScope implements store.Store.
func (s *Store) AuthorizeScope(_ context.Context, tenantID, projectID string, version int, authorizedBy string, at time.Time) (domain.ScopeVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeKey(tenantID, projectID, version)
	sv, ok := s.scopeVersions[key]
	if !ok {
		return domain.ScopeVersion{}, store.ErrNotFound
	}
	t := at.UTC()
	sv.Authorized = true
	sv.AuthorizedAt = &t
	sv.AuthorizedBy = authorizedBy
	s.scopeVersions[key] = sv
	return sv, nil
}

// ---------------------------------------------------------------- assets

// UpsertAssets implements store.Store.
func (s *Store) UpsertAssets(_ context.Context, tenantID, projectID string, assets []domain.Asset) (store.AssetUpsertResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(tenantID, projectID); err != nil {
		return store.AssetUpsertResult{}, err
	}
	now := time.Now().UTC()
	idx := make(map[string]string, len(s.assets))
	for id, a := range s.assets {
		if a.TenantID == tenantID && a.ProjectID == projectID {
			idx[a.CorrelationKey] = id
		}
	}
	res := store.AssetUpsertResult{Items: make([]domain.Asset, 0, len(assets))}
	for _, in := range assets {
		a := in
		a.TenantID = tenantID
		a.ProjectID = projectID
		if a.CorrelationKey == "" {
			a.CorrelationKey = correlationKey(a.AssetType, a.Value)
		}
		if a.ScopeStatus == "" {
			a.ScopeStatus = "unknown"
		}
		if a.Confidence == 0 {
			a.Confidence = 1.0
		}
		if a.Metadata == nil {
			a.Metadata = map[string]any{}
		}
		if a.FirstSeenAt.IsZero() {
			a.FirstSeenAt = now
		}
		if a.LastSeenAt.IsZero() {
			a.LastSeenAt = a.FirstSeenAt
		}
		if existingID, ok := idx[a.CorrelationKey]; ok {
			existing := s.assets[existingID]
			merged := mergeAsset(existing, a)
			s.assets[existingID] = merged
			res.Upserted++
			res.Items = append(res.Items, merged)
			continue
		}
		if a.ID == "" {
			a.ID = idgen.New("asset")
		}
		s.assets[a.ID] = a
		idx[a.CorrelationKey] = a.ID
		res.Upserted++
		res.Created++
		res.Items = append(res.Items, a)
	}
	return res, nil
}

// GetAsset implements store.Store.
func (s *Store) GetAsset(_ context.Context, tenantID, id string) (domain.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok || a.TenantID != tenantID {
		return domain.Asset{}, store.ErrNotFound
	}
	return a, nil
}

// ListAssets implements store.Store.
func (s *Store) ListAssets(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.Asset, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Asset, 0)
	for _, a := range s.assets {
		if a.TenantID != tenantID || a.ProjectID != projectID {
			continue
		}
		items = append(items, a)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].FirstSeenAt.Before(items[j].FirstSeenAt) })
	return paginate(items, limit, offset)
}

// CreateEndpoint implements store.Store.
func (s *Store) CreateEndpoint(_ context.Context, e domain.Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(e.TenantID, e.ProjectID); err != nil {
		return err
	}
	if e.ID == "" {
		e.ID = idgen.New("ep")
	}
	if e.CorrelationKey == "" {
		e.CorrelationKey = correlationKey(e.Method, e.URL)
	}
	if e.FirstSeenAt.IsZero() {
		e.FirstSeenAt = time.Now().UTC()
	}
	for id, existing := range s.endpoints {
		if existing.TenantID == e.TenantID && existing.ProjectID == e.ProjectID && existing.CorrelationKey == e.CorrelationKey {
			e.ID = id
			break
		}
	}
	s.endpoints[e.ID] = e
	return nil
}

// ListEndpoints implements store.Store.
func (s *Store) ListEndpoints(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.Endpoint, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Endpoint, 0)
	for _, e := range s.endpoints {
		if e.TenantID != tenantID || e.ProjectID != projectID {
			continue
		}
		items = append(items, e)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].FirstSeenAt.Before(items[j].FirstSeenAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- findings

// CreateFinding implements store.Store. It deduplicates on
// (tenant, project, correlation_key): an existing finding is returned with
// created=false.
func (s *Store) CreateFinding(_ context.Context, f domain.Finding) (domain.Finding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(f.TenantID, f.ProjectID); err != nil {
		return domain.Finding{}, false, err
	}
	if f.CorrelationKey() == "" {
		f.SetCorrelationKey(findingCorrelationKey(f))
	}
	for _, existing := range s.findings {
		if existing.TenantID == f.TenantID && existing.ProjectID == f.ProjectID && existing.CorrelationKey() == f.CorrelationKey() {
			return existing, false, nil
		}
	}
	if f.ID == "" {
		f.ID = idgen.New("finding")
	}
	now := time.Now().UTC()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.UpdatedAt = now
	if f.Severity == "" {
		f.Severity = "unknown"
	}
	if f.Status == "" {
		f.Status = "discovered"
	}
	if f.SourceTools == nil {
		f.SourceTools = []string{}
	}
	s.findings[f.ID] = f
	return f, true, nil
}

// GetFinding implements store.Store.
func (s *Store) GetFinding(_ context.Context, tenantID, id string) (domain.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.findings[id]
	if !ok || f.TenantID != tenantID {
		return domain.Finding{}, store.ErrNotFound
	}
	return f, nil
}

// UpdateFinding implements store.Store.
func (s *Store) UpdateFinding(_ context.Context, f domain.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.findings[f.ID]
	if !ok || existing.TenantID != f.TenantID {
		return store.ErrNotFound
	}
	f.CreatedAt = existing.CreatedAt
	f.UpdatedAt = time.Now().UTC()
	s.findings[f.ID] = f
	return nil
}

// ListFindings implements store.Store.
func (s *Store) ListFindings(_ context.Context, tenantID, projectID, status string, limit, offset int) ([]domain.Finding, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Finding, 0)
	for _, f := range s.findings {
		if f.TenantID != tenantID {
			continue
		}
		if projectID != "" && f.ProjectID != projectID {
			continue
		}
		if status != "" && f.Status != status {
			continue
		}
		items = append(items, f)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- tasks

// CreateTask implements store.Store, deduplicating on
// (tenant_id, idempotency_key).
func (s *Store) CreateTask(_ context.Context, t domain.Task) (domain.Task, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(t.TenantID, t.ProjectID); err != nil {
		return domain.Task{}, false, err
	}
	if t.IdempotencyKey == "" {
		return domain.Task{}, false, store.ErrConflict
	}
	idemKey := t.TenantID + "|" + t.IdempotencyKey
	if id, ok := s.taskIdem[idemKey]; ok {
		return s.tasks[id], true, nil
	}
	if t.ID == "" {
		t.ID = idgen.New("task")
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = domain.TaskPending
	}
	if t.Input == nil {
		t.Input = map[string]any{}
	}
	s.tasks[t.ID] = t
	s.taskIdem[idemKey] = t.ID
	return t, false, nil
}

// GetTask implements store.Store.
func (s *Store) GetTask(_ context.Context, tenantID, id string) (domain.Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[id]
	if !ok || t.TenantID != tenantID {
		return domain.Task{}, store.ErrNotFound
	}
	return t, nil
}

// UpdateTaskStatus implements store.Store.
func (s *Store) UpdateTaskStatus(_ context.Context, tenantID, id, status, reason string) (domain.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok || t.TenantID != tenantID {
		return domain.Task{}, store.ErrNotFound
	}
	t.Status = status
	if reason != "" {
		t.Reason = reason
	}
	s.tasks[id] = t
	return t, nil
}

// ListTasks implements store.Store.
func (s *Store) ListTasks(_ context.Context, tenantID, projectID, status string, limit, offset int) ([]domain.Task, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Task, 0)
	for _, t := range s.tasks {
		if t.TenantID != tenantID {
			continue
		}
		if projectID != "" && t.ProjectID != projectID {
			continue
		}
		if status != "" && t.Status != status {
			continue
		}
		items = append(items, t)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Priority != items[j].Priority {
			return items[i].Priority > items[j].Priority
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	return paginate(items, limit, offset)
}

// ListTasksByStatus implements store.Store: it spans every tenant so the
// worker-manager can reconcile stale dispatches.
func (s *Store) ListTasksByStatus(_ context.Context, status string, limit int) ([]domain.Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Task, 0)
	for _, t := range s.tasks {
		if status != "" && t.Status != status {
			continue
		}
		items = append(items, t)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// CreateTaskAttempt implements store.Store.
func (s *Store) CreateTaskAttempt(_ context.Context, a domain.TaskAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[a.TaskID]
	if !ok || t.TenantID != a.TenantID {
		return store.ErrNotFound
	}
	if a.ID == "" {
		a.ID = idgen.New("attempt")
	}
	if a.StartedAt.IsZero() {
		a.StartedAt = time.Now().UTC()
	}
	if a.Attempt == 0 {
		a.Attempt = len(s.attempts[a.TaskID]) + 1
	}
	s.attempts[a.TaskID] = append(s.attempts[a.TaskID], a)
	return nil
}

// ListTaskAttempts implements store.Store.
func (s *Store) ListTaskAttempts(_ context.Context, tenantID, taskID string) ([]domain.TaskAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[taskID]
	if !ok || t.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	return append([]domain.TaskAttempt(nil), s.attempts[taskID]...), nil
}

// ---------------------------------------------------------------- events

// CreateEvent implements store.Store, deduplicating on event_id.
func (s *Store) CreateEvent(_ context.Context, e domain.DomainEvent) (domain.DomainEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[e.EventID]; ok {
		return s.events[e.EventID], false, nil
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Payload == nil {
		e.Payload = map[string]any{}
	}
	if e.ScopeVersion == 0 {
		e.ScopeVersion = 1
	}
	s.events[e.EventID] = e
	return e, true, nil
}

// ListEvents implements store.Store.
func (s *Store) ListEvents(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.DomainEvent, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.DomainEvent, 0)
	for _, e := range s.events {
		if e.TenantID != tenantID {
			continue
		}
		if projectID != "" && e.ProjectID != projectID {
			continue
		}
		items = append(items, e)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Timestamp.After(items[j].Timestamp) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- executions

// CreateExecution implements store.Store.
func (s *Store) CreateExecution(_ context.Context, e domain.ToolExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(e.TenantID, e.ProjectID); err != nil {
		return err
	}
	if e.ID == "" {
		e.ID = idgen.New("exec")
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.Status == "" {
		e.Status = "queued"
	}
	if e.Input == nil {
		e.Input = map[string]any{}
	}
	if e.OutputSummary == nil {
		e.OutputSummary = map[string]any{}
	}
	s.execs[e.ID] = e
	return nil
}

// GetExecution implements store.Store.
func (s *Store) GetExecution(_ context.Context, tenantID, id string) (domain.ToolExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.execs[id]
	if !ok {
		return domain.ToolExecution{}, store.ErrNotFound
	}
	if tenantID != "" && e.TenantID != tenantID {
		return domain.ToolExecution{}, store.ErrNotFound
	}
	return e, nil
}

// UpdateExecution implements store.Store.
func (s *Store) UpdateExecution(_ context.Context, e domain.ToolExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.execs[e.ID]
	if !ok || existing.TenantID != e.TenantID {
		return store.ErrNotFound
	}
	e.CreatedAt = existing.CreatedAt
	s.execs[e.ID] = e
	return nil
}

// ListExecutions implements store.Store.
func (s *Store) ListExecutions(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.ToolExecution, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.ToolExecution, 0)
	for _, e := range s.execs {
		if e.TenantID != tenantID {
			continue
		}
		if projectID != "" && e.ProjectID != projectID {
			continue
		}
		items = append(items, e)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- workflows

// CreateWorkflow implements store.Store.
func (s *Store) CreateWorkflow(_ context.Context, w domain.Workflow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProjectLocked(w.TenantID, w.ProjectID); err != nil {
		return err
	}
	if _, ok := s.workflows[w.ID]; ok {
		return store.ErrConflict
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now().UTC()
	}
	if w.Status == "" {
		w.Status = "running"
	}
	if w.MaxDepth == 0 {
		w.MaxDepth = 5
	}
	s.workflows[w.ID] = w
	if s.wfNodes[w.ID] == nil {
		s.wfNodes[w.ID] = map[string]domain.WorkflowNode{}
	}
	return nil
}

// GetWorkflow implements store.Store.
func (s *Store) GetWorkflow(_ context.Context, tenantID, id string) (domain.Workflow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workflows[id]
	if !ok || w.TenantID != tenantID {
		return domain.Workflow{}, store.ErrNotFound
	}
	return w, nil
}

// UpsertWorkflowNode implements store.Store.
func (s *Store) UpsertWorkflowNode(_ context.Context, n domain.WorkflowNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workflows[n.WorkflowID]
	if !ok || w.TenantID != n.TenantID {
		return store.ErrNotFound
	}
	if n.ID == "" {
		n.ID = idgen.New("node")
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	if n.Status == "" {
		n.Status = "pending"
	}
	if s.wfNodes[n.WorkflowID] == nil {
		s.wfNodes[n.WorkflowID] = map[string]domain.WorkflowNode{}
	}
	s.wfNodes[n.WorkflowID][n.ID] = n
	return nil
}

// ListWorkflowNodes implements store.Store.
func (s *Store) ListWorkflowNodes(_ context.Context, tenantID, workflowID string) ([]domain.WorkflowNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workflows[workflowID]
	if !ok || w.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	nodes := make([]domain.WorkflowNode, 0, len(s.wfNodes[workflowID]))
	for _, n := range s.wfNodes[workflowID] {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].CreatedAt.Before(nodes[j].CreatedAt) })
	return nodes, nil
}

// ListWorkflows implements store.Store.
func (s *Store) ListWorkflows(_ context.Context, tenantID, projectID string, limit, offset int) ([]domain.Workflow, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Workflow, 0)
	for _, w := range s.workflows {
		if w.TenantID != tenantID {
			continue
		}
		if projectID != "" && w.ProjectID != projectID {
			continue
		}
		items = append(items, w)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- workers

// CreateWorker implements store.Store.
func (s *Store) CreateWorker(_ context.Context, w domain.Worker) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workers[w.ID]; ok {
		return store.ErrConflict
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now().UTC()
	}
	if w.Status == "" {
		w.Status = "offline"
	}
	if w.ToolIDs == nil {
		w.ToolIDs = []string{}
	}
	s.workers[w.ID] = w
	if w.TokenHash != "" {
		s.workerByToken[w.TokenHash] = w.ID
	}
	return nil
}

// GetWorker implements store.Store.
func (s *Store) GetWorker(_ context.Context, id string) (domain.Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.workers[id]
	if !ok {
		return domain.Worker{}, store.ErrNotFound
	}
	return w, nil
}

// GetWorkerByTokenHash implements store.Store.
func (s *Store) GetWorkerByTokenHash(_ context.Context, tokenHash string) (domain.Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.workerByToken[tokenHash]
	if !ok {
		return domain.Worker{}, store.ErrNotFound
	}
	return s.workers[id], nil
}

// ListWorkers implements store.Store.
func (s *Store) ListWorkers(_ context.Context, tenantID string, limit, offset int) ([]domain.Worker, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Worker, 0)
	for _, w := range s.workers {
		if tenantID != "" && w.TenantID != tenantID {
			continue
		}
		items = append(items, w)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return paginate(items, limit, offset)
}

// ListAllWorkers implements store.Store.
func (s *Store) ListAllWorkers(_ context.Context) ([]domain.Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.Worker, 0, len(s.workers))
	for _, w := range s.workers {
		items = append(items, w)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return items, nil
}

// UpdateWorkerHeartbeat implements store.Store.
func (s *Store) UpdateWorkerHeartbeat(_ context.Context, workerID string, runningJobs int, cpuLoad float64, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workers[workerID]
	if !ok {
		return store.ErrNotFound
	}
	t := at.UTC()
	w.LastHeartbeat = &t
	w.RunningJobs = runningJobs
	w.CPULoad = cpuLoad
	w.Status = "online"
	s.workers[workerID] = w
	return nil
}

// SetWorkerStatus implements store.Store.
func (s *Store) SetWorkerStatus(_ context.Context, workerID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.workers[workerID]
	if !ok {
		return store.ErrNotFound
	}
	w.Status = status
	s.workers[workerID] = w
	return nil
}

// ---------------------------------------------------------------- usage

// AddUsage implements store.Store.
func (s *Store) AddUsage(_ context.Context, u domain.UsageRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == "" {
		u.ID = idgen.New("usage")
	}
	if u.RecordedAt.IsZero() {
		u.RecordedAt = time.Now().UTC()
	}
	s.usage = append(s.usage, u)
	return nil
}

// ListUsage implements store.Store.
func (s *Store) ListUsage(_ context.Context, tenantID string, limit, offset int) ([]domain.UsageRecord, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]domain.UsageRecord, 0)
	for _, u := range s.usage {
		if u.TenantID != tenantID {
			continue
		}
		items = append(items, u)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RecordedAt.After(items[j].RecordedAt) })
	return paginate(items, limit, offset)
}

// ---------------------------------------------------------------- audit

// LastAuditHash implements store.AuditBackend.
func (s *Store) LastAuditHash(context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.auditEntries) == 0 {
		return "", nil
	}
	return s.auditEntries[len(s.auditEntries)-1].EntryHash, nil
}

// PutAudit implements store.AuditBackend.
func (s *Store) PutAudit(_ context.Context, e audit.Entry) (audit.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSeq++
	e.Seq = s.auditSeq
	s.auditEntries = append(s.auditEntries, e)
	return e, nil
}

// ListAudit implements store.AuditBackend.
func (s *Store) ListAudit(_ context.Context, tenantID string, limit, offset int) ([]audit.Entry, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]audit.Entry, 0, len(s.auditEntries))
	for _, e := range s.auditEntries {
		if tenantID != "" && e.TenantID != tenantID {
			continue
		}
		items = append(items, e)
	}
	// newest first for the API listing
	sort.Slice(items, func(i, j int) bool { return items[i].Seq > items[j].Seq })
	return paginate(items, limit, offset)
}

// AllAudit implements store.AuditBackend.
func (s *Store) AllAudit(context.Context) ([]audit.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]audit.Entry(nil), s.auditEntries...), nil
}

// ---------------------------------------------------------------- helpers

func (s *Store) ensureProjectLocked(tenantID, projectID string) error {
	p, ok := s.projects[projectID]
	if !ok {
		return store.ErrNotFound
	}
	if p.TenantID != tenantID {
		return store.ErrCrossTenant
	}
	return nil
}

func (s *Store) latestScopeLocked(tenantID, projectID string) (domain.ScopeVersion, bool) {
	var best domain.ScopeVersion
	found := false
	for _, sv := range s.scopeVersions {
		if sv.TenantID != tenantID || sv.ProjectID != projectID {
			continue
		}
		if !found || sv.Version > best.Version {
			best = sv
			found = true
		}
	}
	return best, found
}

func scopeKey(tenantID, projectID string, version int) string {
	return tenantID + "|" + projectID + "|" + itoa(version)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func paginate[T any](items []T, limit, offset int) ([]T, int, error) {
	total := len(items)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []T{}, total, nil
	}
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	return items[offset:end], total, nil
}

func correlationKey(parts ...string) string {
	joined := strings.Join(parts, "|")
	return strings.ToLower(strings.TrimSpace(joined))
}

// findingCorrelationKey derives the deterministic, tenant/project-scoped dedup
// identity of a finding from its semantic tuple (type + target + parameter).
// Two tools reporting the same issue on the same target therefore collapse to
// one finding.
func findingCorrelationKey(f domain.Finding) string {
	parts := []string{f.FindingType}
	for _, p := range []*string{f.Endpoint, f.HTTPMethod, f.Parameter, f.AssetID} {
		if p != nil {
			parts = append(parts, *p)
		}
	}
	return correlationKey(parts...)
}

func mergeAsset(existing, incoming domain.Asset) domain.Asset {
	out := existing
	out.SourceTools = unionStrings(existing.SourceTools, incoming.SourceTools)
	if !incoming.FirstSeenAt.IsZero() && (out.FirstSeenAt.IsZero() || incoming.FirstSeenAt.Before(out.FirstSeenAt)) {
		out.FirstSeenAt = incoming.FirstSeenAt
	}
	if !incoming.LastSeenAt.IsZero() && incoming.LastSeenAt.After(out.LastSeenAt) {
		out.LastSeenAt = incoming.LastSeenAt
	}
	if incoming.ScopeStatus != "" {
		out.ScopeStatus = incoming.ScopeStatus
	}
	if incoming.Confidence != 0 {
		out.Confidence = incoming.Confidence
	}
	if incoming.ParentAssetID != nil {
		out.ParentAssetID = incoming.ParentAssetID
	}
	if incoming.Value != "" {
		out.Value = incoming.Value
	}
	if out.Metadata == nil {
		out.Metadata = map[string]any{}
	}
	for k, v := range incoming.Metadata {
		out.Metadata[k] = v
	}
	return out
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
