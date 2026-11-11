// Package audit implements the append-only audit log and its hash chain.
//
// Every mutating action in the control plane records exactly one Entry. The
// chain is sealed with
//
//	entry_hash = sha256(prev_hash + canonical_json(entry))
//
// where canonical_json has deterministic key ordering and no insignificant
// whitespace, and the entry's own entry_hash field is excluded. Any mutation of
// a stored entry therefore breaks Verify for that entry and every entry after
// it.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Entry is one immutable audit record.
type Entry struct {
	// Seq is the storage sequence number, assigned when the entry is appended.
	// It is excluded from the hash (json:"-") so the hash can be computed
	// before the backend allocates the number.
	Seq int64 `json:"-"`
	// TenantID is empty for platform-wide actions.
	TenantID string `json:"tenant_id"`
	// ProjectID is empty when the action is not project-scoped.
	ProjectID string `json:"project_id"`
	// ActorUserID is the user that performed the action, when known.
	ActorUserID string `json:"actor_user_id"`
	// ActorKind is "user", "worker" or "system".
	ActorKind string `json:"actor_kind"`
	// Action is the audited operation, e.g. "project.create".
	Action string `json:"action"`
	// ResourceType is the kind of the affected resource.
	ResourceType string `json:"resource_type"`
	// ResourceID identifies the affected resource.
	ResourceID string `json:"resource_id"`
	// ScopeVersion is the scope version in force, when applicable.
	ScopeVersion *int `json:"scope_version"`
	// PolicyVersion is the policy version in force, when applicable.
	PolicyVersion *int `json:"policy_version"`
	// Result is "success" or "denied".
	Result string `json:"result"`
	// ExecutionID links the entry to a tool execution, when applicable.
	ExecutionID string `json:"execution_id"`
	// PrevHash is the entry_hash of the previous entry ("" for the first).
	PrevHash string `json:"prev_hash"`
	// EntryHash is the sealed hash of this entry.
	EntryHash string `json:"entry_hash"`
	// At is the record timestamp (UTC).
	At time.Time `json:"at"`
}

// ErrChainBroken is returned by Verify when the chain does not validate.
var ErrChainBroken = errors.New("audit: hash chain broken")

// ComputeHash returns hex(sha256(prevHash || canonical_json(entry))) with the
// entry's own EntryHash cleared.
func ComputeHash(prevHash string, e Entry) (string, error) {
	e.EntryHash = ""
	canonical, err := canonicalJSON(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify walks entries in order and checks that every prev_hash links to the
// preceding entry_hash and that every entry_hash recomputes.
func Verify(entries []Entry) error {
	prev := ""
	for i, e := range entries {
		if e.PrevHash != prev {
			return fmt.Errorf("%w: entry %d (seq %d) prev_hash %q does not follow %q",
				ErrChainBroken, i, e.Seq, e.PrevHash, prev)
		}
		want, err := ComputeHash(e.PrevHash, e)
		if err != nil {
			return err
		}
		if want != e.EntryHash {
			return fmt.Errorf("%w: entry %d (seq %d) entry_hash mismatch (stored %q, computed %q)",
				ErrChainBroken, i, e.Seq, e.EntryHash, want)
		}
		prev = e.EntryHash
	}
	return nil
}

// Backend persists audit entries. Created by the store implementations so an
// in-memory run and a Postgres run share exactly one chain implementation.
type Backend interface {
	// LastAuditHash returns the entry_hash of the most recent entry ("" when
	// the chain is empty).
	LastAuditHash(ctx context.Context) (string, error)
	// PutAudit stores a sealed entry and returns it with its sequence number.
	PutAudit(ctx context.Context, e Entry) (Entry, error)
	// ListAudit returns entries in append order, oldest first.
	ListAudit(ctx context.Context, tenantID string, limit, offset int) ([]Entry, int, error)
	// AllAudit returns every entry in append order (used by Verify).
	AllAudit(ctx context.Context) ([]Entry, error)
}

// Recorder serialises appends so the chain stays linear.
type Recorder struct {
	mu      sync.Mutex
	backend Backend
	now     func() time.Time
}

// NewRecorder returns a Recorder writing to backend.
func NewRecorder(backend Backend) *Recorder {
	return &Recorder{backend: backend, now: func() time.Time { return time.Now().UTC() }}
}

// Record seals e (filling PrevHash, EntryHash and At) and appends it.
func (r *Recorder) Record(ctx context.Context, e Entry) (Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	prev, err := r.backend.LastAuditHash(ctx)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: read chain head: %w", err)
	}
	if e.At.IsZero() {
		e.At = r.now()
	}
	e.At = e.At.UTC()
	if e.ActorKind == "" {
		e.ActorKind = "system"
	}
	if e.Result == "" {
		e.Result = "success"
	}
	e.PrevHash = prev
	hash, err := ComputeHash(prev, e)
	if err != nil {
		return Entry{}, err
	}
	e.EntryHash = hash
	return r.backend.PutAudit(ctx, e)
}

// List returns a page of audit entries.
func (r *Recorder) List(ctx context.Context, tenantID string, limit, offset int) ([]Entry, int, error) {
	return r.backend.ListAudit(ctx, tenantID, limit, offset)
}

// VerifyChain re-validates the whole stored chain.
func (r *Recorder) VerifyChain(ctx context.Context) error {
	all, err := r.backend.AllAudit(ctx)
	if err != nil {
		return err
	}
	return Verify(all)
}

// canonicalJSON renders v with sorted object keys and no insignificant
// whitespace. Numbers keep their original textual form (json.Number).
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("audit: canonical json: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("audit: canonical json: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("audit: canonical json: unsupported type %T", v)
	}
	return nil
}
