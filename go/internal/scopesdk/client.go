// Package scopesdk is the HTTP client for the Rust scope enforcement engine.
//
// It is the only place the control plane talks about scope. The Go code never
// re-implements a scope rule: it builds a ScopeRequest and returns whatever
// ScopeDecision comes back.
package scopesdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Rule is one entry of ScopeRequest.scope_rules.
type Rule struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
}

// Target is the object under evaluation.
type Target struct {
	Kind   string  `json:"kind"`
	Value  string  `json:"value"`
	Scheme *string `json:"scheme,omitempty"`
	Host   *string `json:"host,omitempty"`
	Port   *int    `json:"port,omitempty"`
	Path   *string `json:"path,omitempty"`
}

// RatePolicy mirrors the Rust RatePolicy.
type RatePolicy struct {
	MaxRPS         *int `json:"max_rps,omitempty"`
	MaxConcurrency *int `json:"max_concurrency,omitempty"`
}

// Authorization mirrors the Rust Authorization grant.
type Authorization struct {
	Authorized bool       `json:"authorized"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// Request mirrors packages/schemas/scope-request.schema.json. The Rust engine
// uses `deny_unknown_fields`, so every field must match exactly.
type Request struct {
	RequestID      string         `json:"request_id,omitempty"`
	TenantID       string         `json:"tenant_id"`
	ProjectID      string         `json:"project_id"`
	ScopeVersion   *int           `json:"scope_version,omitempty"`
	PolicyProfile  string         `json:"policy_profile"`
	Target         Target         `json:"target"`
	ResolvedIPs    []string       `json:"resolved_ips,omitempty"`
	RedirectChain  []string       `json:"redirect_chain,omitempty"`
	DestIP         *string        `json:"dest_ip,omitempty"`
	ScopeRules     []Rule         `json:"scope_rules"`
	RatePolicy     *RatePolicy    `json:"rate_policy,omitempty"`
	Authorization  *Authorization `json:"authorization,omitempty"`
	Now            *time.Time     `json:"now,omitempty"`
}

// Decision mirrors packages/schemas/scope-decision.schema.json.
type Decision struct {
	RequestID        string    `json:"request_id"`
	Decision         string    `json:"decision"`
	ReasonCode       string    `json:"reason_code"`
	Reason           string    `json:"reason"`
	MatchedRuleID    *string   `json:"matched_rule_id"`
	NormalizedTarget *string   `json:"normalized_target"`
	RiskFlags        []string  `json:"risk_flags"`
	ScopeVersion     int       `json:"scope_version"`
	EvaluatedAt      time.Time `json:"evaluated_at"`
}

// Approved reports whether the decision permits the operation.
func (d Decision) Approved() bool { return d.Decision == "approved" }

// Error is a scope engine failure (transport, non-200 status or bad payload).
type Error struct {
	StatusCode int
	Body       string
	Err        error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("scopesdk: %v", e.Err)
	}
	return fmt.Sprintf("scopesdk: scope engine returned HTTP %d: %s", e.StatusCode, truncate(e.Body, 200))
}

// Unwrap exposes the underlying transport error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Client calls the scope engine.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a client for baseURL.
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

// NewWithHTTPClient returns a client using a caller-supplied http.Client.
func NewWithHTTPClient(baseURL string, hc *http.Client) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc}
}

// Decide calls POST /v1/scope/decide.
func (c *Client) Decide(ctx context.Context, req Request) (Decision, error) {
	return c.post(ctx, "/v1/scope/decide", req)
}

// AuthorizeEgress calls POST /v1/egress/authorize.
func (c *Client) AuthorizeEgress(ctx context.Context, req Request) (Decision, error) {
	return c.post(ctx, "/v1/egress/authorize", req)
}

func (c *Client) post(ctx context.Context, path string, req Request) (Decision, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Decision{}, &Error{Err: fmt.Errorf("encode request: %w", err)}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return Decision{}, &Error{Err: err}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Decision{}, &Error{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Decision{}, &Error{StatusCode: resp.StatusCode, Body: string(payload)}
	}
	var decision Decision
	if err := json.Unmarshal(payload, &decision); err != nil {
		return Decision{}, &Error{StatusCode: resp.StatusCode, Body: string(payload), Err: fmt.Errorf("decode decision: %w", err)}
	}
	if decision.Decision == "" {
		return Decision{}, &Error{StatusCode: resp.StatusCode, Body: string(payload), Err: fmt.Errorf("decode decision: missing verdict")}
	}
	return decision, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
