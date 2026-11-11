package eventbus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ffuf-online/platform/internal/domain"
)

// Forwarder POSTs every ingested event to the Python intelligence engine.
//
// Forwarding is strictly best-effort: it never blocks the caller for longer
// than the configured timeout and never turns a failure into a request error.
type Forwarder struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

// NewForwarder returns a Forwarder for the intelligence engine base URL. An
// empty url disables forwarding (Forward becomes a no-op that reports false).
func NewForwarder(url string, timeout time.Duration, logger *slog.Logger) *Forwarder {
	if logger == nil {
		logger = slog.Default()
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Forwarder{
		url:    url,
		client: &http.Client{Timeout: timeout},
		logger: logger,
	}
}

// Enabled reports whether a target URL is configured.
func (f *Forwarder) Enabled() bool { return f.url != "" }

// Forward posts ev to {INTEL_URL}/v1/events. It returns an error only for
// logging purposes; callers must ignore it.
func (f *Forwarder) Forward(ctx context.Context, ev domain.DomainEvent) error {
	if f.url == "" {
		return nil
	}
	body, err := json.Marshal(ev)
	if err != nil {
		f.logger.Warn("intel forward: encode event failed", "event_id", ev.EventID, "error", err)
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url+"/v1/events", bytes.NewReader(body))
	if err != nil {
		f.logger.Warn("intel forward: build request failed", "event_id", ev.EventID, "error", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		f.logger.Warn("intel forward: request failed", "event_id", ev.EventID, "error", err)
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		err = fmt.Errorf("intel engine returned HTTP %d", resp.StatusCode)
		f.logger.Warn("intel forward: rejected", "event_id", ev.EventID, "status", resp.StatusCode)
		return err
	}
	return nil
}
