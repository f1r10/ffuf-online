package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ffuf-online/platform/internal/domain"
	"github.com/nats-io/nats.go"
)

// NATS is a Bus backed by a core NATS connection. Every event is JSON encoded
// and published on the subject; subscribers receive decoded domain events.
//
// Core NATS is at-most-once: an event published while no subscriber is
// connected is simply lost. The control plane therefore treats the bus as a
// notification channel and the store as the source of truth.
type NATS struct {
	conn    *nats.Conn
	logger  *slog.Logger
	mu      sync.Mutex
	subs    []*nats.Subscription
}

// NewNATS connects to url and returns a Bus.
func NewNATS(url string, logger *slog.Logger) (*NATS, error) {
	if logger == nil {
		logger = slog.Default()
	}
	conn, err := nats.Connect(url, nats.Name("ffuf-online-control-plane"), nats.MaxReconnects(-1))
	if err != nil {
		return nil, fmt.Errorf("eventbus: connect %s: %w", url, err)
	}
	return &NATS{conn: conn, logger: logger}, nil
}

// Publish implements Bus.
func (n *NATS) Publish(_ context.Context, subject string, ev domain.DomainEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("eventbus: encode event: %w", err)
	}
	if err := n.conn.Publish(subject, body); err != nil {
		return fmt.Errorf("eventbus: publish: %w", err)
	}
	return nil
}

// Subscribe implements Bus.
func (n *NATS) Subscribe(subject string, h Handler) error {
	sub, err := n.conn.Subscribe(subject, func(msg *nats.Msg) {
		var ev domain.DomainEvent
		if err := json.Unmarshal(msg.Data, &ev); err != nil {
			n.logger.Warn("eventbus: decode event failed", "subject", subject, "error", err)
			return
		}
		h(context.Background(), ev)
	})
	if err != nil {
		return fmt.Errorf("eventbus: subscribe %s: %w", subject, err)
	}
	n.mu.Lock()
	n.subs = append(n.subs, sub)
	n.mu.Unlock()
	return nil
}

// Close implements Bus.
func (n *NATS) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, sub := range n.subs {
		_ = sub.Unsubscribe()
	}
	n.subs = nil
	n.conn.Close()
	return nil
}

// NewBus returns the bus selected by kind ("inprocess" or "nats").
func NewBus(kind, natsURL string, logger *slog.Logger) (Bus, error) {
	switch kind {
	case "", "inprocess":
		return NewInProcess(logger), nil
	case "nats":
		return NewNATS(natsURL, logger)
	default:
		return nil, fmt.Errorf("eventbus: unknown driver %q", kind)
	}
}
