// Package eventbus carries ingested domain events to subscribers and to the
// Python intelligence engine.
package eventbus

import (
	"context"

	"github.com/ffuf-online/platform/internal/domain"
)

// Subjects used on the bus.
const (
	// SubjectEvents carries every ingested DomainEvent.
	SubjectEvents = "ffuf.events"
	// SubjectDispatch carries task-created notifications for worker agents.
	SubjectDispatch = "ffuf.dispatch"
)

// Handler consumes a domain event.
type Handler func(ctx context.Context, ev domain.DomainEvent)

// Bus publishes and subscribes to domain events.
type Bus interface {
	// Publish delivers ev to subject. It must not block indefinitely.
	Publish(ctx context.Context, subject string, ev domain.DomainEvent) error
	// Subscribe registers h for subject.
	Subscribe(subject string, h Handler) error
	// Close releases any resources held by the bus.
	Close() error
}

// Nop is a Bus that discards everything. Used in tests and when no bus is
// configured.
type Nop struct{}

// Publish implements Bus.
func (Nop) Publish(context.Context, string, domain.DomainEvent) error { return nil }

// Subscribe implements Bus.
func (Nop) Subscribe(string, Handler) error { return nil }

// Close implements Bus.
func (Nop) Close() error { return nil }
