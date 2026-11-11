package eventbus

import (
	"context"
	"log/slog"
	"sync"

	"github.com/ffuf-online/platform/internal/domain"
)

// InProcess is a thread-safe, synchronous fan-out bus. Handlers are invoked in
// registration order; a panicking handler is contained and logged so one
// subscriber can never take down ingestion.
type InProcess struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
	logger   *slog.Logger
}

// NewInProcess returns an empty in-process bus.
func NewInProcess(logger *slog.Logger) *InProcess {
	if logger == nil {
		logger = slog.Default()
	}
	return &InProcess{handlers: make(map[string][]Handler), logger: logger}
}

// Publish implements Bus.
func (b *InProcess) Publish(ctx context.Context, subject string, ev domain.DomainEvent) error {
	b.mu.RLock()
	hs := append([]Handler(nil), b.handlers[subject]...)
	b.mu.RUnlock()
	for _, h := range hs {
		b.safeInvoke(ctx, h, ev)
	}
	return nil
}

// Subscribe implements Bus.
func (b *InProcess) Subscribe(subject string, h Handler) error {
	if h == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[subject] = append(b.handlers[subject], h)
	return nil
}

// Close implements Bus.
func (b *InProcess) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = make(map[string][]Handler)
	return nil
}

func (b *InProcess) safeInvoke(ctx context.Context, h Handler, ev domain.DomainEvent) {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error("eventbus handler panicked", "subject", SubjectEvents, "error", r)
		}
	}()
	h(ctx, ev)
}
