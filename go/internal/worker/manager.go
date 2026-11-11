// Package worker implements worker selection for the dispatch loop.
//
// The selection is a pure, deterministic function of the candidate set so it
// can be unit-tested without a database or a clock: given the same workers and
// the same request it always returns the same worker.
package worker

import (
	"errors"
	"sort"
	"time"

	"github.com/ffuf-online/platform/internal/domain"
)

// ErrNoEligibleWorker is returned when no worker can run the request.
var ErrNoEligibleWorker = errors.New("worker: no eligible worker")

// StatusOnline is the worker status that makes a worker dispatchable.
const StatusOnline = "online"

// Request describes the work to place.
type Request struct {
	// TenantID is the tenant the work belongs to. A worker with an empty
	// TenantID is part of the shared platform pool and can run work for any
	// tenant; a worker with a non-empty TenantID only serves its own tenant.
	TenantID string
	// ToolID is the tool that must be installed on the worker. An empty value
	// matches every worker.
	ToolID string
	// Now is the selection time (injected for determinism).
	Now time.Time
	// HeartbeatTimeout is the maximum age of a heartbeat for a worker to be
	// considered healthy. Zero disables the freshness check.
	HeartbeatTimeout time.Duration
}

// Eligible reports whether w may run req.
//
// A worker is eligible when it is online, its heartbeat is fresh, it has the
// required tool installed and it is allowed to serve the tenant.
func Eligible(w domain.Worker, req Request) bool {
	if w.Status != StatusOnline {
		return false
	}
	if req.HeartbeatTimeout > 0 {
		if w.LastHeartbeat == nil {
			return false
		}
		if req.Now.Sub(*w.LastHeartbeat) > req.HeartbeatTimeout {
			return false
		}
	}
	if req.ToolID != "" && !domain.Contains(w.ToolIDs, req.ToolID) {
		return false
	}
	if w.TenantID != "" && w.TenantID != req.TenantID {
		return false
	}
	return true
}

// Select returns the single best eligible worker for req.
//
// Tie-break order, applied strictly in this order so the result is stable:
//
//  1. fewer running jobs (least loaded first),
//  2. then lower measured CPU load,
//  3. then a tenant-dedicated worker before a shared platform-pool worker,
//  4. then the lexicographically smallest worker id.
func Select(workers []domain.Worker, req Request) (domain.Worker, error) {
	candidates := make([]domain.Worker, 0, len(workers))
	for _, w := range workers {
		if Eligible(w, req) {
			candidates = append(candidates, w)
		}
	}
	if len(candidates) == 0 {
		return domain.Worker{}, ErrNoEligibleWorker
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.RunningJobs != b.RunningJobs {
			return a.RunningJobs < b.RunningJobs
		}
		if a.CPULoad != b.CPULoad {
			return a.CPULoad < b.CPULoad
		}
		aDedicated := a.TenantID != ""
		bDedicated := b.TenantID != ""
		if aDedicated != bDedicated {
			return aDedicated
		}
		return a.ID < b.ID
	})
	return candidates[0], nil
}
