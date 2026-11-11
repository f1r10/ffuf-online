// Package config loads the control-plane configuration from the environment.
//
// Defaults mirror `.env.example`; nothing is read from files so a container can
// be configured purely through its environment.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved control-plane configuration.
type Config struct {
	// APIAddr is the listen address of the HTTP API (default ":8080").
	APIAddr string
	// APIPublicURL is the externally reachable base URL of this API.
	APIPublicURL string
	// WorkerManagerAddr is the listen address of the worker-manager health
	// endpoint (default ":8081").
	WorkerManagerAddr string

	// Storage selects the persistence driver: "memory" or "postgres".
	Storage string
	// EventBus selects the event bus driver: "inprocess" or "nats".
	EventBus string
	// Dispatch selects the worker dispatch driver: "memory" or "nats".
	Dispatch string

	// JWTSecret signs user session tokens (HS256).
	JWTSecret string
	// JWTTTL is the session lifetime.
	JWTTTL time.Duration

	// JobSigningSecret signs worker jobs (HMAC-SHA256 over canonical JSON).
	JobSigningSecret string
	// JobTTL is how long a dispatched job stays valid.
	JobTTL time.Duration

	// DatabaseURL is the Postgres DSN used when Storage == "postgres".
	DatabaseURL string
	// NATSURL is the NATS server URL used when a bus uses nats.
	NATSURL string

	// ScopeEngineURL is the HTTP base URL of the Rust scope engine.
	ScopeEngineURL string
	// ScopeEngineBin is the compiled Rust binary path (informational).
	ScopeEngineBin string

	// IntelURL is the base URL of the Python intelligence engine.
	IntelURL string

	// ServiceToken, when set, is required in the X-Service-Token header for
	// machine-to-machine ingestion endpoints. Empty disables the check (dev).
	ServiceToken string

	// ToolRegistryPath is the path of the tool registry JSON. LoadToolRegistry
	// falls back to a built-in list when the file is missing.
	ToolRegistryPath string

	// ScopeTimeout bounds a single call to the Rust scope engine.
	ScopeTimeout time.Duration
	// WorkerHeartbeatTimeout is the age after which a worker is considered
	// offline.
	WorkerHeartbeatTimeout time.Duration
}

// Load reads the configuration from the process environment, applying the
// documented defaults, and validates it.
func Load() (Config, error) {
	ttlMinutes, err := envInt("JWT_TTL_MINUTES", 720)
	if err != nil {
		return Config{}, err
	}
	jobTTLSeconds, err := envInt("JOB_TTL_SECONDS", 300)
	if err != nil {
		return Config{}, err
	}

	c := Config{
		APIAddr:                env("API_ADDR", ":8080"),
		APIPublicURL:           env("API_PUBLIC_URL", "http://localhost:8080"),
		WorkerManagerAddr:      env("WORKER_MANAGER_ADDR", ":8081"),
		Storage:                strings.ToLower(env("STORAGE", "memory")),
		EventBus:               strings.ToLower(env("EVENT_BUS", "inprocess")),
		Dispatch:               strings.ToLower(env("DISPATCH", "memory")),
		JWTSecret:              env("JWT_SECRET", "dev-only-change-me"),
		JWTTTL:                 time.Duration(ttlMinutes) * time.Minute,
		JobSigningSecret:       env("JOB_SIGNING_SECRET", "dev-only-change-me-too"),
		JobTTL:                 time.Duration(jobTTLSeconds) * time.Second,
		DatabaseURL:            env("DATABASE_URL", "postgres://ffuf:ffuf@localhost:5432/ffuf_online?sslmode=disable"),
		NATSURL:                env("NATS_URL", "nats://localhost:4222"),
		ScopeEngineURL:         strings.TrimRight(env("SCOPE_ENGINE_URL", "http://localhost:8090"), "/"),
		ScopeEngineBin:         env("SCOPE_ENGINE_BIN", filepath.FromSlash("rust/scope-engine/target/release/scope-engine")),
		IntelURL:               strings.TrimRight(env("INTEL_URL", "http://127.0.0.1:8091"), "/"),
		ServiceToken:           env("SERVICE_TOKEN", ""),
		ToolRegistryPath:       env("TOOL_REGISTRY_PATH", ""),
		ScopeTimeout:           10 * time.Second,
		WorkerHeartbeatTimeout: 60 * time.Second,
	}
	if c.ToolRegistryPath == "" {
		c.ToolRegistryPath = findToolRegistry()
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate rejects configurations that cannot work.
func (c Config) Validate() error {
	switch c.Storage {
	case "memory", "postgres":
	default:
		return fmt.Errorf("config: STORAGE must be memory or postgres, got %q", c.Storage)
	}
	switch c.EventBus {
	case "inprocess", "nats":
	default:
		return fmt.Errorf("config: EVENT_BUS must be inprocess or nats, got %q", c.EventBus)
	}
	switch c.Dispatch {
	case "memory", "nats":
	default:
		return fmt.Errorf("config: DISPATCH must be memory or nats, got %q", c.Dispatch)
	}
	if c.JWTSecret == "" {
		return fmt.Errorf("config: JWT_SECRET must not be empty")
	}
	if c.JobSigningSecret == "" {
		return fmt.Errorf("config: JOB_SIGNING_SECRET must not be empty")
	}
	if c.Storage == "postgres" && c.DatabaseURL == "" {
		return fmt.Errorf("config: DATABASE_URL is required when STORAGE=postgres")
	}
	if c.APIAddr == "" {
		return fmt.Errorf("config: API_ADDR must not be empty")
	}
	return nil
}

// UsesDefaultSecrets reports whether the process is running with the shipped
// development secrets. containers use it to decide how loudly to warn.
func (c Config) UsesDefaultSecrets() bool {
	return c.JWTSecret == "dev-only-change-me" || c.JobSigningSecret == "dev-only-change-me-too"
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer: %w", key, err)
	}
	return n, nil
}

// findToolRegistry looks for python/adapters/tool-registry.json relative to the
// working directory (and a couple of parent directories) so both
// `go run ./cmd/api` from go/ and a run from the repository root find it.
func findToolRegistry() string {
	candidates := []string{
		filepath.Join("python", "adapters", "tool-registry.json"),
		filepath.Join("..", "python", "adapters", "tool-registry.json"),
		filepath.Join("..", "..", "python", "adapters", "tool-registry.json"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}
