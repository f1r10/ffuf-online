.PHONY: all check build test test-rust test-go test-python e2e fmt lint clean

all: check

# ---------------------------------------------------------------- build
build: build-rust build-go

build-rust:
	cd rust/scope-engine && cargo build --release

build-go:
	cd go && go build ./...

# ---------------------------------------------------------------- check
check: lint test

fmt:
	cd rust/scope-engine && cargo fmt
	cd go && go fmt ./...
	cd python && python -m ruff format . || true

lint:
	cd rust/scope-engine && cargo clippy --all-targets -- -D warnings
	cd go && go vet ./...
	cd python && python -m ruff check . || true

# ---------------------------------------------------------------- test
test: test-rust test-go test-python

test-rust:
	cd rust/scope-engine && cargo test

test-go:
	cd go && go test ./...

test-python:
	cd python && python -m pytest -q

# ---------------------------------------------------------------- e2e
e2e:
	python tests/e2e/run_pipeline.py

clean:
	cd rust/scope-engine && cargo clean
	cd go && go clean ./...
