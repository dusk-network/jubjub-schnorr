help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: ## Run tests (all features, release mode)
	@cargo test --features zk,alloc,serde --release
	@cargo test --no-default-features
	@cargo test --features alloc --no-run

clippy: ## Run clippy
	@cargo clippy --features rkyv/size_32,zk,serde -- -D warnings

cq: ## Run code quality checks (formatting + clippy)
	@$(MAKE) fmt CHECK=1
	@$(MAKE) clippy

fmt: ## Format code
	@rustup component add --toolchain nightly rustfmt 2>/dev/null || true
	@cargo +nightly fmt --all $(if $(CHECK),-- --check,)

check: ## Type-check
	@cargo check --features zk,alloc,serde

doc: ## Generate docs
	@cargo doc --no-deps

build-benches: ## Build benchmarks
	@cargo bench --no-run --features zk

no-std: ## Verify no_std + WASM compatibility
	@rustup target add wasm32-unknown-unknown 2>/dev/null || true
	@cargo build --release --no-default-features --features serde --target wasm32-unknown-unknown

clean: ## Clean build artifacts
	@cargo clean

.PHONY: help test clippy cq fmt check doc build-benches no-std clean
