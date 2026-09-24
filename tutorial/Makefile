.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: actix
actix: ## Build the WASM parts and run the actix server
actix:
	cd server/actix_web && cargo run

.PHONY: axum
axum: ## Build and run the axum server, builds the WASM parts regardless.
axum:
	cd server/axum && cargo run
