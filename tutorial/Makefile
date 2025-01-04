.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: wasm
wasm: ## build the WASM parts
wasm:
	cd wasm && ./build.sh

.PHONY: actix
actix: ## Build the WASM parts and run the actix server
actix: wasm
	cd server/actix_web && cargo run

.PHONY: axum
axum: ## Build and run the axum server, builds the WASM parts regardless.
axum:
	cd server/axum && ./build_wasm.sh
	cd server/axum && cargo run

.PHONY: tide
tide: ## Build and run the tide server
tide: wasm
	cd server/tide && cargo run
