.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

wasm: ## build the WASM parts
wasm:
	cd wasm && ./build.sh

actix: ## Build the WASM parts and run the actix server
actix: wasm
	cd server/actix_web && cargo run