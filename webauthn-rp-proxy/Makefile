all: register-start register-finish authenticate-start authenticate-finish authenticate-finish-fail

register-start:
	cat test-data/register-start.json | cargo run -- --pretty-print register-start

register-finish:
	cat test-data/register-finish.json | cargo run -- --pretty-print register-finish

authenticate-start:
	cat test-data/authenticate-start.json | cargo run -- --pretty-print authenticate-start

authenticate-finish:
	cat test-data/authenticate-finish.json | cargo run -- --pretty-print authenticate-finish

authenticate-finish-fail:
	cat test-data/authenticate-finish-fail.json | cargo run -- --pretty-print authenticate-finish
