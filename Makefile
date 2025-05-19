start:
	@spacetime start

publish:
	@spacetime publish --project-path server quickstart-chat

logs:
	@spacetime logs quickstart-chat

generate:
	@mkdir -p client/src/module_bindings
	@spacetime generate --lang rust --out-dir client/src/module_bindings --project-path server

run:
	@cargo run -p client