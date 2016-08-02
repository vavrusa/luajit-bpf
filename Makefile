LUA ?= luajit

check:
	@echo "[*] static analysis"
	@luacheck --codes --formatter TAP .
	@echo "[*] unit tests"
	@busted --lua=$(LUA) -o TAP
