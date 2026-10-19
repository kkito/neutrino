# neutrino Makefile
#
#   make test          本机测试（单元 + e2e）
#   make build         本机 debug 构建
#   make release       本机 release 构建
#   make clean         清理构建产物

BIN          := neutrino

.PHONY: test build release clean

test:
	cargo test

build:
	cargo build
	@ls -lh target/debug/$(BIN)

release:
	cargo build --release
	@ls -lh target/release/$(BIN)

clean:
	cargo clean
