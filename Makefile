# neutrino Makefile
#
#   make test          本机测试（单元 + e2e，串行跑）
#   make build         本机 debug 构建
#   make release       本机 release 构建
#   make clean         清理构建产物

BIN          := neutrino

.PHONY: test build release clean

test:
	# 串行跑：每个 e2e 用例都起真实 server+agent 子进程，并行时 4 核机会
	# 互相抢 CPU/网络缓冲，导致带时间窗的用例随机假红（实测约 1/10）。
	# 串行后无争抢，代价只是 e2e 从 ~28s 变 ~105s。
	cargo test -- --test-threads=1

build:
	RUSTFLAGS="-D warnings" cargo build
	@ls -lh target/debug/$(BIN)

release:
	cargo build --release
	@ls -lh target/release/$(BIN)

clean:
	cargo clean
