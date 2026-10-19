# neutrino Makefile
#
#   make test          本机测试（单元 + e2e）
#   make build         本机 debug 构建
#   make release       本机 release 构建
#   make linux         docker 交叉编译 x86_64 linux release（产物 target/x86_64-unknown-linux-gnu/release/neutrino）
#   make linux-detach  后台跑 linux 编译（输出长时间时用），日志 .build-linux.log
#   make linux-log     看后台编译日志
#   make clean         清理构建产物（含 docker 卷，注意会重下依赖）

BIN          := neutrino
TARGET       := x86_64-unknown-linux-gnu
IMAGE        := rust:1.89-slim-bookworm
LINUX_OUT    := target/$(TARGET)/release/$(BIN)
CARGO_VOL    := nt-cargo-home
BUILD_CTN    := nt-release

.PHONY: test build release linux linux-detach linux-log clean

test:
	cargo test

build:
	cargo build

release:
	cargo build --release

linux:
	docker run --rm --platform linux/amd64 \
		-v "$(PWD):/src" -w /src \
		-v $(CARGO_VOL):/usr/local/cargo \
		$(IMAGE) \
		bash -c "cargo build --release --target $(TARGET) && ls -lh $(LINUX_OUT) && file $(LINUX_OUT)"

linux-detach:
	docker run -d --platform linux/amd64 \
		--name $(BUILD_CTN) \
		-v "$(PWD):/src" -w /src \
		-v $(CARGO_VOL):/usr/local/cargo \
		$(IMAGE) \
		bash -c "cargo build --release --target $(TARGET)"
	@echo "building in background: make linux-log"

linux-log:
	docker logs -f $(BUILD_CTN)

clean:
	cargo clean
	-docker rm -f $(BUILD_CTN)
	@echo "tip: docker volume rm $(CARGO_VOL)  # 连依赖缓存一起清"
