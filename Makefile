# neutrino Makefile
#
#   make test          本机测试（单元 + e2e）
#   make build         本机 debug 构建
#   make release       本机 release 构建
#   make linux         docker 交叉编译 x86_64 linux release（产物 target/x86_64-unknown-linux-gnu/release/neutrino）
#   make clean         清理构建产物（含 docker 卷，注意会重下依赖）

BIN          := neutrino
TARGET       := x86_64-unknown-linux-gnu
IMAGE        := rust:1.89-slim-bookworm
LINUX_OUT    := target/$(TARGET)/release/$(BIN)
CARGO_VOL    := nt-cargo-home
# crates.io 镜像（容器内更新索引用，默认中科大；改道：RSYNC_MIRROR=sparse+https://... make linux）
CRATES_MIRROR ?= sparse+https://mirrors.ustc.edu.cn/crates.io-index/

.PHONY: test build release linux clean

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
		-e CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
		$(IMAGE) \
		bash -c "mkdir -p /usr/local/cargo && printf '[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"$(CRATES_MIRROR)\"\n' > /usr/local/cargo/config.toml && cargo build --release --target $(TARGET) && ls -lh $(LINUX_OUT) && file $(LINUX_OUT)"

clean:
	cargo clean
	@echo "tip: docker volume rm $(CARGO_VOL)  # 连依赖缓存一起清"
