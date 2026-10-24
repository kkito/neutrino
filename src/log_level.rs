//! 动态日志级别（spec §16.5）。
//!
//! 为什么需要：流收尾等排查日志是 DEBUG 级，默认 `RUST_LOG=info` 看不到；
//! 但生产上为了开 debug 去改 systemd Environment 再 restart，会掐掉所有正在
//! 进行的 UDP 会话，等于把要观测的现象消灭掉。
//!
//! 为什么用信号不用 HTTP：agent 当前无 WebUI（`--server` 直连），HTTP 对它
//! 不可用；信号两端对称、零配置、无需认证。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// DEBUG 窗口时长（spec §16.5 ⑦：不限时会让 DEBUG 撑爆 journald）。
pub(crate) const DEBUG_WINDOW: Duration = Duration::from_secs(60);

/// 启动时的级别（= RUST_LOG 解析后的基准）。恢复目标必须是它而不是硬编码
/// "info"——用户若用 `RUST_LOG=neutrino::agent=debug` 启动，USR2 应回到那个值。
static BASE_LEVEL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
/// 当前窗口的代际计数：每次 USR1/USR2 自增，旧的 restore 任务看到代际不符就退出。
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// 记录启动时的基准级别（main 里 install 后调用一次）。
pub(crate) fn set_base(level: &str) {
    let _ = BASE_LEVEL.set(level.to_string());
}

/// 恢复目标：基准级别；未初始化时回退 "info"。
pub(crate) fn restore_target() -> &'static str {
    BASE_LEVEL.get().map(|s| s.as_str()).unwrap_or("info")
}

/// 启动 banner 的那行提示（spec §16.5 ⑤：信号开关最大的问题是没人知道它存在）。
/// 抽成纯函数便于单测——banner 文本里少写一个信号，运维就永远只会用一半功能。
pub(crate) fn hint_line(available: bool, level: &str) -> String {
    if available {
        format!(
            "  log level    : {level}  →  kill -USR1 <pid> 临时开 DEBUG {}s；kill -USR2 <pid> 提前恢复",
            DEBUG_WINDOW.as_secs()
        )
    } else {
        "  log level    : 信号开关不可用（signal() 注册失败），请用 RUST_LOG 环境变量".to_string()
    }
}

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

/// 可换 filter 的句柄。install() 后存进这里，信号处理与运行期调级共用。
static HANDLE: std::sync::OnceLock<reload::Handle<EnvFilter, tracing_subscriber::Registry>> =
    std::sync::OnceLock::new();

/// 初始化日志：读 RUST_LOG（缺省 info），与旧的 `fmt().with_env_filter().init()`
/// 行为一致，额外多一个能换 filter 的把手。
pub(crate) fn install() {
    let env = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let filter = EnvFilter::try_new(&env).unwrap_or_else(|_| EnvFilter::new("info"));
    let (layer, handle) = reload::Layer::new(filter);
    // stdout 时间戳用本地 wall clock（默认 SystemTime 打 UTC，如 HKT 机器 18:00 打成 10:00Z）。
    let timer = tracing_subscriber::fmt::time::ChronoLocal::new(
        "%Y-%m-%dT%H:%M:%S%.3f%:z".to_string(),
    );
    tracing_subscriber::registry()
        .with(layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_timer(timer),
        )
        .init();
    let _ = HANDLE.set(handle);
    set_base(&env);
}

/// 换级别。失败（句柄未初始化 / filter 语法错）返回 false，调用方应 warn。
pub(crate) fn set_level(spec: &str) -> bool {
    match HANDLE.get() {
        Some(h) => h
            .reload(EnvFilter::try_new(spec).unwrap_or_else(|_| EnvFilter::new("info")))
            .is_ok(),
        None => false,
    }
}

/// 注册 SIGUSR1 / SIGUSR2。返回 false = 注册失败，调用方必须 warn，
/// 并把 banner 改成「不可用」——**失败时结不能假装能发信号**：
/// SIGUSR1 的默认行为是终止进程，运维照着 banner 发一下就把服务打死了。
#[cfg(unix)]
pub(crate) fn spawn_signal_handler() -> bool {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut usr1, mut usr2) = match (
        signal(SignalKind::user_defined1()),
        signal(SignalKind::user_defined2()),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    // 注册即接管默认行为（默认是终止进程）；这条 tokio::spawn 的任务不会被 await，
    // 进程生命周期内一直跑。
    tokio::spawn(async move {
        let mut restore: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            tokio::select! {
                _ = usr1.recv() => {
                    // 重复 USR1 要覆盖旧计时器：不 abort 会积累 N 个 restore 任务，
                    // 第一个到期就把级别打回去，窗口远短于 60s。
                    if let Some(h) = restore.take() { h.abort(); }
                    let gen = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
                    if set_level("debug") {
                        tracing::info!(
                            "log level -> debug for {}s (SIGUSR1)",
                            DEBUG_WINDOW.as_secs()
                        );
                    } else {
                        tracing::warn!("log level reload failed (SIGUSR1)");
                    }
                    let target = restore_target().to_string();
                    restore = Some(tokio::spawn(async move {
                        tokio::time::sleep(DEBUG_WINDOW).await;
                        // 代际不符 = 期间又按过 USR1 或 USR2，让位给更新的任务
                        if GENERATION.load(Ordering::SeqCst) != gen {
                            return;
                        }
                        if set_level(&target) {
                            tracing::info!(
                                "log level restored to {target} after {}s",
                                DEBUG_WINDOW.as_secs()
                            );
                        }
                    }));
                }
                _ = usr2.recv() => {
                    if let Some(h) = restore.take() { h.abort(); }
                    GENERATION.fetch_add(1, Ordering::SeqCst);
                    let target = restore_target().to_string();
                    if set_level(&target) {
                        tracing::info!("log level restored to {target} early (SIGUSR2)");
                    }
                }
            }
        }
    });
    true
}

/// 非 unix：没有 SIGUSR1/2，直接不可用。
#[cfg(not(unix))]
pub(crate) fn spawn_signal_handler() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 恢复目标必须是启动值，不能是硬编码 "info"（spec §16.5 ④ 要点 2）。
    #[test]
    fn log_level_restore_target_is_startup_value() {
        set_base("neutrino=debug");
        assert_eq!(
            restore_target(),
            "neutrino=debug",
            "restore_target 必须返回 set_base 传入的值，硬编码 info 会把用户自己开的模块级 debug 也关掉"
        );
    }

    /// banner 必须同时提到两个信号，否则运维只会用一半功能（spec §16.5 ⑤）。
    #[test]
    fn log_level_hint_line_names_both_signals() {
        let h = hint_line(true, "info");
        assert!(h.contains("-USR1"), "banner 缺 SIGUSR1: {h}");
        assert!(h.contains("-USR2"), "banner 缺 SIGUSR2: {h}");
        assert!(h.contains("60"), "banner 必须写明窗口秒数: {h}");
    }

    /// 注册失败时必须明说不可用，而不是照打一句"能用"（否则运维 kill 一下进程就死了）。
    #[test]
    fn log_level_hint_line_warns_when_unavailable() {
        let h = hint_line(false, "info");
        assert!(h.contains("不可用"), "注册失败必须提示不可用: {h}");
        assert!(!h.contains("-USR1"), "不可用时不该教用户发信号: {h}");
    }
}
