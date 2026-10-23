//! 映射级总量下行限速：sleep 截流（方案 B）。burst-sleep 锯齿可接受；
//! 以后换令牌桶时配置格式不变，只换此文件内部（spec 预留切换点）。
use crate::server::state::S;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 单块 sleep 量：应耗时 - 已用， clamp 到 0。
/// 根因→修法：纯函数可单测，泵里只调它 + sleep，不手算。
pub fn throttle_sleep(chunk: usize, limit_bps: u64, elapsed: Duration) -> Duration {
    if chunk == 0 || limit_bps == 0 {
        return Duration::ZERO;
    }
    let want = Duration::from_secs_f64(chunk as f64 / limit_bps as f64);
    want.checked_sub(elapsed).unwrap_or(Duration::ZERO)
}

/// 映射级共享窗口：1s 滑动，记（窗口起始，已传字节）。
/// 同映射所有连接共用一个，超了大家一起等 = 总量语义。
pub struct RateWindow {
    start: Instant,
    bytes: u64,
}

impl RateWindow {
    pub fn new() -> Self {
        Self { start: Instant::now(), bytes: 0 }
    }
    /// 累进 n 字节，返回本块应 sleep 量（调用方负责 sleep）。窗口超 1s 即重置。
    pub fn take(&mut self, n: usize, limit_bps: u64) -> Duration {
        if limit_bps == 0 || n == 0 {
            return Duration::ZERO;
        }
        let now = Instant::now();
        if now.duration_since(self.start) >= Duration::from_secs(1) {
            self.start = now;
            self.bytes = 0;
        }
        self.bytes += n as u64;
        // 窗口累计应耗时 - 窗口已流逝 = 本块补睡量
        let want = Duration::from_secs_f64(self.bytes as f64 / limit_bps as f64);
        want.checked_sub(now.duration_since(self.start)).unwrap_or(Duration::ZERO)
    }
}

impl Default for RateWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// 映射级 limiter：limit 可热更新（desired 重载后新值覆盖），窗口共享。
pub struct RateLimiter {
    limit: AtomicU64,
    win: tokio::sync::Mutex<RateWindow>,
    throttled_bytes: AtomicU64,
    sleep_millis: AtomicU64,
}

impl RateLimiter {
    pub fn new(limit_bps: u64) -> Self {
        Self { limit: AtomicU64::new(limit_bps), win: tokio::sync::Mutex::new(RateWindow::new()), throttled_bytes: AtomicU64::new(0), sleep_millis: AtomicU64::new(0) }
    }
    /// 纯算 sleep 量（不 sleep，调用方 sleep；零开销路径：limit==0 直接 ZERO 不锁）。
    pub async fn take(&self, n: usize) -> Duration {
        let lim = self.limit.load(Ordering::Relaxed);
        if lim == 0 || n == 0 {
            return Duration::ZERO;
        }
        let d = self.win.lock().await.take(n, lim);
        self.throttled_bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.sleep_millis.fetch_add(d.as_millis() as u64, Ordering::Relaxed);
        d
    }
    /// (limit, 经手字节累计, 累计 sleep 毫秒)——供 /api/tunnels + 周期日志验证限速生效。
    /// try_stats：非阻塞快照（/api/tunnels+overview 热路径用）。
    /// BT flood 高 pps 下 N 个转发泵在 take() 里排队等 win 锁，stats() 若再
    /// 阻塞等同一把锁，读会叠进队尾、agents.read() 饿死、API 10s 超时
    /// （2026-10-23 HK 现场：live/conns/traffic 1ms 正常，唯 tunnels/overview 卡死）。
    /// win.try_lock 拿不到即返回预算值（limit, throttled, sleep），不歪曲、不等待。
    pub fn try_stats(&self) -> (u64, u64, u64) {
        (
            self.limit.load(Ordering::Relaxed),
            self.throttled_bytes.load(Ordering::Relaxed),
            self.sleep_millis.load(Ordering::Relaxed),
        )
    }
    pub fn stats(&self) -> (u64, u64, u64) {
        (self.limit.load(Ordering::Relaxed), self.throttled_bytes.load(Ordering::Relaxed), self.sleep_millis.load(Ordering::Relaxed))
    }
    pub fn set_limit(&self, v: u64) {
        self.limit.store(v, Ordering::Relaxed);
    }
}

/// 同 key 复用 limiter（key=`traffic_key(hostname,proxy名)`），limit 变化时更新。
/// 根因→修法：limiter 常驻内存，desired 热更新只改 limit 不丢窗口，避免重置漂移。
pub(crate) async fn limiter_for(s: &S, key: &str, limit_bps: u64) -> Arc<RateLimiter> {
    if let Some(l) = s.rate_limiters.read().await.get(key) {
        l.set_limit(limit_bps);
        return l.clone();
    }
    let l = Arc::new(RateLimiter::new(limit_bps));
    s.rate_limiters.write().await.insert(key.to_string(), l.clone());
    l
}

/// 配置字符串 -> limiter（None = 不限速，调用方分支跳过不建窗口，零开销）。
/// 非法值 warn + None（配置文件手滑不能把隧道搞挂）。
pub fn limit_of(opt: Option<&str>) -> Option<u64> {
    let raw = opt.unwrap_or("").trim();
    if raw.is_empty() {
        return None;
    }
    match crate::common::proto::parse_rate_limit(raw) {
        Some(v) => Some(v),
        None => {
            tracing::warn!("rate_limit '{raw}' 非法，已忽略当不限速");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn try_stats_never_blocks_on_hot_window() {
        // HK 2026-10-23：BT flood 下 N 个泵在 take() 里等 win 锁，
        // /api/tunnels 的 stats() 若阻塞等同一把锁即叠进队尾 -> 10s 超时。
        // try_stats 必须零等待：即使窗口锁被占也立刻返回预算值。
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let l = std::sync::Arc::new(super::RateLimiter::new(1024));
            let _guard = l.win.lock().await; // 模拟 flood：窗口锁被泵占住
            let t0 = std::time::Instant::now();
            let (limit, bytes, sleep_ms) = l.try_stats();
            assert!(t0.elapsed() < std::time::Duration::from_millis(50)); // 零等待
            assert_eq!((limit, bytes, sleep_ms), (1024, 0, 0)); // 预算值，不歪曲
        });
    }
    #[test]
    fn limiter_stats_counters() {
        // 可观测回归：take 累计经手字节 + sleep 量；零 limit/零字节不计数。
        // RED 现场：旧 RateLimiter 无 stats 方法，编译即红。
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let l = super::RateLimiter::new(10 * 1024 * 1024);
            let d = l.take(32 * 1024).await;
            let (limit, bytes, sleep_ms) = l.stats();
            assert_eq!(limit, 10 * 1024 * 1024);
            assert_eq!(bytes, 32 * 1024);
            assert_eq!(sleep_ms, d.as_millis() as u64);
            // 零字节不计数
            let _ = l.take(0).await;
            assert_eq!(l.stats().1, 32 * 1024);
        });
        let zero = super::RateLimiter::new(0);
        let rt2 = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt2.block_on(async {
            assert_eq!(zero.take(100).await, std::time::Duration::ZERO);
            assert_eq!(zero.stats(), (0, 0, 0));
        });
    }
    #[test]
    fn sleep_math_clamps_at_zero() {
        // 32KB 块 @0.5MB/s 理论 62.5ms；已用 10ms -> 睡 52.5ms；已超时 -> 0
        let d = super::throttle_sleep(32 * 1024, 524288, Duration::from_millis(10));
        assert!(d >= Duration::from_millis(50) && d <= Duration::from_millis(55));
        assert_eq!(super::throttle_sleep(100, 1024 * 1024 * 1024, Duration::from_secs(1)), Duration::ZERO);
        assert_eq!(super::throttle_sleep(0, 100, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn window_slides_each_second() {
        // 同窗口累积：第 2 块要补睡；窗口过期后重置不清零漂移
        let mut w = super::RateWindow::new();
        let lim = 1000u64; // 1KB/s
        let d1 = w.take(600, lim); // 首块 600B -> 应睡 600ms
        assert!(d1 >= Duration::from_millis(590));
        let d2 = w.take(600, lim); // 累计 1200B/窗口 -> 补到 1200ms
        assert!(d2 >= Duration::from_millis(590));
        std::thread::sleep(Duration::from_millis(1100));
        let d3 = w.take(600, lim); // 新窗口 -> 回到 600ms
        assert!(d3 < Duration::from_millis(700));
    }
}
