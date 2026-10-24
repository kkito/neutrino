//! UDP 出站 socket 池：纯逻辑（零 IO），只管 sid ↔ 槽位的账。
//!
//! 背景（2026-10-23 事故）：旧实现一个 sid 独占一个 socket，用
//! `Semaphore(256)` 限并发，打满就**直接拒绝新流**——DHT 扫描下所有
//! 新 peer 全断，且 `udp` 与 `link_udp` 共用一个信号量会互相饿死。
//!
//! 根因→修法：改为固定容量的池 + LRU 复用。socket 数只与「同时在等回包
//! 的会话数」相关，与「累计会话数」无关。池满时踢最久未活跃的 sid
//! （发 Close + 归还槽位），新会话总能进。
//!
//! 为何必须多 socket（不能共享一个）：UDP 回包不带会话标识，目标服务
//! 回包时只有源地址可区分归属，所以必须靠不同源端口 = 不同 socket。
//! 这不是设计选择，是 UDP 语义强制。

/// 池类别：udp 与 link_udp 各自独立一个池，互不抢占。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolKind {
    Udp,
    LinkUdp,
}

/// 池初始容量（起步值，按需扩容）。
pub const POOL_INIT: usize = 64;
/// 池扩容硬上限。超过则踢 LRU。
pub const POOL_MAX: usize = 512;

/// acquire 的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Acquire {
    /// 分到槽位号（0..cap）。
    Slot(usize),
    /// 池满，踢掉了这个 sid（调用方需给它发 Close）。
    Evicted(u32),
}

pub struct UdpPool {
    kind: PoolKind,
    /// 已创建的槽位总数（= 曾扩容到的最大并发）。
    created: usize,
    /// 空闲槽位号。
    idle: Vec<usize>,
    /// sid → 槽位号。
    in_use: std::collections::HashMap<u32, usize>,
    /// 最近使用顺序：头部最久未用。
    lru: std::collections::VecDeque<u32>,
    /// 累计踢流次数（观测）。
    evicted_total: u64,
}

impl UdpPool {
    pub fn new(kind: PoolKind) -> Self {
        Self {
            kind,
            created: 0,
            idle: Vec::new(),
            in_use: std::collections::HashMap::new(),
            lru: std::collections::VecDeque::new(),
            evicted_total: 0,
        }
    }
    /// 池类别。
    pub fn kind(&self) -> PoolKind {
        self.kind
    }
    /// 已创建的槽位总数。
    pub fn created(&self) -> usize {
        self.created
    }
    /// 正在使用的 sid 数。
    pub fn in_use_len(&self) -> usize {
        self.in_use.len()
    }
    /// 空闲槽位数。
    pub fn idle_len(&self) -> usize {
        self.idle.len()
    }
    /// 该 sid 当前占用的槽位号。
    pub fn slot_of(&self, sid: u32) -> Option<usize> {
        self.in_use.get(&sid).copied()
    }
    /// sid 是否在池中。
    pub fn contains(&self, sid: u32) -> bool {
        self.in_use.contains_key(&sid)
    }
    /// 累计踢流次数。
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total
    }
    /// 分配一个槽位给 sid。见 [`Acquire`]。
    pub fn acquire(&mut self, sid: u32) -> Acquire {
        // 已有则直接返回原槽位（重复 Open 幂等）。
        if let Some(&slot) = self.in_use.get(&sid) {
            self.touch(sid);
            return Acquire::Slot(slot);
        }
        // 1) 有空闲槽位 → 复用
        if let Some(slot) = self.idle.pop() {
            self.in_use.insert(sid, slot);
            self.lru.push_back(sid);
            return Acquire::Slot(slot);
        }
        // 2) 还能扩容 → 新建
        if self.created < POOL_MAX {
            let slot = self.created;
            self.created += 1;
            self.in_use.insert(sid, slot);
            self.lru.push_back(sid);
            return Acquire::Slot(slot);
        }
        // 3) 满 → 踢 LRU
        let victim = self.lru.pop_front().expect("池满时 lru 不应为空");
        let slot = self.in_use.remove(&victim).expect("lru 里的 sid 必须在 in_use");
        self.evicted_total += 1;
        self.in_use.insert(sid, slot);
        self.lru.push_back(sid);
        Acquire::Evicted(victim)
    }
    /// 归还 sid 的槽位。
    pub fn release(&mut self, sid: u32) {
        if let Some(slot) = self.in_use.remove(&sid) {
            self.idle.push(slot);
            self.lru.retain(|&s| s != sid);
        }
    }
    /// 标记 sid 最近活跃（移到 LRU 尾部）。
    pub fn touch(&mut self, sid: u32) {
        if self.in_use.contains_key(&sid) {
            self.lru.retain(|&s| s != sid);
            self.lru.push_back(sid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 空池首次 acquire：扩容出一个槽位。
    #[test]
    fn pool_allocates_first_slot() {
        let mut p = UdpPool::new(PoolKind::Udp);
        assert_eq!(p.created(), 0);
        assert_eq!(p.acquire(100), Acquire::Slot(0));
        assert_eq!(p.created(), 1, "首次 acquire 应扩容出 1 个槽位");
        assert_eq!(p.in_use_len(), 1);
    }

    /// 归还后再 acquire 必须复用槽位，不能扩容。
    #[test]
    fn pool_reuses_idle_socket() {
        let mut p = UdpPool::new(PoolKind::Udp);
        assert_eq!(p.acquire(100), Acquire::Slot(0));
        let created_after_first = p.created();
        p.release(100);
        assert_eq!(p.in_use_len(), 0);
        assert_eq!(p.acquire(200), Acquire::Slot(0));
        assert_eq!(
            p.created(),
            created_after_first,
            "归还后应按复用槽位，不该再扩容"
        );
    }

    /// 扩容到 POOL_MAX 为止，未超上限不该踢流。
    #[test]
    fn pool_grows_up_to_max() {
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            assert!(matches!(p.acquire(sid), Acquire::Slot(_)), "未到上限不应踢流");
        }
        assert_eq!(p.created(), POOL_MAX);
        assert_eq!(p.in_use_len(), POOL_MAX);
        assert_eq!(p.evicted_total(), 0, "未超上限不该有踢流");
    }

    /// reuse 必须真的走 idle 列表（而不是碰巧返回同一槽位）。
    #[test]
    fn pool_reuse_actually_uses_idle_list() {
        let mut p = UdpPool::new(PoolKind::Udp);
        p.acquire(1);
        p.acquire(2);
        assert_eq!(p.created(), 2);
        p.release(1);
        assert_eq!(p.idle_len(), 1, "release 后应有 1 个空闲槽位");
        p.acquire(3);
        assert_eq!(p.created(), 2, "不应扩容");
        assert_eq!(p.idle_len(), 0, "idle 应被取空");
    }

    /// 池满时踢最久未用的 sid，新 sid 必须能进。
    #[test]
    fn pool_evicts_lru_when_full() {
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            p.acquire(sid);
        }
        let out = p.acquire(9999);
        assert_eq!(out, Acquire::Evicted(0), "池满应踢最久未用的 sid=0");
        assert_eq!(p.evicted_total(), 1);
        assert_eq!(p.in_use_len(), POOL_MAX, "踢一个进一个，总数不变");
        assert!(p.contains(9999), "新 sid 必须能进");
        assert!(!p.contains(0), "被踢的 sid 必须已移除");
    }

    /// touch 过的 sid 不该被踢（LRU 语义）。
    #[test]
    fn pool_touch_moves_to_back() {
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            p.acquire(sid);
        }
        p.touch(0); // 0 变最近使用
        let out = p.acquire(9999);
        assert_eq!(out, Acquire::Evicted(1), "touch 后应踢 sid=1 而不是 0");
        assert!(p.contains(0), "touch 过的 sid 不该被踢");
    }

    /// udp 与 link_udp 是两个独立池，互不抢占。
    #[test]
    fn pool_kinds_are_isolated() {
        let mut udp = UdpPool::new(PoolKind::Udp);
        let mut link = UdpPool::new(PoolKind::LinkUdp);
        for sid in 0..POOL_MAX as u32 {
            udp.acquire(sid);
        }
        assert_eq!(udp.in_use_len(), POOL_MAX);
        assert_eq!(link.created(), 0, "udp 打满不该动 link_udp");
        assert!(matches!(link.acquire(1), Acquire::Slot(0)), "link_udp 应能正常分配");
        assert_eq!(link.evicted_total(), 0);
    }

    /// kind() 报告正确类别。
    #[test]
    fn pool_reports_kind() {
        assert_eq!(UdpPool::new(PoolKind::Udp).kind(), PoolKind::Udp);
        assert_eq!(UdpPool::new(PoolKind::LinkUdp).kind(), PoolKind::LinkUdp);
    }
}
