//! Lightweight system memory queries with zero dependencies.
//!
//! Provides [`total_memory`] (effective available memory) and [`current_rss`]
//! (resident set size) on macOS, Linux, FreeBSD, OpenBSD, NetBSD, illumos,
//! Solaris, and Windows. Returns `None` on unsupported platforms.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::sync::OnceLock;

/// Bytes in one gibibyte.
const GB: u64 = 1024 * 1024 * 1024;

// ── public API ──────────────────────────────────────────────────────────

/// Effective total memory in bytes, cached after the first call.
///
/// On Linux, this is the smaller of `/proc/meminfo` MemTotal and cgroup v2
/// memory.high/memory.max when a cgroup limit is visible. If `/proc/meminfo`
/// is hidden by service sandboxing, the cgroup limit is still used.
///
/// Returns `None` only on unsupported platforms.
#[must_use]
pub fn total_memory() -> Option<u64> {
    static TOTAL: OnceLock<Option<u64>> = OnceLock::new();
    *TOTAL.get_or_init(total_memory_impl)
}

/// Effective *available* memory in bytes — memory allocatable now without
/// reclaim/swap pressure. Unlike [`total_memory`], this is a **live** value (not
/// cached): poll it to throttle concurrent work as other processes — including
/// other instances of this program — consume RAM.
///
/// On Linux this is the smaller of `/proc/meminfo` `MemAvailable` and the cgroup
/// v2 headroom (`memory.max − memory.current`) when a cgroup limit is visible,
/// so it respects both host and container pressure. Returns `None` on platforms
/// (or in sandboxes) where no live source is readable, so callers fall back to a
/// total-memory budget rather than over- or under-committing.
#[must_use]
pub fn available_memory() -> Option<u64> {
    available_memory_impl()
}

/// Current process RSS (Resident Set Size) in bytes when the platform exposes it.
///
/// Reports the *instantaneous* RSS — a value that falls as the process frees
/// memory — on Linux, macOS, FreeBSD, illumos/Solaris, and Windows. OpenBSD and
/// NetBSD fall back to `ru_maxrss`, the lifetime high-water mark, which only
/// ever increases.
///
/// Returns `None` if the value cannot be determined.
#[must_use]
pub fn current_rss() -> Option<u64> {
    current_rss_impl()
}

/// Memory pressure limit based on system RAM:
/// - ≤ 8 GiB: total − 512 MiB
/// - > 8 GiB: 85% of total
///
/// 85% matches litmus's worker RSS policy so the two never disagree about what
/// "too much" means. There is deliberately no absolute cap: an earlier 32 GiB
/// ceiling flooded large hosts (which legitimately use 100 GB+ across a big
/// worker fleet) with false "High memory usage" warnings while enforcing
/// nothing.
#[must_use]
pub fn memory_limit() -> u64 {
    let total = total_memory().unwrap_or(16 * GB);
    if total <= 8 * GB {
        total.saturating_sub(GB / 2)
    } else {
        total / 100 * 85
    }
}

/// Warning threshold: 512 MiB below [`memory_limit`].
#[must_use]
pub fn warning_threshold() -> u64 {
    memory_limit().saturating_sub(512 * 1024 * 1024)
}

/// Number of CPUs available to the process, cached after the first call.
///
/// `std::thread::available_parallelism()` returns `Err(Unsupported)` on
/// illumos/Solaris, where callers would otherwise silently collapse a thread
/// pool to a small hardcoded fallback on a many-core host. There we probe
/// `sysconf(_SC_NPROCESSORS_ONLN)` directly. Everywhere else we defer to the
/// standard library.
///
/// Returns `None` only when no source is usable, so callers can log a resource
/// downgrade instead of silently assuming a small default.
#[must_use]
pub fn cpu_count() -> Option<usize> {
    static COUNT: OnceLock<Option<usize>> = OnceLock::new();
    *COUNT.get_or_init(cpu_count_impl)
}

/// Number of *physical* CPU cores (excluding SMT/hyperthread siblings), cached
/// after the first call, or `None` if the platform exposes no reliable source.
///
/// cleave's archive-heavy, CPU-bound workload peaks at the physical-core count:
/// a ternary sweep on a 64-core / 128-thread AMD Threadripper put the wall
/// optimum at 64 threads (96 cost +13%, full-SMT worse still), because the
/// hyperthread siblings only add scheduler contention once every core is fed.
///
/// On asymmetric Apple Silicon this returns the *performance*-core count (the
/// efficiency cores regress this workload). `None` here is not an error — the
/// caller falls back to a logical/2 SMT heuristic and warns, so an
/// unrecognised platform still gets a sane (if conservative) default.
#[must_use]
pub fn physical_cpu_count() -> Option<usize> {
    static COUNT: OnceLock<Option<usize>> = OnceLock::new();
    *COUNT.get_or_init(physical_cpu_count_impl)
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn cpu_count_impl() -> Option<usize> {
    extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    // From <sys/unistd.h> on illumos/Solaris: _SC_NPROCESSORS_ONLN = 15. This is
    // the system-wide online-CPU count; a process bound to a smaller processor
    // set would see more CPUs than it can use, but that matches the existing
    // `total_memory` sysconf basis and is correct for the common case.
    const SC_NPROCESSORS_ONLN: i32 = 15;
    // SAFETY: sysconf is a pure C function; the selector is a well-defined POSIX
    // value and a non-positive return is treated as failure.
    let n = unsafe { sysconf(SC_NPROCESSORS_ONLN) };
    (n > 0).then_some(n as usize)
}

#[cfg(not(any(target_os = "illumos", target_os = "solaris")))]
fn cpu_count_impl() -> Option<usize> {
    std::thread::available_parallelism()
        .ok()
        .map(std::num::NonZero::get)
}

// ── macOS ───────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn total_memory_impl() -> Option<u64> {
    extern "C" {
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            oldp: *mut std::ffi::c_void,
            oldlenp: *mut usize,
            newp: *const std::ffi::c_void,
            newlen: usize,
        ) -> i32;
    }

    let mut memsize: u64 = 0;
    let mut len = std::mem::size_of::<u64>();

    // SAFETY: sysctlbyname with "hw.memsize" writes a u64; we provide a
    // correctly-sized and -aligned buffer.
    let ret = unsafe {
        sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&raw mut memsize).cast(),
            &raw mut len,
            std::ptr::null(),
            0,
        )
    };
    if ret == 0 && memsize > 0 {
        Some(memsize)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn current_rss_impl() -> Option<u64> {
    #[repr(C)]
    struct TimeValue {
        seconds: i32,
        microseconds: i32,
    }

    #[repr(C)]
    struct MachTaskBasicInfo {
        virtual_size: u64,
        resident_size: u64,
        resident_size_max: u64,
        user_time: TimeValue,
        system_time: TimeValue,
        policy: i32,
        suspend_count: i32,
    }

    const MACH_TASK_BASIC_INFO: i32 = 20;
    const MACH_TASK_BASIC_INFO_COUNT: u32 =
        (std::mem::size_of::<MachTaskBasicInfo>() / std::mem::size_of::<i32>()) as u32;

    extern "C" {
        fn mach_task_self() -> u32;
        fn task_info(
            target_task: u32,
            flavor: i32,
            task_info_out: *mut i32,
            task_info_out_cnt: *mut u32,
        ) -> i32;
    }

    // SAFETY: task_info with MACH_TASK_BASIC_INFO fills MachTaskBasicInfo;
    // we pass a correctly-sized zeroed struct.
    let task = unsafe { mach_task_self() };
    let mut info: MachTaskBasicInfo = unsafe { std::mem::zeroed() };
    let mut count = MACH_TASK_BASIC_INFO_COUNT;

    let kr = unsafe {
        task_info(
            task,
            MACH_TASK_BASIC_INFO,
            (&raw mut info).cast(),
            &raw mut count,
        )
    };

    if kr == 0 {
        Some(info.resident_size)
    } else {
        None
    }
}

// ── Linux ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn total_memory_impl() -> Option<u64> {
    effective_linux_memory(meminfo_total_memory(), cgroup_memory_limit())
}

#[cfg(target_os = "linux")]
fn meminfo_total_memory() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_total_memory(&meminfo)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_total_memory(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn effective_linux_memory(physical: Option<u64>, cgroup_limit: Option<u64>) -> Option<u64> {
    match (physical, cgroup_limit) {
        (Some(p), Some(c)) => Some(p.min(c)),
        (Some(p), None) => Some(p),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> Option<u64> {
    let path = cgroup_v2_path()?;
    [
        read_trimmed(path.join("memory.high")),
        read_trimmed(path.join("memory.max")),
    ]
    .into_iter()
    .flatten()
    .filter_map(|v| parse_cgroup_memory_value(&v))
    .min()
}

#[cfg(target_os = "linux")]
fn cgroup_v2_path() -> Option<std::path::PathBuf> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    for line in cgroup.lines() {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let rel = parts.next()?;
        if hierarchy == "0" && controllers.is_empty() {
            let rel = rel.trim_start_matches('/');
            return Some(if rel.is_empty() {
                std::path::PathBuf::from("/sys/fs/cgroup")
            } else {
                std::path::PathBuf::from("/sys/fs/cgroup").join(rel)
            });
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: std::path::PathBuf) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn parse_cgroup_memory_value(value: &str) -> Option<u64> {
    if value == "max" {
        return None;
    }
    value.parse().ok()
}

#[cfg(target_os = "linux")]
fn available_memory_impl() -> Option<u64> {
    // Min of host MemAvailable and cgroup headroom — mirrors total_memory's
    // host-vs-cgroup reconciliation, so a container sees its own limit.
    effective_linux_memory(meminfo_available_memory(), cgroup_memory_headroom())
}

#[cfg(target_os = "linux")]
fn meminfo_available_memory() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_available_memory(&meminfo)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_available_memory(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn cgroup_memory_headroom() -> Option<u64> {
    let path = cgroup_v2_path()?;
    let limit = parse_cgroup_memory_value(&read_trimmed(path.join("memory.max"))?)?;
    let current: u64 = read_trimmed(path.join("memory.current"))?.parse().ok()?;
    Some(limit.saturating_sub(current))
}

/// Platforms without a live available-memory source: callers fall back to a
/// total-memory budget.
#[cfg(not(target_os = "linux"))]
fn available_memory_impl() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn current_rss_impl() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

// ── FreeBSD / OpenBSD / NetBSD ──────────────────────────────────────────

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
fn total_memory_impl() -> Option<u64> {
    // All three BSDs support sysctl hw.physmem via the C API.
    // FreeBSD/NetBSD return a u64, OpenBSD returns a long (i64 on 64-bit).
    extern "C" {
        fn sysctl(
            name: *const i32,
            namelen: u32,
            oldp: *mut std::ffi::c_void,
            oldlenp: *mut usize,
            newp: *const std::ffi::c_void,
            newlen: usize,
        ) -> i32;
    }

    const CTL_HW: i32 = 6;

    // HW_PHYSMEM is 5 on all three BSDs. On FreeBSD 64-bit it's HW_PHYSMEM
    // which may be 32-bit; HW_REALMEM (12) gives the 64-bit value.
    // We try HW_REALMEM first on FreeBSD, fall back to HW_PHYSMEM.
    #[cfg(target_os = "freebsd")]
    const HW_ENTRIES: &[(i32, usize)] = &[
        (12 /* HW_REALMEM */, std::mem::size_of::<u64>()),
        (5 /* HW_PHYSMEM */, std::mem::size_of::<u64>()),
    ];
    #[cfg(not(target_os = "freebsd"))]
    const HW_ENTRIES: &[(i32, usize)] = &[(5 /* HW_PHYSMEM */, std::mem::size_of::<u64>())];

    for &(hw_id, expected_len) in HW_ENTRIES {
        let mib = [CTL_HW, hw_id];
        let mut val: u64 = 0;
        let mut len = expected_len;

        // SAFETY: sysctl with CTL_HW/HW_PHYSMEM writes at most `len` bytes
        // into a u64 buffer; we check the return code.
        let ret = unsafe {
            sysctl(
                mib.as_ptr(),
                mib.len() as u32,
                (&raw mut val).cast(),
                &raw mut len,
                std::ptr::null(),
                0,
            )
        };

        if ret == 0 && val > 0 {
            return Some(val);
        }
    }
    None
}

/// `getrusage(RUSAGE_SELF).ru_maxrss` (lifetime high-water mark) in bytes.
///
/// Shared fallback for the BSDs and illumos/Solaris, where `ru_maxrss` is in
/// kilobytes. This is monotonic — it never decreases — so it is only a
/// last-resort backstop. The per-platform `current_rss_impl` below prefers a
/// true *instantaneous* RSS where the kernel exposes one (FreeBSD, illumos),
/// because the memory-admission throttle needs to see RSS fall as work
/// completes; a high-water mark would pin the gate shut forever.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris"
))]
fn getrusage_maxrss() -> Option<u64> {
    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    // Minimal rusage — we only need ru_maxrss (3rd field). The full struct is
    // much larger; we pad to be safe.
    #[repr(C)]
    struct Rusage {
        ru_utime: Timeval,
        ru_stime: Timeval,
        ru_maxrss: i64,
        _pad: [i64; 13],
    }

    const RUSAGE_SELF: i32 = 0;

    // SAFETY: getrusage fills the Rusage struct; we pass a zeroed buffer.
    let mut usage: Rusage = unsafe { std::mem::zeroed() };
    let ret = unsafe { getrusage(RUSAGE_SELF, &raw mut usage) };
    if ret == 0 && usage.ru_maxrss > 0 {
        Some(usage.ru_maxrss as u64 * 1024) // KB → bytes
    } else {
        None
    }
}

/// FreeBSD instantaneous RSS via `sysctl kern.proc.pid.<pid>`.
///
/// The kernel fills a `struct kinfo_proc` whose `ki_rssize` field is the live
/// resident page count. On all 64-bit FreeBSD targets the struct layout is
/// frozen: `ki_rssize` (a `segsz_t`, i.e. 8 bytes, in pages) sits at offset 264,
/// immediately after `ki_size` (bytes) at 256. We read it defensively and
/// validate against physical RAM, falling back to the `ru_maxrss` high-water
/// mark if the value is implausible (guards against a layout change on a future
/// release).
#[cfg(target_os = "freebsd")]
fn current_rss_impl() -> Option<u64> {
    extern "C" {
        fn sysctl(
            name: *const i32,
            namelen: u32,
            oldp: *mut std::ffi::c_void,
            oldlenp: *mut usize,
            newp: *const std::ffi::c_void,
            newlen: usize,
        ) -> i32;
        fn getpid() -> i32;
        fn getpagesize() -> i32;
    }

    const CTL_KERN: i32 = 1;
    const KERN_PROC: i32 = 14;
    const KERN_PROC_PID: i32 = 1;
    /// Byte offset of `ki_rssize` within `struct kinfo_proc` on 64-bit FreeBSD.
    const KI_RSSIZE_OFFSET: usize = 264;

    let instantaneous = || -> Option<u64> {
        // SAFETY: getpid/getpagesize are pure libc calls with no arguments.
        let pid = unsafe { getpid() };
        let page_size = unsafe { getpagesize() };
        if page_size <= 0 {
            return None;
        }
        let mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];

        // First call: ask for the buffer size the kernel needs.
        let mut len: usize = 0;
        // SAFETY: oldp=null asks sysctl to report the required length in `len`.
        let ret = unsafe {
            sysctl(
                mib.as_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &raw mut len,
                std::ptr::null(),
                0,
            )
        };
        if ret != 0 || len <= KI_RSSIZE_OFFSET + std::mem::size_of::<u64>() {
            return None;
        }

        // Second call: fill a byte buffer with the kinfo_proc record.
        let mut buf = vec![0u8; len];
        // SAFETY: buffer is `len` bytes; sysctl writes at most `len` and updates
        // `len` with the bytes actually written.
        let ret = unsafe {
            sysctl(
                mib.as_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr().cast(),
                &raw mut len,
                std::ptr::null(),
                0,
            )
        };
        if ret != 0 || len <= KI_RSSIZE_OFFSET + std::mem::size_of::<u64>() {
            return None;
        }

        // Read ki_rssize (pages) from its fixed offset via an unaligned load.
        let mut rssize_pages = [0u8; 8];
        rssize_pages.copy_from_slice(&buf[KI_RSSIZE_OFFSET..KI_RSSIZE_OFFSET + 8]);
        let pages = u64::from_ne_bytes(rssize_pages);
        let bytes = pages.checked_mul(page_size as u64)?;

        // Validate: a live RSS must be positive and cannot exceed physical RAM.
        // An implausible value means the struct layout drifted; reject it so the
        // caller falls back to the (always-safe) high-water mark.
        match total_memory() {
            Some(total) if bytes > 0 && bytes <= total => Some(bytes),
            None if bytes > 0 => Some(bytes),
            _ => None,
        }
    };

    instantaneous().or_else(getrusage_maxrss)
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
fn current_rss_impl() -> Option<u64> {
    // OpenBSD/NetBSD expose ru_maxrss (high-water mark). Their kinfo_proc
    // layouts differ from FreeBSD's, so we keep the conservative fallback until
    // an instantaneous reader is needed there.
    getrusage_maxrss()
}

// ── illumos / Solaris ───────────────────────────────────────────────────

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn total_memory_impl() -> Option<u64> {
    // sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) is POSIX and works on
    // illumos/Solaris with no extra dependencies. In zones this returns the
    // zone's rcap-capped memory when set, else the host RAM.
    extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    // From <unistd.h> on illumos: _SC_PAGESIZE=11, _SC_PHYS_PAGES=500.
    const SC_PAGESIZE: i32 = 11;
    const SC_PHYS_PAGES: i32 = 500;

    // SAFETY: sysconf is a pure C function; both names are well-defined POSIX
    // selectors and return -1 on error which we check for.
    let pages = unsafe { sysconf(SC_PHYS_PAGES) };
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    if pages > 0 && page_size > 0 {
        Some(pages as u64 * page_size as u64)
    } else {
        None
    }
}

/// illumos/Solaris instantaneous RSS via `/proc/self/psinfo`.
///
/// `psinfo_t` is a stable binary struct mounted by the always-present procfs.
/// Its `pr_rssize` field is the live resident size in *kilobytes* and sits at a
/// fixed offset (56) on 64-bit targets, after `pr_size` (48). We read it
/// defensively and validate against physical RAM, falling back to the
/// `ru_maxrss` high-water mark if procfs is absent or the value is implausible.
///
/// `getrusage(RUSAGE_SELF).ru_maxrss` — the previous behaviour — is a lifetime
/// high-water mark, which would pin the memory-admission throttle shut once the
/// process peaked; the instantaneous reading is what lets the gate reopen.
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn current_rss_impl() -> Option<u64> {
    /// Byte offset of `pr_rssize` within `psinfo_t` on 64-bit illumos/Solaris.
    const PR_RSSIZE_OFFSET: usize = 56;

    let instantaneous = || -> Option<u64> {
        let buf = std::fs::read("/proc/self/psinfo").ok()?;
        if buf.len() < PR_RSSIZE_OFFSET + std::mem::size_of::<u64>() {
            return None;
        }
        let mut rssize_kb = [0u8; 8];
        rssize_kb.copy_from_slice(&buf[PR_RSSIZE_OFFSET..PR_RSSIZE_OFFSET + 8]);
        let bytes = u64::from_ne_bytes(rssize_kb).checked_mul(1024)?;

        match total_memory() {
            Some(total) if bytes > 0 && bytes <= total => Some(bytes),
            None if bytes > 0 => Some(bytes),
            _ => None,
        }
    };

    instantaneous().or_else(getrusage_maxrss)
}

// ── Windows ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn total_memory_impl() -> Option<u64> {
    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }

    // SAFETY: GlobalMemoryStatusEx fills the struct when dw_length is set
    // correctly; we zero-init and set the length field.
    let mut status: MemoryStatusEx = unsafe { std::mem::zeroed() };
    status.dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
    let ret = unsafe { GlobalMemoryStatusEx(&raw mut status) };
    if ret != 0 && status.ull_total_phys > 0 {
        Some(status.ull_total_phys)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn current_rss_impl() -> Option<u64> {
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, pmc: *mut ProcessMemoryCounters, cb: u32)
            -> i32;
    }

    // SAFETY: K32GetProcessMemoryInfo fills the struct for the current process.
    let mut pmc: ProcessMemoryCounters = unsafe { std::mem::zeroed() };
    pmc.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
    let ret = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut pmc, pmc.cb) };
    if ret != 0 {
        Some(pmc.working_set_size as u64)
    } else {
        None
    }
}

// ── Unsupported ─────────────────────────────────────────────────────────

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "windows",
)))]
fn total_memory_impl() -> Option<u64> {
    None
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "windows",
)))]
fn current_rss_impl() -> Option<u64> {
    None
}

// ── physical CPU cores ──────────────────────────────────────────────────
//
// One impl per platform, mirroring the cpu/mem sections above. Each returns
// `None` rather than guessing when its source is unavailable, so the caller
// can warn and apply its own heuristic.

/// `sysctlbyname` returning a single C `int` as `usize`. Shared by the two
/// platforms whose physical-core sysctls return an `int`: macOS and FreeBSD.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn sysctlbyname_int(name: &core::ffi::CStr) -> Option<usize> {
    extern "C" {
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            oldp: *mut std::ffi::c_void,
            oldlenp: *mut usize,
            newp: *const std::ffi::c_void,
            newlen: usize,
        ) -> i32;
    }

    let mut val: i32 = 0;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: the named sysctls (hw.*physicalcpu, kern.smp.cores) write a
    // single C int; we provide a correctly-sized, -aligned i32 buffer and
    // gate on the return code.
    let ret = unsafe {
        sysctlbyname(
            name.as_ptr(),
            (&raw mut val).cast(),
            &raw mut len,
            std::ptr::null(),
            0,
        )
    };
    (ret == 0 && val > 0).then_some(val as usize)
}

#[cfg(target_os = "macos")]
fn physical_cpu_count_impl() -> Option<usize> {
    // Prefer the performance-core count on asymmetric Apple Silicon; fall back
    // to all physical cores on uniform (Intel) Macs, where perflevel0 is absent.
    sysctlbyname_int(c"hw.perflevel0.physicalcpu").or_else(|| sysctlbyname_int(c"hw.physicalcpu"))
}

#[cfg(target_os = "freebsd")]
fn physical_cpu_count_impl() -> Option<usize> {
    // kern.smp.cores is the physical-core count; kern.smp.threads_per_core is
    // the SMT factor (verified on FreeBSD 14: cores=8, threads_per_core=1).
    sysctlbyname_int(c"kern.smp.cores")
}

#[cfg(target_os = "linux")]
fn physical_cpu_count_impl() -> Option<usize> {
    // Count distinct (physical_package_id, core_id) pairs across the CPUs in
    // sysfs topology; SMT siblings share a core_id within a package, so this is
    // the true physical-core count. Reading sysfs avoids any external crate.
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let dir = std::fs::read_dir("/sys/devices/system/cpu").ok()?;
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Match `cpuN` (a CPU dir), not `cpufreq`/`cpuidle`/etc.
        let Some(rest) = name.strip_prefix("cpu") else {
            continue;
        };
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let topo = entry.path().join("topology");
        let pkg = std::fs::read_to_string(topo.join("physical_package_id")).ok();
        let core = std::fs::read_to_string(topo.join("core_id")).ok();
        if let (Some(pkg), Some(core)) = (pkg, core) {
            seen.insert((pkg.trim().to_owned(), core.trim().to_owned()));
        }
    }
    (!seen.is_empty()).then_some(seen.len())
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn physical_cpu_count_impl() -> Option<usize> {
    // No sysconf/sysctl exposes a physical-core count here; only kstat does.
    // FFI'ing libkstat would mean hand-mirroring kstat_ctl_t/kstat_t/
    // kstat_named_t layouts — a wrong offset is UB — so we read the
    // always-present `kstat` tool and count distinct (chip_id, core_id) pairs.
    // Verified on OmniOS r151058: 16 physical cores on a 1-socket SMT host.
    use std::process::Command;
    let out = Command::new("kstat")
        .args(["-p", "cpu_info"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let n = count_kstat_physical_cores(&text);
    (n > 0).then_some(n)
}

/// Count distinct `(chip_id, core_id)` pairs from `kstat -p cpu_info` output.
///
/// Lines look like `cpu_info:<instance>:cpu_info<instance>:<field>\t<value>`.
/// Defined unconditionally (not behind `cfg`) so it is unit-testable on any
/// host. Returns 0 when the input carries no usable topology.
#[cfg_attr(
    not(any(target_os = "illumos", target_os = "solaris")),
    allow(dead_code)
)]
fn count_kstat_physical_cores(kstat_p: &str) -> usize {
    use std::collections::{HashMap, HashSet};
    let mut chip: HashMap<&str, &str> = HashMap::new();
    let mut core: HashMap<&str, &str> = HashMap::new();
    for line in kstat_p.lines() {
        let Some((key, value)) = line.split_once('\t') else {
            continue;
        };
        let mut parts = key.split(':');
        let (Some(_module), Some(instance), Some(_name), Some(field)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        match field {
            "chip_id" => {
                chip.insert(instance, value.trim());
            }
            "core_id" => {
                core.insert(instance, value.trim());
            }
            _ => {}
        }
    }
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for (instance, core_id) in &core {
        let chip_id = chip.get(instance).copied().unwrap_or("");
        seen.insert((chip_id, *core_id));
    }
    seen.len()
}

#[cfg(target_os = "windows")]
fn physical_cpu_count_impl() -> Option<usize> {
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION; the trailing union (ProcessorCore /
    // NumaNode / CACHE_DESCRIPTOR / ULONGLONG[2]) is 16 bytes, align 8 — modeled
    // as [u64; 2] so the struct size/alignment match the OS layout exactly. We
    // count entries whose Relationship == RelationProcessorCore.
    #[repr(C)]
    struct SystemLogicalProcessorInformation {
        processor_mask: usize,
        relationship: u32,
        _union: [u64; 2],
    }
    const RELATION_PROCESSOR_CORE: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    extern "system" {
        fn GetLogicalProcessorInformation(
            buffer: *mut SystemLogicalProcessorInformation,
            returned_length: *mut u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    // First call sizes the buffer: it fails with ERROR_INSUFFICIENT_BUFFER and
    // sets `len`.
    let mut len: u32 = 0;
    // SAFETY: a null buffer with a valid length-out pointer is the documented
    // size-probe form.
    let ret = unsafe { GetLogicalProcessorInformation(std::ptr::null_mut(), &raw mut len) };
    // SAFETY: GetLastError reads thread-local error state.
    if ret != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || len == 0 {
        return None;
    }

    let entry_size = std::mem::size_of::<SystemLogicalProcessorInformation>();
    let count = len as usize / entry_size;
    let mut buf: Vec<SystemLogicalProcessorInformation> = Vec::with_capacity(count);
    // SAFETY: the buffer has capacity for `len` bytes; the call fills it and we
    // only set_len after it reports success.
    let ret = unsafe { GetLogicalProcessorInformation(buf.as_mut_ptr(), &raw mut len) };
    if ret == 0 {
        return None;
    }
    // SAFETY: the call populated `len` bytes = `count` initialised entries.
    unsafe { buf.set_len(count) };

    let cores = buf
        .iter()
        .filter(|e| e.relationship == RELATION_PROCESSOR_CORE)
        .count();
    (cores > 0).then_some(cores)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "windows",
)))]
fn physical_cpu_count_impl() -> Option<usize> {
    // OpenBSD/NetBSD and any other target: no verified physical-core source.
    // The caller applies a logical/2 SMT heuristic and warns. (OpenBSD disables
    // SMT by default, so logical ≈ physical there in practice.)
    None
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn total_memory_returns_value() {
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
            target_os = "windows",
        ))]
        {
            let mem = total_memory().expect("should detect total memory");
            // Sanity: at least 128 MiB, at most 64 TiB
            assert!(mem >= 128 * 1024 * 1024, "too small: {mem}");
            assert!(mem <= 64 * 1024 * GB, "too large: {mem}");
        }
    }

    #[test]
    fn current_rss_returns_value() {
        #[cfg(any(
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
            target_os = "windows",
        ))]
        {
            let rss = current_rss().expect("should detect RSS");
            assert!(rss > 0);
        }
    }

    #[test]
    fn cpu_count_returns_positive() {
        // Every platform sysmem targets exposes a CPU count; a `None` here would
        // drive the silent thread-pool downgrade this function exists to prevent.
        let n = cpu_count().expect("should detect CPU count");
        assert!(n > 0);
    }

    #[test]
    fn physical_cpu_count_within_logical() {
        // Where detectable, physical cores must be positive and never exceed the
        // logical CPU count. `None` is allowed (OpenBSD/NetBSD/unknown targets).
        if let Some(physical) = physical_cpu_count() {
            assert!(physical > 0, "physical core count should be positive");
            if let Some(logical) = cpu_count() {
                assert!(
                    physical <= logical,
                    "physical {physical} should not exceed logical {logical}"
                );
            }
        }
    }

    #[test]
    fn count_kstat_physical_cores_counts_distinct_core_chip_pairs() {
        // Two chips × two cores each = 4 physical cores, with an SMT sibling per
        // core (instances 0/1 share chip0/core0, etc.). The parser must collapse
        // SMT siblings (same chip+core) and keep cross-chip cores distinct.
        let sample = "\
cpu_info:0:cpu_info0:chip_id\t0
cpu_info:0:cpu_info0:core_id\t0
cpu_info:1:cpu_info1:chip_id\t0
cpu_info:1:cpu_info1:core_id\t0
cpu_info:2:cpu_info2:chip_id\t0
cpu_info:2:cpu_info2:core_id\t1
cpu_info:3:cpu_info3:chip_id\t1
cpu_info:3:cpu_info3:core_id\t0
cpu_info:4:cpu_info4:chip_id\t1
cpu_info:4:cpu_info4:core_id\t1
cpu_info:5:cpu_info5:state\ton-line
";
        assert_eq!(count_kstat_physical_cores(sample), 4);
    }

    #[test]
    fn count_kstat_physical_cores_handles_empty_and_garbage() {
        assert_eq!(count_kstat_physical_cores(""), 0);
        assert_eq!(
            count_kstat_physical_cores("no tabs here\nand:colons:but:no\tcore"),
            0
        );
    }

    #[test]
    fn memory_limit_matches_policy() {
        if let Some(total) = total_memory() {
            let expected = if total <= 8 * GB {
                total.saturating_sub(GB / 2)
            } else {
                total / 100 * 85
            };
            assert_eq!(memory_limit(), expected);
        } else {
            // fallback total is 16 GB → 85% = 13.6 GB
            assert_eq!(memory_limit(), 16 * GB / 100 * 85);
        }
    }

    #[test]
    fn warning_threshold_is_512mib_below_limit() {
        let limit = memory_limit();
        let warn = warning_threshold();
        assert_eq!(warn, limit.saturating_sub(512 * 1024 * 1024));
    }

    #[test]
    fn total_memory_is_cached() {
        let a = total_memory();
        let b = total_memory();
        assert_eq!(a, b);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_total_memory_reads_kib() {
        let mem = parse_meminfo_total_memory("MemTotal:       131693424 kB\nMemFree: 1 kB\n")
            .expect("memtotal");
        assert_eq!(mem, 131_693_424 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_available_memory_reads_kib() {
        let mem = parse_meminfo_available_memory(
            "MemTotal:       131693424 kB\nMemFree: 1 kB\nMemAvailable:    76543210 kB\n",
        )
        .expect("memavailable");
        assert_eq!(mem, 76_543_210 * 1024);
        // Absent MemAvailable (very old kernels) → None, not a misparse.
        assert_eq!(parse_meminfo_available_memory("MemTotal: 1 kB\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn effective_linux_memory_prefers_lowest_available_limit() {
        assert_eq!(
            effective_linux_memory(Some(128 * GB), Some(64 * GB)),
            Some(64 * GB)
        );
        assert_eq!(effective_linux_memory(None, Some(64 * GB)), Some(64 * GB));
        assert_eq!(effective_linux_memory(Some(128 * GB), None), Some(128 * GB));
        assert_eq!(effective_linux_memory(None, None), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_cgroup_memory_value_handles_max() {
        assert_eq!(
            parse_cgroup_memory_value("77309411328"),
            Some(77_309_411_328)
        );
        assert_eq!(parse_cgroup_memory_value("max"), None);
        assert_eq!(parse_cgroup_memory_value("not-a-number"), None);
    }
}
