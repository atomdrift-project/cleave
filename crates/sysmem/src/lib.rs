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

/// Current process RSS (Resident Set Size) in bytes when the platform exposes it.
///
/// On FreeBSD, OpenBSD, and NetBSD this currently returns `ru_maxrss`, which is
/// the process high-water mark rather than the instantaneous RSS.
///
/// Returns `None` if the value cannot be determined.
#[must_use]
pub fn current_rss() -> Option<u64> {
    current_rss_impl()
}

/// Memory pressure limit based on system RAM:
/// - ≤ 8 GiB: total − 512 MiB
/// - > 8 GiB: total − 1.5 GiB
/// - capped at 32 GiB
#[must_use]
pub fn memory_limit() -> u64 {
    const MAX: u64 = 32 * GB;
    let total = total_memory().unwrap_or(16 * GB);
    let limit = if total <= 8 * GB {
        total.saturating_sub(GB / 2)
    } else {
        total.saturating_sub(GB + GB / 2)
    };
    limit.min(MAX)
}

/// Warning threshold: 512 MiB below [`memory_limit`].
#[must_use]
pub fn warning_threshold() -> u64 {
    memory_limit().saturating_sub(512 * 1024 * 1024)
}

// ── macOS ───────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn total_memory_impl() -> Option<u64> {
    extern "C" {
        fn sysctlbyname(
            name: *const i8,
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

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
fn current_rss_impl() -> Option<u64> {
    // getrusage(RUSAGE_SELF) is available on all BSDs.
    // ru_maxrss is in kilobytes on FreeBSD/OpenBSD/NetBSD.
    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    // Minimal rusage — we only need ru_maxrss (3rd field).
    // The full struct is much larger; we pad to be safe.
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

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn current_rss_impl() -> Option<u64> {
    // getrusage(RUSAGE_SELF).ru_maxrss is in kilobytes on illumos/Solaris
    // (high-water mark, not instantaneous — same caveat as the BSDs). True
    // instantaneous RSS would require parsing /proc/self/psinfo as a binary
    // struct; getrusage is enough for throttling-style monitoring.
    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    // Minimal rusage — we only need ru_maxrss. The full struct is larger;
    // we pad to be safe. On illumos ru_maxrss is `long` (i64 on amd64).
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
        Some(usage.ru_maxrss as u64 * 1024)
    } else {
        None
    }
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
    fn memory_limit_matches_policy() {
        const MAX: u64 = 32 * GB;
        if let Some(total) = total_memory() {
            let expected = if total <= 8 * GB {
                total.saturating_sub(GB / 2)
            } else {
                total.saturating_sub(GB + GB / 2)
            }
            .min(MAX);
            assert_eq!(memory_limit(), expected);
        } else {
            // fallback total is 16 GB → 16 − 1.5 = 14.5 GB
            assert_eq!(memory_limit(), 14 * GB + GB / 2);
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
