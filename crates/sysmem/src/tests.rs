#![allow(clippy::expect_used)]
use super::*;

/// The Linux aggregate line, with the post-2.6.11 fields present. iowait
/// is idle time: a core waiting on a disk is not a busy core.
#[test]
fn parse_proc_stat_cpu_splits_busy_from_idle() {
    let stat = "cpu  100 20 300 4000 50 6 7 8 90 10\ncpu0 1 2 3 4 5 6 7 8 9 10\n";
    let t = parse_proc_stat_cpu(stat).expect("cpu line");
    assert_eq!(t.busy, 100 + 20 + 300 + 6 + 7 + 8);
    assert_eq!(t.idle, 4000 + 50);
}

/// An old kernel with only the four original fields still parses.
#[test]
fn parse_proc_stat_cpu_tolerates_short_lines() {
    let t = parse_proc_stat_cpu("cpu 1 2 3 4\n").expect("cpu line");
    assert_eq!(t, CpuTime { busy: 6, idle: 4 });
    assert!(
        parse_proc_stat_cpu("cpu0 1 2 3 4\n").is_none(),
        "no aggregate line"
    );
    assert!(
        parse_proc_stat_cpu("cpu 1 2 x 4\n").is_none(),
        "garbage refused"
    );
}

/// Where the platform supports it, two reads a moment apart are monotonic.
#[test]
fn cpu_time_is_monotonic_where_supported() {
    if let (Some(a), Some(b)) = (cpu_time(), cpu_time()) {
        assert!(b.busy >= a.busy && b.idle >= a.idle, "{a:?} then {b:?}");
    }
}

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
fn zfs_credit_counts_only_evictable_data_and_preserves_minimum() {
    let stats = "name type data\nsize 4 1000\nc_min 4 300\n\
                     mru_evictable_data 4 450\nmfu_evictable_data 4 200\n\
                     mru_evictable_metadata 4 100\n";
    assert_eq!(parse_zfs_reclaimable_data(stats), Some(650));
    assert_eq!(
        parse_zfs_reclaimable_data(&stats.replace("300", "500")),
        Some(500)
    );
    assert_eq!(
        parse_zfs_reclaimable_data(&stats.replace("300", "1100")),
        Some(0)
    );
    assert_eq!(
        parse_zfs_reclaimable_data(&stats.replace("450", "0").replace("200", "0")),
        Some(0)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn zfs_credit_rejects_incomplete_or_malformed_stats() {
    for stats in [
        "",
        "size 4 1000\nc_min 4 100\n",
        "size 4 bad\nc_min 4 0\nmru_evictable_data 4 20\nmfu_evictable_data 4 10\n",
        "size 4 1000\nsize 4 2000\nc_min 4 0\nmru_evictable_data 4 20\nmfu_evictable_data 4 10\n",
        "size 4 1000\nc_min 4 0\nmru_evictable_data 2 20\nmfu_evictable_data 4 10\n",
        "size 4 1000\nc_min 4 0\nmru_evictable_data 4 18446744073709551615\nmfu_evictable_data 4 10\n",
    ] {
        assert_eq!(parse_zfs_reclaimable_data(stats), None, "{stats}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn zfs_credit_cannot_bypass_physical_or_cgroup_limits() {
    assert_eq!(
        host_available_with_arc(10 * GB, Some(128 * GB), 200 * GB),
        128 * GB
    );
    assert_eq!(host_available_with_arc(10 * GB, None, 200 * GB), 10 * GB);
    let host = host_available_with_arc(10 * GB, Some(128 * GB), 90 * GB);
    assert_eq!(
        effective_linux_memory(Some(host), Some(4 * GB)),
        Some(4 * GB)
    );
    assert_eq!(effective_linux_memory(Some(host), Some(0)), Some(0));
    assert_eq!(host_available_with_arc(10 * GB, Some(128 * GB), 0), 10 * GB);
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

#[cfg(target_os = "linux")]
#[test]
fn parse_cgroup_reclaimable_reads_cold_page_cache() {
    // Shape of a real memory.stat: a wedged service.
    let stat = "anon 3364188160\nfile 46862876672\nkernel_stack 851968\n\
                    inactive_file 42156023808\nactive_file 515813376\nslab 1752777984\n";
    assert_eq!(parse_cgroup_reclaimable(stat), 42_156_023_808);
    // Neither a suffix match nor a prefix match may stand in for it.
    assert_eq!(parse_cgroup_reclaimable("active_file 123\n"), 0);
    assert_eq!(parse_cgroup_reclaimable("total_inactive_file 123\n"), 0);
    assert_eq!(parse_cgroup_reclaimable("inactive_file bogus\n"), 0);
    assert_eq!(parse_cgroup_reclaimable(""), 0);
}
