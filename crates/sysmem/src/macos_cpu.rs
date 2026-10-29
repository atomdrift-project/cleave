//! Apple CPU classes are named, not a fixed performance/efficiency pair.

#[cfg(target_os = "macos")]
pub(super) fn physical_core_count() -> Option<usize> {
    use std::ffi::CString;

    let total = super::sysctlbyname_int(c"hw.physicalcpu");
    let selected = super::sysctlbyname_int(c"hw.nperflevels").and_then(|levels| {
        performance_cores(levels, |index| {
            let name = CString::new(format!("hw.perflevel{index}.name")).ok()?;
            let count = CString::new(format!("hw.perflevel{index}.physicalcpu")).ok()?;
            Some((sysctl_name(&name)?, super::sysctlbyname_int(&count)?))
        })
    });
    selected
        .filter(|count| total.is_none_or(|total| *count <= total))
        // Older macOS releases may expose counts without class names. Keep
        // their previous performance-only policy; Intel has no perflevel0.
        .or_else(|| super::sysctlbyname_int(c"hw.perflevel0.physicalcpu"))
        .or(total)
}

fn performance_cores(
    levels: usize,
    mut read_level: impl FnMut(usize) -> Option<(String, usize)>,
) -> Option<usize> {
    let mut selected = 0usize;
    for index in 0..levels {
        let (name, cores) = read_level(index)?;
        if cores == 0 {
            return None;
        }
        match name.as_str() {
            "Super" | "Performance" => selected = selected.checked_add(cores)?,
            "Efficiency" => {}
            // Do not silently admit an unknown low-power class, or return a
            // partial sum after a failed probe. The caller uses the old policy.
            _ => return None,
        }
    }
    (selected > 0).then_some(selected)
}

#[cfg(target_os = "macos")]
fn sysctl_name(name: &std::ffi::CStr) -> Option<String> {
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            oldp: *mut std::ffi::c_void,
            oldlenp: *mut usize,
            newp: *const std::ffi::c_void,
            newlen: usize,
        ) -> i32;
    }

    let mut value = [0u8; 128];
    let mut len = value.len();
    // SAFETY: the writable byte buffer has the supplied capacity. No new
    // value is provided. Failed/truncated or non-NUL-terminated reads are
    // rejected before parsing; no kernel-controlled length is indexed unchecked.
    let result = unsafe {
        sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    if result != 0 {
        return None;
    }
    std::ffi::CStr::from_bytes_with_nul(value.get(..len)?)
        .ok()?
        .to_str()
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::performance_cores;

    #[test]
    fn reported_apple_topologies_preserve_efficiency_exclusion() {
        for (levels, expected) in [
            // MacBook Pro output supplied by the operator.
            (vec![("Performance", 12), ("Efficiency", 4)], Some(12)),
            // Production QA host: both classes are performance cores.
            (vec![("Super", 12), ("Performance", 24)], Some(36)),
            (
                vec![("Super", 4), ("Performance", 8), ("Efficiency", 4)],
                Some(12),
            ),
            (vec![("Efficiency", 4), ("Performance", 8)], Some(8)),
            (vec![("Performance", 8)], Some(8)),
        ] {
            assert_eq!(
                performance_cores(levels.len(), |i| {
                    Some((levels[i].0.to_owned(), levels[i].1))
                }),
                expected,
                "{levels:?}"
            );
        }
    }

    #[test]
    fn incomplete_or_unknown_topology_never_returns_a_partial_count() {
        for levels in [
            vec![],
            vec![("Efficiency", 4)],
            vec![("Performance", 12), ("Unknown", 4)],
            vec![("Performance", 12), ("Super", 0)],
            vec![("Super", usize::MAX), ("Performance", 1)],
        ] {
            assert_eq!(
                performance_cores(levels.len(), |i| {
                    Some((levels[i].0.to_owned(), levels[i].1))
                }),
                None
            );
        }
        assert_eq!(
            performance_cores(2, |i| (i == 0).then(|| ("Performance".to_owned(), 12))),
            None
        );
    }
}
