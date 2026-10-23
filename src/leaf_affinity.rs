//! Optional Linux CPU placement for the private large-file worker pools.
//! `CLEAVE_LEAF_CPUS` uses CPU-list notation, e.g. `2-7,24-39`. The mask is
//! intersected with each worker's inherited affinity; it never widens it.

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    };

    fn parse(value: &str) -> Option<Vec<usize>> {
        let mut cpus = Vec::new();
        for part in value.split(',') {
            let part = part.trim();
            let (first, last) = part.split_once('-').unwrap_or((part, part));
            let first = first.parse::<usize>().ok()?;
            let last = last.parse::<usize>().ok()?;
            if first > last || last >= libc::CPU_SETSIZE as usize {
                return None;
            }
            cpus.extend(first..=last);
        }
        cpus.sort_unstable();
        cpus.dedup();
        Some(cpus)
    }

    fn current() -> io::Result<libc::cpu_set_t> {
        // SAFETY: cpu_set_t is a plain bitset; the syscall receives its full
        // writable storage and pid 0 denotes only the calling thread.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(set)
        }
    }

    fn restrict(cpus: &[usize]) -> io::Result<()> {
        let inherited = current()?;
        // SAFETY: both sets have CPU_SETSIZE bits. All indices are checked
        // before accessing the bitset. The syscall reads valid stack storage.
        unsafe {
            let mut selected: libc::cpu_set_t = std::mem::zeroed();
            let mut any = false;
            for &cpu in cpus {
                if cpu < libc::CPU_SETSIZE as usize && libc::CPU_ISSET(cpu, &inherited) {
                    libc::CPU_SET(cpu, &mut selected);
                    any = true;
                }
            }
            if !any {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no requested leaf CPUs are allowed",
                ));
            }
            if libc::sched_setaffinity(0, std::mem::size_of_val(&selected), &selected) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn apply() {
        static CPUS: OnceLock<Option<Vec<usize>>> = OnceLock::new();
        let Some(cpus) = CPUS.get_or_init(|| {
            let value = std::env::var("CLEAVE_LEAF_CPUS").ok()?;
            let cpus = parse(&value);
            if cpus.is_none() {
                tracing::warn!(%value, "invalid CLEAVE_LEAF_CPUS; retaining inherited affinity");
            }
            cpus
        }) else {
            return;
        };
        if let Err(error) = restrict(cpus) {
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(%error, "could not set leaf CPU affinity; retaining inherited affinity");
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used)]
        use super::*;

        #[test]
        fn cpu_lists_reject_invalid_or_unbounded_ranges() {
            assert_eq!(parse("2-4, 7,3"), Some(vec![2, 3, 4, 7]));
            for value in ["", "2,", "4-2", "-1", "1-2-3", "1024", "0-999999999"] {
                assert_eq!(parse(value), None, "{value}");
            }
        }

        #[test]
        fn worker_restriction_does_not_widen_affinity_or_change_caller() {
            let original = current().unwrap();
            let allowed: Vec<_> = (0..libc::CPU_SETSIZE as usize)
                .filter(|&cpu| {
                    // SAFETY: cpu is below CPU_SETSIZE and original is an initialized bitset.
                    unsafe { libc::CPU_ISSET(cpu, &original) }
                })
                .collect();
            let cpu = allowed[0];
            std::thread::spawn(move || {
                restrict(&[cpu]).unwrap();
                // Even an overly broad subsequent request cannot widen it.
                restrict(&allowed).unwrap();
                let selected = current().unwrap();
                for n in 0..libc::CPU_SETSIZE as usize {
                    // SAFETY: n is below CPU_SETSIZE and selected is an initialized bitset.
                    assert_eq!(unsafe { libc::CPU_ISSET(n, &selected) }, n == cpu);
                }
                assert!(restrict(&[]).is_err());
                // SAFETY: cpu came from the bounded allowed list; current returns an initialized bitset.
                assert!(unsafe { libc::CPU_ISSET(cpu, &current().unwrap()) });
            })
            .join()
            .unwrap();
            let after = current().unwrap();
            for n in 0..libc::CPU_SETSIZE as usize {
                assert_eq!(
                    // SAFETY: n is below CPU_SETSIZE and after is an initialized bitset.
                    unsafe { libc::CPU_ISSET(n, &after) },
                    // SAFETY: n is below CPU_SETSIZE and original is an initialized bitset.
                    unsafe { libc::CPU_ISSET(n, &original) }
                );
            }
        }
    }
}

pub(crate) fn apply() {
    #[cfg(target_os = "linux")]
    linux::apply();
}
