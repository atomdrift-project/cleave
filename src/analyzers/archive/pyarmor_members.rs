//! Companion-runtime pairing belongs in the archive walker. Format decoding
//! belongs in filefacts. Only bounded, signature-qualified bytes are retained.
use super::{FileType, MemoryArchiveMember, calculate_sha256};

#[derive(Default)]
pub(super) struct Collector {
    runtimes: Vec<Vec<u8>>,
    modules: Vec<(String, Vec<Vec<u8>>)>,
    retained: usize,
    limited: bool,
}
impl Collector {
    pub(super) fn observe(&mut self, member: &MemoryArchiveMember) {
        let data: &[u8] = &member.data;
        if data.len() > 16 * 1024 * 1024 {
            return;
        }
        let runtime =
            data.len() <= 8 * 1024 * 1024 && data.windows(12).any(|v| v == b"pyarmor-vax-");
        let candidate = matches!(
            member.file_type,
            FileType::Python | FileType::PythonBytecode
        ) || filefacts::pyarmor::is_container(data);
        if !runtime && !(candidate && data.windows(8).any(filefacts::pyarmor::is_container)) {
            return;
        }
        if self.retained.saturating_add(data.len()) > 32 * 1024 * 1024
            || (runtime && self.runtimes.len() >= 8)
            || (!runtime && self.modules.len() >= 128)
        {
            self.limited = true;
            return;
        }
        if runtime {
            self.retained += data.len();
            self.runtimes.push(data.to_vec());
        } else {
            let mut containers = filefacts::pyarmor::python_containers(data);
            if containers.is_empty() && member.file_type != FileType::Python {
                containers.push(data.to_vec());
            }
            let size: usize = containers.iter().map(Vec::len).sum();
            if self.retained.saturating_add(size) > 32 * 1024 * 1024 {
                self.limited = true;
                return;
            }
            if !containers.is_empty() {
                self.retained += size;
                self.modules
                    .push((member.relative_path.clone(), containers));
            }
        }
    }

    pub(super) fn recover(
        self,
        mut diagnostic: impl FnMut(String),
        cancelled: impl Fn() -> bool,
    ) -> Vec<MemoryArchiveMember> {
        let mut count = 0usize;
        let mut note = |message: String| {
            if count < 64 {
                diagnostic(message);
            } else if count == 64 {
                diagnostic("Further PyArmor analysis diagnostics were omitted".into());
            }
            count += 1;
        };
        let mut out = Vec::new();
        let mut attempts = 0;
        let mut total = 0usize;
        if self.limited {
            note("PyArmor pairing reached the retained-byte or member budget".into());
        }
        for (path, containers) in self.modules {
            for (index, container) in containers.iter().enumerate() {
                let mut recovered = false;
                for runtime in &self.runtimes {
                    if cancelled() {
                        return out;
                    }
                    attempts += 1;
                    if attempts > 256 {
                        note("PyArmor pairing reached the 256-attempt budget".into());
                        return out;
                    }
                    let Some(recovery) = filefacts::pyarmor::recover(runtime, container) else {
                        continue;
                    };
                    let pyc = match recovery.pyc() {
                        Ok(pyc) => pyc,
                        Err(reason) => {
                            note(format!("PyArmor {path}: {reason}"));
                            break;
                        }
                    };
                    total = total.saturating_add(pyc.data.len());
                    if total > 16 * 1024 * 1024 {
                        note("PyArmor recovery reached the 16 MiB output budget".into());
                        return out;
                    }
                    if !pyc.limitations.is_empty() {
                        note(format!("PyArmor {path}: {}", pyc.limitations.join("; ")));
                    }
                    out.push(MemoryArchiveMember {
                        relative_path: format!("{path}.{index}.pyarmor-analysis.pyc"),
                        sha256: calculate_sha256(&pyc.data),
                        data: pyc.data.into(),
                        file_type: FileType::PythonBytecode,
                        container_kind: Some("pyarmor-analysis-snapshot".into()),
                    });
                    recovered = true;
                    break;
                }
                if !recovered {
                    note(format!(
                        "PyArmor {path}: no supported companion-runtime recovery"
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn members() -> Vec<MemoryArchiveMember> {
        let bytes = include_bytes!("testdata/pyarmor-runtime-wrapper.zip");
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        (0..archive.len())
            .map(|i| {
                use std::io::Read;
                let mut entry = archive.by_index(i).unwrap();
                let name = entry.name().unwrap().into_owned();
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                let file_type = crate::analyzers::detect_file_type_from_data(
                    std::path::Path::new(&name),
                    &data,
                );
                MemoryArchiveMember {
                    relative_path: name,
                    sha256: calculate_sha256(&data),
                    data: data.into(),
                    file_type,
                    container_kind: None,
                }
            })
            .collect()
    }
    #[test]
    fn pairs_source_and_runtime_in_either_archive_order() {
        for reverse in [false, true] {
            let mut members = members();
            if reverse {
                members.reverse();
            }
            let mut collector = Collector::default();
            for member in &members {
                collector.observe(member);
            }
            let recovered = collector.recover(|_| {}, || false);
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].file_type, FileType::PythonBytecode);
            assert_eq!(&recovered[0].data[2..4], &[13, 10]);
            assert_eq!(recovered[0].data[16] & 0x7f, b'c');
            assert!(recovered[0].data.windows(7).any(|v| v == b"message"));
        }
    }
    #[test]
    fn requires_companion_runtime_and_honors_cancellation_and_budget() {
        let members = members();
        let mut collector = Collector::default();
        collector.observe(
            members
                .iter()
                .find(|m| m.file_type == FileType::Python)
                .unwrap(),
        );
        assert!(collector.recover(|_| {}, || false).is_empty());
        let mut collector = Collector::default();
        for member in &members {
            collector.observe(member);
        }
        assert!(collector.recover(|_| {}, || true).is_empty());
        let mut collector = Collector::default();
        let runtime = members
            .iter()
            .find(|m| m.data.windows(12).any(|v| v == b"pyarmor-vax-"))
            .unwrap();
        for _ in 0..9 {
            collector.observe(runtime);
        }
        assert!(collector.limited);
        assert_eq!(collector.runtimes.len(), 8);
    }
}
