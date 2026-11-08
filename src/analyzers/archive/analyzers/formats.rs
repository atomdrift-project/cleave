//! In-memory member walks for zip, tar, JAR, CHM, ASAR and PHAR archives.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl ArchiveAnalyzer {
    pub(super) fn analyze_zip_archive_from_filefacts_index(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        indexed_entries: &[ArchiveEntry],
        is_jar: bool,
    ) -> Result<bool> {
        if indexed_entries.is_empty() {
            return Ok(false);
        }
        if indexed_entries.len() > super::super::MAX_ZIP_ENTRIES {
            anyhow::bail!(
                "ZIP central directory claims {} entries (max {})",
                indexed_entries.len(),
                super::super::MAX_ZIP_ENTRIES
            );
        }

        for entry in indexed_entries {
            if entry.entry_type.as_deref() == Some("directory") && entry.size_bytes == 0 {
                continue;
            }
            if entry.data_offset.is_none()
                || entry.compressed_size.is_none()
                || entry.compression_method.is_none()
            {
                return Ok(false);
            }
            if !matches!(
                entry.compression_method.as_deref(),
                Some("stored" | "deflate")
            ) {
                return Ok(false);
            }
        }

        let fake_root = Path::new("/__cleave_archive__");
        // JAR main-class detection needs the full member list, so JARs keep the
        // all-resident path; everything else streams through a byte-windowed
        // accumulator that never holds more than one window of members resident.
        // The scope hosts the window's pipelined consumer; every exit path
        // (including the mid-loop `return Ok(false)` fallbacks) drops the
        // window and its channel before the scope joins, so it cannot hang.
        std::thread::scope(|scope| -> Result<bool> {
            let mut window = MemberWindow::new_in(scope, self, "filefacts ZIP index");
            let mut jar_members: Vec<MemoryArchiveMember> = Vec::new();
            let mut pyarmor = pyarmor_members::Collector::default();
            let mut rc4 = (report.target.file_type == FileType::ApkAndroid.report_file_type())
                .then(rc4_members::Collector::default);

            for entry in indexed_entries {
                if self.is_cancelled() {
                    anyhow::bail!("Analysis cancelled during ZIP member read");
                }
                // Stop at the member cap rather than failing: the members read
                // so far are analyzed by the `finalize` below, and
                // `check_file_count` has already recorded the hostile reason
                // that makes the truncation visible as a finding.
                if !guard.check_file_count() {
                    guard.add_extraction_note(format!(
                        "stopped after the {} member cap",
                        super::super::guards::MAX_FILE_COUNT
                    ));
                    break;
                }

                let entry_name = entry.path.clone();
                if entry_name.len() > MAX_PATH_COMPONENT_LEN {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                        len: entry_name.len(),
                        preview: entry_name.chars().take(80).collect(),
                    });
                }

                let Some(outpath) = sanitize_entry_path(&entry_name, fake_root) else {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                    continue;
                };
                let relative_path = outpath
                    .strip_prefix(fake_root)
                    .unwrap_or(&outpath)
                    .to_string_lossy()
                    .replace('\\', "/");
                let entry_type_label = entry.entry_type.as_deref().unwrap_or("regular");

                if entry_type_label == "directory" {
                    if entry.size_bytes == 0 {
                        continue;
                    }
                    // A "directory" entry that carries data is a file to the
                    // JVM: ZipFile.getEntry("a/B.class") falls back to
                    // "a/B.class/", and class-hiding obfuscators (Caesium)
                    // store every class that way so extractors skip it.
                    guard.add_extraction_note(format!(
                        "{entry_name}: directory entry carries {} bytes; analyzed as a file",
                        entry.size_bytes
                    ));
                }

                // One encrypted member does not make the rest unreadable.
                if entry.encrypted
                    && super::super::zip::read_verified_plaintext_member(data, entry, MAX_FILE_SIZE)
                        .is_err()
                {
                    guard.add_extraction_note(format!("{entry_name}: encrypted, skipped"));
                    continue;
                }

                // A symlink-mode entry records its target, but no link is
                // made: the JVM, Android and pip ignore unix modes and load it
                // as an ordinary file, so its bytes are analyzed below too.
                if entry_type_label == "symlink"
                    && let Some(target) = super::super::zip::read_indexed_member(data, entry, 4096)
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                    && symlink_escapes(&outpath, &target, fake_root)
                {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                        "{entry_name} -> {target}"
                    )));
                }
                guard.record_member_metadata(super::super::guards::ExtractedMemberMetadata {
                    archive_path: relative_path.clone(),
                    entry_type: Some(entry_type_label.to_string()),
                });

                let compressed = entry.compressed_size.unwrap_or(0);
                let uncompressed = entry.size_bytes;
                if !guard.check_compression_ratio(compressed, uncompressed) {
                    continue;
                }
                if uncompressed > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name,
                        size: uncompressed,
                    });
                    continue;
                }

                // Read no further than the declared size, which the ratio
                // check trusted: a few KB of deflate can otherwise inflate to
                // gigabytes in memory. A member that inflates past it keeps
                // its declared bytes, as readers that trust the header do.
                let Ok((file_data, overran)) =
                    super::super::zip::read_indexed_member_prefix(data, entry, uncompressed)
                else {
                    return Ok(false);
                };
                if overran {
                    guard.add_extraction_note(format!(
                        "{relative_path}: inflates past its declared {uncompressed} bytes; kept those"
                    ));
                }
                let written = file_data.len() as u64;
                // Same as the member cap: stop, keep, and let the recorded
                // hostile reason speak for the archive.
                if !guard.check_bytes(written, &relative_path) {
                    guard.add_extraction_note(
                        "stopped at the total extraction size cap".to_string(),
                    );
                    break;
                }

                let logical_path = Path::new(&relative_path);
                let file_type =
                    crate::analyzers::detect_file_type_from_data(logical_path, &file_data);
                let sha256 = calculate_sha256(&file_data);
                let member = MemoryArchiveMember {
                    relative_path,
                    data: file_data.into(),
                    file_type,
                    sha256,
                    container_kind: None,
                };
                pyarmor.observe(&member);
                if let Some(rc4) = rc4.as_mut() {
                    rc4.observe(&member, &|| self.is_cancelled());
                }
                if is_jar {
                    jar_members.push(member);
                } else {
                    window.push(member);
                }
            }

            if let Some(rc4) = rc4 {
                for recovered in rc4.recover(
                    |message| {
                        report.metadata.errors.push(message);
                        report
                            .analysis_gaps
                            .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
                    },
                    self.cancelled.as_deref(),
                ) {
                    if !guard.check_file_count()
                        || !guard.check_bytes(
                            recovered.member.data.len() as u64,
                            &recovered.member.relative_path,
                        )
                    {
                        guard.add_extraction_note(
                            "RC4 code-asset recovery exceeded the archive extraction budget".into(),
                        );
                        break;
                    }
                    recovered.record_provenance(report);
                    window.push(recovered.member);
                }
            }

            for member in pyarmor.recover(
                |message| guard.add_extraction_note(message),
                || self.is_cancelled(),
            ) {
                if is_jar {
                    jar_members.push(member);
                } else {
                    window.push(member);
                }
            }
            if is_jar {
                self.analyze_jar_members_in_memory(&jar_members, archive_path, report, start);
            } else {
                window.finalize(
                    report,
                    start,
                    "ZIP archive",
                    vec![
                        "archive_analyzer".to_string(),
                        "filefacts_zip_index".to_string(),
                    ],
                );
            }
            Ok(true)
        })
    }

    /// Analyze ZIP/JAR-style archives without materializing the whole archive
    /// tree under `/tmp`. Members are read into bounded in-memory buffers and
    /// handed to the same member analyzers used by the extracted-directory path.
    pub(in super::super) fn analyze_zip_archive_in_memory(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        indexed_entries: &[ArchiveEntry],
        is_jar: bool,
    ) -> Result<()> {
        if self.analyze_zip_archive_from_filefacts_index(
            data,
            archive_path,
            report,
            start,
            guard,
            indexed_entries,
            is_jar,
        )? {
            return Ok(());
        }

        let mut archive = ::zip::ZipArchive::new(std::io::Cursor::new(data))
            .map_err(|e| anyhow::anyhow!("Failed to read ZIP archive: {e}"))?;
        if archive.len() > super::super::MAX_ZIP_ENTRIES {
            anyhow::bail!(
                "ZIP central directory claims {} entries (max {})",
                archive.len(),
                super::super::MAX_ZIP_ENTRIES
            );
        }

        let fake_root = Path::new("/__cleave_archive__");

        // Members stream through a byte-windowed accumulator: each window is
        // analyzed in parallel then dropped, so resident decompressed bytes and
        // the report transient stay bounded regardless of member count. JARs
        // need the full member list for main-class detection, so they keep the
        // all-resident path.
        // Scope for the window's pipelined consumer; all exit paths drop the
        // window (and its sender) before the join.
        std::thread::scope(|scope| -> Result<()> {
            let mut window = MemberWindow::new_in(scope, self, "memory ZIP");
            let mut jar_members: Vec<MemoryArchiveMember> = Vec::new();
            let mut pyarmor = pyarmor_members::Collector::default();
            let mut rc4 = (report.target.file_type == FileType::ApkAndroid.report_file_type())
                .then(rc4_members::Collector::default);

            for i in 0..archive.len() {
                if self.is_cancelled() {
                    anyhow::bail!("Analysis cancelled during ZIP member read");
                }
                if !guard.check_file_count() {
                    guard.add_extraction_note(format!(
                        "stopped after the {} member cap",
                        super::super::guards::MAX_FILE_COUNT
                    ));
                    break;
                }

                // A member whose local header is unreadable (truncated tail,
                // corrupt central directory) costs us that member, not the
                // archive: this path analyzes in memory with no temp_dir for
                // `analyze_archive_with_data` to fall back on, so bailing here
                // would discard every member already read.
                let mut entry = match archive.by_index(i) {
                    Ok(entry) => entry,
                    Err(e) => {
                        guard.add_extraction_note(format!("ZIP member {i} unreadable: {e}"));
                        continue;
                    }
                };
                let entry_name = entry.name().map_or_else(
                    |_| String::from_utf8_lossy(entry.name_raw()).into_owned(),
                    std::borrow::Cow::into_owned,
                );
                if entry_name.len() > MAX_PATH_COMPONENT_LEN {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                        len: entry_name.len(),
                        preview: entry_name.chars().take(80).collect(),
                    });
                }

                let Some(outpath) = sanitize_entry_path(&entry_name, fake_root) else {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                    continue;
                };
                let relative_path = outpath
                    .strip_prefix(fake_root)
                    .unwrap_or(&outpath)
                    .to_string_lossy()
                    .replace('\\', "/");

                let entry_is_dir = entry.is_dir();
                let entry_is_symlink = entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000);
                let entry_type_label = if entry_is_dir {
                    "directory"
                } else if entry_is_symlink {
                    "symlink"
                } else {
                    "regular"
                };

                if let Some(mode) = entry.unix_mode()
                    && mode & 0o170000 == 0o120000
                {
                    let mut target_buf = Vec::new();
                    let mut limited = LimitedReader::new(&mut entry, 4096);
                    if let Ok(read_size) = limited.read_to_end(&mut target_buf)
                        && read_size > 0
                        && read_size < 4096
                        && let Ok(target_str) = String::from_utf8(target_buf)
                        && symlink_escapes(&outpath, &target_str, fake_root)
                    {
                        guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                            "{entry_name} -> {target_str}"
                        )));
                    }
                    guard.record_member_metadata(super::super::guards::ExtractedMemberMetadata {
                        archive_path: relative_path.clone(),
                        entry_type: Some(entry_type_label.to_string()),
                    });
                    // The JVM, Android and pip ignore unix modes and load this
                    // entry as an ordinary file: analyze its bytes as well.
                    drop(entry);
                    entry = match archive.by_index(i) {
                        Ok(entry) => entry,
                        Err(e) => {
                            guard.add_extraction_note(format!("ZIP member {i} unreadable: {e}"));
                            continue;
                        }
                    };
                } else if entry.is_dir() && entry.size() == 0 {
                    continue;
                } else {
                    // A "directory" entry that carries data is a file to the
                    // JVM: ZipFile.getEntry("a/B.class") falls back to
                    // "a/B.class/", and class-hiding obfuscators (Caesium)
                    // store every class that way so extractors skip it.
                    if entry_is_dir {
                        guard.add_extraction_note(format!(
                            "{entry_name}: directory entry carries {} bytes; analyzed as a file",
                            entry.size()
                        ));
                    }
                    guard.record_member_metadata(super::super::guards::ExtractedMemberMetadata {
                        archive_path: relative_path.clone(),
                        entry_type: Some(entry_type_label.to_string()),
                    });
                }
                if entry.encrypted() {
                    guard.add_extraction_note(format!("{entry_name}: encrypted, skipped"));
                    continue;
                }

                let compressed = entry.compressed_size();
                let uncompressed = entry.size();
                if !guard.check_compression_ratio(compressed, uncompressed) {
                    continue;
                }
                if uncompressed > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name,
                        size: uncompressed,
                    });
                    continue;
                }

                let mut file_data = Vec::with_capacity(uncompressed.min(16 * 1024 * 1024) as usize);
                // A member's deflate stream can end early or fail its CRC while
                // the members around it are intact. Keep what decoded and move
                // on: the bytes are genuine, and there is no on-disk fallback
                // here to salvage the archive if we abort.
                //
                // The stream is read to its declared size and one byte more.
                // The ratio check above trusts that size, so a member that
                // inflates past it is a bomb aimed at memory: keep the declared
                // bytes, as readers that trust the header do, and say so. (The
                // zip crate stops there itself today; this does not rely on it.)
                let cap = uncompressed.saturating_add(1);
                let read = if let Some(c) = guard.cancellation() {
                    let mut cancellable = CancellableReader::new(&mut entry, c);
                    let mut limited = LimitedReader::new(&mut cancellable, cap);
                    read_member_tolerant(&mut limited, &relative_path, guard, &mut file_data)
                } else {
                    let mut limited = LimitedReader::new(&mut entry, cap);
                    read_member_tolerant(&mut limited, &relative_path, guard, &mut file_data)
                };
                // `None` is a member that produced nothing before failing —
                // there is no content to analyze, so skip it. A genuinely empty
                // member reads back as `Some(0)` and is kept, as before.
                let Some(mut written) = read else {
                    continue;
                };
                if written > uncompressed {
                    guard.add_extraction_note(format!(
                        "{relative_path}: inflates past its declared {uncompressed} bytes; kept those"
                    ));
                    file_data.truncate(usize::try_from(uncompressed).unwrap_or(usize::MAX));
                    written = uncompressed;
                }
                if !guard.check_bytes(written, &relative_path) {
                    guard.add_extraction_note(
                        "stopped at the total extraction size cap".to_string(),
                    );
                    break;
                }

                let logical_path = Path::new(&relative_path);
                let file_type =
                    crate::analyzers::detect_file_type_from_data(logical_path, &file_data);
                let sha256 = calculate_sha256(&file_data);
                let member = MemoryArchiveMember {
                    relative_path,
                    data: file_data.into(),
                    file_type,
                    sha256,
                    container_kind: None,
                };
                pyarmor.observe(&member);
                if let Some(rc4) = rc4.as_mut() {
                    rc4.observe(&member, &|| self.is_cancelled());
                }
                if is_jar {
                    jar_members.push(member);
                } else {
                    window.push(member);
                }
            }

            if let Some(rc4) = rc4 {
                for recovered in rc4.recover(
                    |message| {
                        report.metadata.errors.push(message);
                        report
                            .analysis_gaps
                            .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
                    },
                    self.cancelled.as_deref(),
                ) {
                    if !guard.check_file_count()
                        || !guard.check_bytes(
                            recovered.member.data.len() as u64,
                            &recovered.member.relative_path,
                        )
                    {
                        guard.add_extraction_note(
                            "RC4 code-asset recovery exceeded the archive extraction budget".into(),
                        );
                        break;
                    }
                    recovered.record_provenance(report);
                    window.push(recovered.member);
                }
            }

            for member in pyarmor.recover(
                |message| guard.add_extraction_note(message),
                || self.is_cancelled(),
            ) {
                if is_jar {
                    jar_members.push(member);
                } else {
                    window.push(member);
                }
            }
            if is_jar {
                self.analyze_jar_members_in_memory(&jar_members, archive_path, report, start);
            } else {
                window.finalize(
                    report,
                    start,
                    "ZIP archive",
                    vec!["archive_analyzer".to_string(), "in_memory_zip".to_string()],
                );
            }
            Ok(())
        })
    }

    /// Tar-family twin of [`Self::analyze_zip_archive_in_memory`]: stream the
    /// entries straight from the (decompressing) reader into the member
    /// window instead of extracting to a temp tree and walking it back.
    ///
    /// The temp tree was the archive's serial critical path: on a 9,090-member
    /// npm tarball ~3 s to create the files and ~0.7 s to delete them, three
    /// quarters of it kernel time in NTFS and the filter-driver stack
    /// (Defender scans every file it creates), while 15 pool threads idled.
    /// Guards, hostile-archive reasons and per-member metadata mirror
    /// `tar::extract_tar_entries_safe` one for one, including the disk walk's
    /// depth cap, so the member set and its order are the walk's.
    pub(in super::super) fn analyze_tar_archive_in_memory<R: Read>(
        &self,
        reader: R,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        label: &'static str,
    ) -> Result<()> {
        use super::super::guards::ExtractedMemberMetadata;
        use super::super::tar::tar_entry_type_label;

        // Keep the in-memory reader aligned with archive paths walked from a
        // temporary extraction tree, while scanning through nested package
        // layouts that the former ten-level cap silently omitted.
        let fake_root = Path::new("/__cleave_archive__");
        let mut archive = ::tar::Archive::new(reader);

        // Mirrors the temp-tree path's partial-extraction contract: a
        // truncated or hostile stream stops the walk, and the members read
        // before the cut are still analyzed (with an extraction note) as long
        // as there is at least one; with none, the error surfaces.
        std::thread::scope(|scope| -> Result<()> {
            let mut window = MemberWindow::new_in(scope, self, "memory TAR");
            let mut pyarmor = pyarmor_members::Collector::default();
            let mut pushed = 0usize;
            let mut stop_reason: Option<anyhow::Error> = None;
            let mut entries = archive.entries()?;
            loop {
                if self.is_cancelled() {
                    anyhow::bail!("Analysis cancelled during tar member read");
                }
                if !guard.check_file_count() {
                    stop_reason = Some(anyhow::anyhow!("Exceeded maximum file count"));
                    break;
                }
                let Some(entry_result) = entries.next() else {
                    break;
                };
                let mut entry = match entry_result.context("Failed to read tar entry") {
                    Ok(entry) => entry,
                    Err(e) => {
                        stop_reason = Some(e);
                        break;
                    }
                };
                let entry_path = match entry.path() {
                    Ok(p) => p,
                    Err(e) => {
                        stop_reason = Some(e.into());
                        break;
                    }
                };
                let entry_name = entry_path.to_string_lossy().replace('\\', "/");

                if entry_name.len() > MAX_PATH_COMPONENT_LEN {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                        len: entry_name.len(),
                        preview: entry_name.chars().take(80).collect(),
                    });
                }
                let Some(outpath) = sanitize_entry_path(&entry_name, fake_root) else {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                    continue;
                };

                let entry_type = entry.header().entry_type();
                let outpath = if super::super::tar::carries_file_content(entry_type) {
                    guard.claim_output_path(outpath)
                } else {
                    outpath
                };
                let rel_path = outpath
                    .strip_prefix(fake_root)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| entry_name.clone());
                let linkname_opt = if entry_type.is_symlink() || entry_type.is_hard_link() {
                    entry
                        .link_name()
                        .ok()
                        .flatten()
                        .map(|p| p.to_string_lossy().to_string())
                } else {
                    None
                };

                guard.record_member_metadata(ExtractedMemberMetadata {
                    archive_path: rel_path.clone(),
                    entry_type: Some(tar_entry_type_label(entry_type).to_string()),
                });

                if entry_type.is_symlink() || entry_type.is_hard_link() {
                    if let Some(target_str) = linkname_opt.as_deref()
                        && symlink_escapes(&outpath, target_str, fake_root)
                    {
                        guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                            "{} -> {}",
                            entry_name, target_str
                        )));
                    }
                    continue;
                }
                if !super::super::tar::carries_file_content(entry_type) {
                    continue;
                }

                let size = match entry.header().size() {
                    // Entry::size also honors a PAX logical-size override.
                    Ok(_) => entry.size(),
                    Err(e) => {
                        stop_reason = Some(e.into());
                        break;
                    }
                };
                if size > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size,
                    });
                    continue;
                }

                let mut file_data = super::super::member_data::MemberData::for_tar(size);
                let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
                let mut buf = [0u8; 65536];
                let mut written = 0u64;
                let mut read_err = None;
                loop {
                    if guard.is_cancelled() {
                        anyhow::bail!("cancelled");
                    }
                    let n = match limited.read(&mut buf) {
                        Ok(n) => n,
                        Err(e) => {
                            read_err = Some(
                                anyhow::Error::from(e)
                                    .context(format!("Failed to extract: {}", entry_name)),
                            );
                            break;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    if let Err(error) = file_data.append(&buf[..n]) {
                        read_err = Some(
                            anyhow::Error::from(error)
                                .context(format!("Failed to extract: {}", entry_name)),
                        );
                        break;
                    }
                    written += n as u64;
                }
                // A stream cut inside this member (truncated download, damaged
                // gzip) ends the walk, but the bytes read before the cut are
                // genuine: the last member is often the payload a dropper
                // ships, so analyze the prefix rather than discard it.
                if let Some(e) = read_err {
                    stop_reason = Some(e);
                    if file_data.is_empty() {
                        break;
                    }
                    guard.add_extraction_note(format!(
                        "{rel_path}: member truncated after {written} of {size} bytes"
                    ));
                }
                if limited.is_limited() {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size: MAX_FILE_SIZE,
                    });
                    continue;
                }
                if !guard.check_bytes(written, &entry_name) {
                    stop_reason = Some(anyhow::anyhow!("Exceeded maximum total extraction size"));
                    break;
                }

                let depth = rel_path.split('/').count();
                if depth > super::super::guards::MAX_ARCHIVE_MEMBER_DEPTH {
                    guard.add_extraction_note(format!(
                        "member {depth} levels deep, beyond the {}-level analysis limit: {rel_path}",
                        super::super::guards::MAX_ARCHIVE_MEMBER_DEPTH
                    ));
                    if stop_reason.is_some() {
                        break;
                    }
                    continue;
                }

                let logical_path = Path::new(&rel_path);
                let file_type =
                    crate::analyzers::detect_file_type_from_data(logical_path, &file_data);
                let sha256 = calculate_sha256(&file_data);
                let member = MemoryArchiveMember {
                    relative_path: rel_path,
                    data: file_data,
                    file_type,
                    sha256,
                    container_kind: None,
                };
                pyarmor.observe(&member);
                window.push(member);
                pushed += 1;
                if stop_reason.is_some() {
                    break;
                }
            }
            if let Some(e) = stop_reason {
                if pushed == 0 {
                    return Err(e);
                }
                guard.add_extraction_note(format!(
                    "archive extraction stopped after {pushed} entries: {e}"
                ));
            }
            for member in pyarmor.recover(
                |message| guard.add_extraction_note(message),
                || self.is_cancelled(),
            ) {
                window.push(member);
            }
            window.finalize(
                report,
                start,
                label,
                vec!["archive_analyzer".to_string(), "in_memory_tar".to_string()],
            );
            Ok(())
        })
    }

    /// Phase 1 of jar triage: score every class and optionally run YARA,
    /// restricted to the class buckets. Both extraction modes consume the same
    /// retention decision, independent of their member storage.
    ///
    /// Shared by the in-memory and extracted paths so they cannot drift. They
    /// once did: the extracted path called the unfiltered `scan_file`, which
    /// after rule tiering meant every bucket for every class — 77 buckets ×
    /// 70k classes for h2o.jar, an analysis that never finished and held the
    /// whole rayon pool while it tried.
    pub(super) fn triage_jar_classes<T: Sync>(
        &self,
        yara_engine: Option<&crate::yara_engine::YaraEngine>,
        classes: &[T],
        bytes: impl for<'a> Fn(&'a T) -> Option<std::borrow::Cow<'a, [u8]>> + Sync,
    ) -> Vec<JarClassTriage> {
        let filetypes = FileType::JavaClass.yara_filetypes();
        let filter = (!filetypes.is_empty()).then_some(filetypes.as_slice());
        let alert_ids = jar_inline_alert_ids(self.engine.rules().trait_definitions());
        let indexes: Vec<usize> = (0..classes.len()).collect();
        par_filter_map_members(&indexes, self.members_run_parallel(classes.len()), |&i| {
            if self.is_cancelled() {
                return None;
            }
            let data = bytes(&classes[i])?;
            let score = jar_class_triage_score(&data);
            let scan = if let Some(yara) = yara_engine {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    yara.scan_bytes(&data, filter)
                })) {
                    Ok(Ok(scan)) => scan,
                    Ok(Err(e)) => {
                        debug!("YARA scan failed for class {i}: {e}");
                        YaraScan::default()
                    }
                    Err(_panic) => {
                        tracing::error!(class = i, "panic during YARA scan (caught)");
                        YaraScan::default()
                    }
                }
            } else {
                YaraScan::default()
            };
            Some(JarClassTriage {
                index: i,
                score,
                retain: jar_should_retain_class(&scan, &alert_ids),
                matches: scan.matches,
            })
        })
    }

    pub(super) fn analyze_jar_members_in_memory(
        &self,
        members: &[MemoryArchiveMember],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) {
        let main_class = find_main_class_in_members(members);
        if let Some(ref mc) = main_class {
            debug!("Main-Class: {}", mc);
        }

        // JPHP .phb modules wrap JVM classes rather than naming them .class.
        // Preserve the carrier and expose bounded, structurally parsed children.
        let mut jphp_classes = Vec::new();
        for member in members.iter().filter(|m| m.relative_path.ends_with(".phb")) {
            let (frames, incomplete) = filefacts::recover::jphp_class_frames(&member.data);
            if incomplete {
                report
                    .analysis_gaps
                    .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
            }
            for (offset, len) in frames {
                if jphp_classes.len() >= 1024 {
                    report
                        .analysis_gaps
                        .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
                    break;
                }
                let data = member.data[offset..offset + len].to_vec();
                jphp_classes.push(MemoryArchiveMember {
                    relative_path: format!("{}.classes/{offset:08x}.class", member.relative_path),
                    sha256: calculate_sha256(&data),
                    data: data.into(),
                    file_type: FileType::JavaClass,
                    container_kind: Some("jphp-compiled-class".to_string()),
                });
            }
        }
        let class_members: Vec<&MemoryArchiveMember> = members
            .iter()
            .filter(|m| m.relative_path.ends_with(".class"))
            .chain(jphp_classes.iter())
            .collect();
        let total_class_files = class_members.len();

        let mut flagged_classes = HashSet::<String>::new();
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(50);
        let mut class_scores = vec![0usize; class_members.len()];
        let triage_results =
            self.triage_jar_classes(self.yara_engine.as_deref(), &class_members, |m| {
                Some(std::borrow::Cow::Borrowed(&m.data[..]))
            });
        for triage in triage_results {
            class_scores[triage.index] = triage.score;
            if triage.retain {
                flagged_classes.insert(class_members[triage.index].relative_path.clone());
            }
            for ym in triage.matches {
                if !collected_yara.iter().any(|m: &YaraMatch| m.rule == ym.rule) {
                    collected_yara.push(ym);
                }
            }
        }
        for ym in collected_yara {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }

        let main_class_path = main_class.map(|mc| mc.replace('.', "/") + ".class");
        let mut selected: Vec<&MemoryArchiveMember> = class_members
            .iter()
            .copied()
            .filter(|m| {
                main_class_path
                    .as_ref()
                    .is_some_and(|main| m.relative_path.ends_with(main))
                    || flagged_classes.contains(&m.relative_path)
                    || m.container_kind.as_deref() == Some("jphp-compiled-class")
            })
            .collect();

        let selected_paths: HashSet<&str> = selected
            .iter()
            .map(|member| member.relative_path.as_str())
            .collect();
        let mut sample_candidates: Vec<(usize, &MemoryArchiveMember)> = class_members
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, member)| !selected_paths.contains(member.relative_path.as_str()))
            .collect();
        keep_top_ranked(
            &mut sample_candidates,
            20,
            |(left_idx, left), (right_idx, right)| {
                class_scores[*right_idx]
                    .cmp(&class_scores[*left_idx])
                    .then_with(|| right.data.len().cmp(&left.data.len()))
                    .then_with(|| left.relative_path.cmp(&right.relative_path))
            },
        );
        selected.extend(sample_candidates.into_iter().map(|(_, member)| member));
        let class_paths: Vec<String> = class_members
            .iter()
            .map(|member| member.relative_path.clone())
            .collect();
        let companions = jar_nest_companion_indices(
            &class_paths,
            selected.iter().map(|member| member.relative_path.as_str()),
        );
        selected.extend(companions.into_iter().map(|index| class_members[index]));

        selected.extend(
            members
                .iter()
                .filter(|m| !m.relative_path.ends_with(".class"))
                .filter(|m| is_interesting_jar_resource(Path::new(&m.relative_path), &m.file_type))
                // Members the analysis would skip anyway must not spend the
                // cap: a jar padded with a few hundred opaque `assets/*.db`
                // blobs otherwise pushed its XOR-encoded payload past it.
                .filter(|m| {
                    self.archive_member_analysis_skip_reason(&m.file_type, &m.relative_path)
                        .is_none()
                })
                .take(100),
        );

        let selected_count = selected.len();
        self.analyze_in_memory_member_refs(
            &selected,
            archive_path,
            report,
            start,
            "JAR archive",
            "memory JAR",
            vec![
                "archive_analyzer".to_string(),
                "in_memory_jar".to_string(),
                "java_class_analyzer".to_string(),
            ],
        );
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} selected for full analysis",
            total_class_files,
            flagged_classes.len(),
            selected_count
        ));
    }

    /// Analyze a CHM container entirely in memory. Decodes every internal
    /// file (LZX-decompressing the `MSCompressed/Content` blob in one
    /// shot) and feeds each user-visible entry to the same per-member
    /// pipeline used for ZIP archives. No bytes are written to disk.
    ///
    /// CHM members are by definition help-page payloads — HTML topics,
    /// embedded scripts, sometimes images. cleave's default archive
    /// policy skips "non-program" members (HTML, markdown) unless
    /// `--all-files` is set, but for CHM that policy throws away
    /// exactly the content we need to scan for HTML-Help dropper
    /// patterns. We forward to a clone of `self` whose analysis
    /// options have `all_files = true` so every member gets analyzed.
    pub(in super::super) fn analyze_chm_archive_in_memory(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let contents = crate::analyzers::chm::collect_members(data)?;

        if let Some(bomb) = contents.bomb {
            guard.add_hostile_reason(HostileArchiveReason::ZipBomb {
                compressed: bomb.compressed,
                uncompressed: bomb.uncompressed,
            });
        }
        for path in contents.path_traversals {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(path));
        }

        let mut members = Vec::with_capacity(contents.members.len());
        for m in contents.members {
            if !guard.check_file_count() {
                guard.add_extraction_note(format!(
                    "stopped after the {} member cap",
                    super::super::guards::MAX_FILE_COUNT
                ));
                break;
            }
            if m.data.len() as u64 > super::super::guards::MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: m.relative_path.clone(),
                    size: m.data.len() as u64,
                });
                continue;
            }
            if !guard.check_bytes(m.data.len() as u64, &m.relative_path) {
                guard.add_extraction_note("stopped at the total extraction size cap".to_string());
                break;
            }
            let logical = Path::new(&m.relative_path);
            let file_type = crate::analyzers::detect_file_type_from_data(logical, &m.data);
            let sha256 = calculate_sha256(&m.data);
            members.push(MemoryArchiveMember {
                relative_path: m.relative_path,
                data: m.data.into(),
                file_type,
                sha256,
                container_kind: None,
            });
        }

        // Force `all_files = true` for CHM member analysis. This is the
        // only knob that changes; everything else (depth, mapper, yara,
        // cancellation) carries over via `with_*` chaining.
        let chm_options = match self.analysis_options.as_ref() {
            Some(opts) => crate::AnalysisOptions {
                all_files: true,
                ..(**opts).clone()
            },
            None => crate::AnalysisOptions {
                all_files: true,
                ..Default::default()
            },
        };
        let chm_analyzer = self
            .clone_for_member_analysis()
            .with_analysis_options(std::sync::Arc::new(chm_options));

        chm_analyzer.analyze_in_memory_members(
            members,
            archive_path,
            report,
            start,
            "CHM archive",
            "memory CHM",
            vec!["archive_analyzer".to_string(), "in_memory_chm".to_string()],
        );
        Ok(())
    }

    /// Analyze an Electron ASAR container in memory. ASAR member data is
    /// stored uncompressed after the header, so each member filefacts located
    /// (`data_offset`) is sliced directly and routed through normal file-type
    /// detection. Unpacked members live beside the archive and have no offset.
    pub(in super::super) fn analyze_asar_archive_in_memory(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        filefacts_entries: &[ArchiveEntry],
    ) -> Result<()> {
        let entries = filefacts_entries
            .iter()
            .filter_map(|entry| Some((entry.path.clone(), entry.data_offset?, entry.size_bytes)));
        let fake_root = Path::new("/__cleave_archive__");
        // Scope for the window's pipelined consumer; all exit paths drop the
        // window (and its sender) before the join.
        std::thread::scope(|scope| -> Result<()> {
            let mut window = MemberWindow::new_in(scope, self, "memory ASAR");

            for (entry_path, data_offset, entry_size) in entries {
                if self.is_cancelled() {
                    anyhow::bail!("Analysis cancelled during ASAR member read");
                }
                if !guard.check_file_count() {
                    guard.add_extraction_note(format!(
                        "stopped after the {} member cap",
                        super::super::guards::MAX_FILE_COUNT
                    ));
                    break;
                }
                if entry_path.len() > MAX_PATH_COMPONENT_LEN {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                        len: entry_path.len(),
                        preview: entry_path.chars().take(80).collect(),
                    });
                }

                let Some(outpath) = sanitize_entry_path(&entry_path, fake_root) else {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_path));
                    continue;
                };
                let relative_path = outpath
                    .strip_prefix(fake_root)
                    .unwrap_or(&outpath)
                    .to_string_lossy()
                    .replace('\\', "/");

                if entry_size > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_path,
                        size: entry_size,
                    });
                    continue;
                }

                let start_offset = usize::try_from(data_offset).map_err(|e| {
                    anyhow::anyhow!("ASAR member offset exceeds addressable memory: {e}")
                })?;
                let member_size = usize::try_from(entry_size).map_err(|e| {
                    anyhow::anyhow!("ASAR member size exceeds addressable memory: {e}")
                })?;
                let end_offset = start_offset
                    .checked_add(member_size)
                    .ok_or_else(|| anyhow::anyhow!("ASAR member range overflow"))?;
                // A truncated ASAR keeps a valid header, so every member past
                // the cut addresses bytes that aren't there. Skip those and
                // analyze the ones that are — bailing would throw away the
                // members already read, with no temp_dir to recover them from.
                let Some(file_data) = data.get(start_offset..end_offset) else {
                    guard.add_extraction_note(format!(
                        "{relative_path}: ASAR member extends past end of file"
                    ));
                    continue;
                };
                if !guard.check_bytes(file_data.len() as u64, &relative_path) {
                    guard.add_extraction_note(
                        "stopped at the total extraction size cap".to_string(),
                    );
                    break;
                }

                guard.record_member_metadata(super::super::guards::ExtractedMemberMetadata {
                    archive_path: relative_path.clone(),
                    entry_type: Some("regular".to_string()),
                });

                let logical_path = Path::new(&relative_path);
                let file_type =
                    crate::analyzers::detect_file_type_from_data(logical_path, file_data);
                let sha256 = calculate_sha256(file_data);
                let member = MemoryArchiveMember {
                    relative_path,
                    data: file_data.to_vec().into(),
                    file_type,
                    sha256,
                    container_kind: None,
                };
                window.push(member);
            }

            window.finalize(
                report,
                start,
                "ASAR archive",
                vec!["archive_analyzer".to_string(), "in_memory_asar".to_string()],
            );
            Ok(())
        })
    }

    /// Analyze a native phar from the member index filefacts read out of its
    /// manifest. Members are sliced from the loaded bytes and decompressed in
    /// memory (stored, raw deflate, bzip2); nothing runs an external
    /// extractor. The stub (`.phar/stub.php`) comes first and is analyzed like
    /// any other member: it is the PHP that runs when the archive is executed
    /// or included.
    pub(in super::super) fn analyze_phar_archive_in_memory(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        entries: &[ArchiveEntry],
    ) -> Result<()> {
        let fake_root = Path::new("/__cleave_archive__");
        // Scope for the window's pipelined consumer; all exit paths drop the
        // window (and its sender) before the join.
        std::thread::scope(|scope| -> Result<()> {
            let mut window = MemberWindow::new_in(scope, self, "memory phar");

            for entry in entries {
                if self.is_cancelled() {
                    anyhow::bail!("Analysis cancelled during phar member read");
                }
                if entry.entry_type.as_deref() == Some("directory") {
                    continue;
                }
                if !guard.check_file_count() {
                    guard.add_extraction_note(format!(
                        "stopped after the {} member cap",
                        super::super::guards::MAX_FILE_COUNT
                    ));
                    break;
                }
                if entry.path.len() > MAX_PATH_COMPONENT_LEN {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                        len: entry.path.len(),
                        preview: entry.path.chars().take(80).collect(),
                    });
                }

                let Some(outpath) = sanitize_entry_path(&entry.path, fake_root) else {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(
                        entry.path.clone(),
                    ));
                    continue;
                };
                let relative_path = outpath
                    .strip_prefix(fake_root)
                    .unwrap_or(&outpath)
                    .to_string_lossy()
                    .replace('\\', "/");

                guard.record_member_metadata(super::super::guards::ExtractedMemberMetadata {
                    archive_path: relative_path.clone(),
                    entry_type: Some("regular".to_string()),
                });

                if !guard
                    .check_compression_ratio(entry.compressed_size.unwrap_or(0), entry.size_bytes)
                {
                    continue;
                }
                if entry.size_bytes > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry.path.clone(),
                        size: entry.size_bytes,
                    });
                    continue;
                }
                // The manifest declares each member's uncompressed size, so a
                // member that inflates past it is malformed or hostile: the
                // read stops one byte over and the member is skipped.
                let limit = entry.size_bytes.saturating_add(1);
                let file_data = match super::super::zip::read_indexed_member(data, entry, limit) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        guard.add_extraction_note(format!("{relative_path}: {e:#}"));
                        continue;
                    }
                };
                if let Some(expected) = entry.crc32 {
                    let mut crc = flate2::Crc::new();
                    crc.update(&file_data);
                    if crc.sum() != expected {
                        guard.add_extraction_note(format!(
                            "{relative_path}: CRC32 does not match the manifest"
                        ));
                    }
                }
                if !guard.check_bytes(file_data.len() as u64, &relative_path) {
                    guard.add_extraction_note(
                        "stopped at the total extraction size cap".to_string(),
                    );
                    break;
                }

                let logical_path = Path::new(&relative_path);
                let file_type =
                    crate::analyzers::detect_file_type_from_data(logical_path, &file_data);
                let sha256 = calculate_sha256(&file_data);
                window.push(MemoryArchiveMember {
                    relative_path,
                    data: file_data.into(),
                    file_type,
                    sha256,
                    container_kind: None,
                });
            }

            window.finalize(
                report,
                start,
                "phar archive",
                vec!["archive_analyzer".to_string(), "in_memory_phar".to_string()],
            );
            Ok(())
        })
    }

    /// Run the par_iter analysis + aggregation over a prebuilt
    /// `Vec<MemoryArchiveMember>`. Used by both the CHM and PyInstaller
    /// in-memory paths.
    pub(super) fn analyze_in_memory_members(
        &self,
        members: Vec<MemoryArchiveMember>,
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        slow_log_label: &'static str,
        tools_used: Vec<String>,
    ) {
        let total_files = members.len();
        tracing::debug!(
            archive = %archive_path.display(),
            file_count = total_files,
            archive_label,
            "Starting in-memory archive member analysis"
        );

        let mut acc = MemberAccumulator::default();
        par_filter_fold_owned_members(
            members,
            self.members_run_parallel(total_files),
            member_priority,
            |member| self.analyze_one_member(member, slow_log_label),
            |result| acc.fold(result, &self.engine),
        );
        acc.finalize(report, start, archive_label, tools_used, total_files);
    }

    pub(super) fn analyze_in_memory_member_refs(
        &self,
        members: &[&MemoryArchiveMember],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        slow_log_label: &'static str,
        tools_used: Vec<String>,
    ) {
        let total_files = members.len();
        tracing::debug!(
            archive = %archive_path.display(),
            file_count = total_files,
            archive_label,
            "Starting borrowed in-memory archive member analysis"
        );

        let mut acc = MemberAccumulator::default();
        par_filter_fold_members(
            members,
            self.members_run_parallel(members.len()),
            |member| member_priority(member),
            |member| self.analyze_one_member(member, slow_log_label),
            |result| acc.fold(result, &self.engine),
        );
        acc.finalize(report, start, archive_label, tools_used, total_files);
    }

    /// Analyze a single decompressed archive member. Pure per-member work —
    /// no aggregation. Safe to call from `par_iter` or sequentially as
    /// members stream in.
    pub(super) fn analyze_one_member(
        &self,
        member: &MemoryArchiveMember,
        slow_log_label: &'static str,
    ) -> Option<MemberAnalysisResult> {
        let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
        if self.is_cancelled() {
            return None;
        }

        let entry_path = self.format_entry_path(&member.relative_path);
        let archive_location = self.format_evidence_location(&member.relative_path);
        let member_start = std::time::Instant::now();
        if member.data.len() >= 16 * 1024 * 1024 {
            tracing::info!(target: "cleave::native_timing", path = %member.relative_path, "member begin");
        }
        let logical_path = Path::new(&member.relative_path);
        let entry_metadata = archive_entry_metadata(
            entry_path.clone(),
            &member.file_type,
            member.sha256.clone(),
            &member.data,
            member.container_kind.clone(),
        );

        let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
        if member.data.len() >= 16 * 1024 * 1024 {
            tracing::info!(target: "cleave::native_timing", path = %member.relative_path, ms = member_start.elapsed().as_millis() as u64, "member metadata complete");
        }
        let member_report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.analyze_extracted_member(
                logical_path,
                &member.relative_path,
                &member.data,
                &member.file_type,
                &member.sha256,
            )
        })) {
            Ok(Ok(Some(mut r))) => {
                // Matching is done; drop the fields nothing downstream reads so
                // they don't pile up across the archive's members.
                r.clear_unserialized_member_fields();
                Some(r)
            }
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                debug!("Failed to analyze archive member {}: {}", entry_path, e);
                None
            }
            Err(_) => {
                tracing::error!(path = %entry_path, "panic during archive member analysis (caught)");
                FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                None
            }
        };

        let elapsed = member_start.elapsed();
        tracing::debug!(
            relative_path = %member.relative_path,
            file_type = %member.file_type.report_file_type(),
            size_bytes = member.data.len(),
            elapsed_ms = elapsed.as_millis() as u64,
            rayon_thread = ?rayon::current_thread_index(),
            "archive member timing",
        );
        if elapsed.as_millis() > SLOW_ARCHIVE_MEMBER_ANALYSIS_MS {
            tracing::warn!(
                relative_path = %member.relative_path,
                file_type = %member.file_type.report_file_type(),
                size_bytes = member.data.len(),
                elapsed_ms = elapsed.as_millis() as u64,
                rayon_thread = ?rayon::current_thread_index(),
                "Slow archive member analysis ({})",
                slow_log_label,
            );
        }

        Some(MemberAnalysisResult {
            go_source: (member.file_type == FileType::Go).then(|| {
                if member.data.len() <= 2 * 1024 * 1024 {
                    String::from_utf8_lossy(&member.data).into_owned()
                } else {
                    String::new()
                }
            }),
            entry_path,
            archive_location,
            entry_metadata,
            report: member_report,
        })
    }
}
