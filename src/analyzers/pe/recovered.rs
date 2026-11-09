//! Payloads recovered from inside a PE — unpacked, decrypted or carved
//! resources — each analyzed as its own member of the host.
//!
//! Every recoverer decodes bytes; none executes the sample. A recovered child
//! never scans for further embedded images, so recovery cannot recurse.

use super::PEAnalyzer;
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::types::AnalysisReport;
use anyhow::Result;
use std::path::Path;

/// One recovered payload to analyze as a member of the host.
struct Recovered<'a> {
    /// The member's path inside the host, e.g. `mpress/resource-1a0.exe`.
    member_path: String,
    /// Extension of the temporary file the child is analyzed from.
    suffix: &'a str,
    data: &'a [u8],
    kind: crate::FileType,
    /// Encoding chain recorded on the member, `/`-separated.
    encoding: &'a str,
    /// What the member is, for the error recorded when it cannot be analyzed.
    label: &'a str,
}

impl PEAnalyzer {
    /// Recover every payload the extractors recognize in `pe_data` and attach
    /// each to `report` as a member.
    pub(super) fn analyze_recovered_payloads(
        &self,
        report: &mut AnalysisReport,
        pe_data: &[u8],
        logical_path: &Path,
    ) {
        if self.skip_embedded_scan {
            return;
        }
        // MPRESS resources, by bounded LZMA decoding.
        match unpack::mpress::recover(pe_data) {
            Ok(resources) => {
                for resource in resources {
                    if self.is_cancelled() {
                        break;
                    }
                    let (kind, suffix) = if resource.executable {
                        (crate::FileType::Pe, "exe")
                    } else {
                        (crate::FileType::Text, "txt")
                    };
                    self.attach_recovered(
                        report,
                        logical_path,
                        &Recovered {
                            member_path: format!("mpress/resource-{:x}.{suffix}", resource.rva),
                            suffix,
                            data: &resource.data,
                            kind,
                            encoding: "mpress-lzma",
                            label: "MPRESS resource analysis",
                        },
                    );
                }
            }
            Err(error) => tracing::debug!(%error, "MPRESS recovery failed"),
        }

        // Node single-executable-application resources: source and assets.
        for member in unpack::node_sea::recover(pe_data).unwrap_or_default() {
            if self.is_cancelled() {
                break;
            }
            let kind = if member.javascript {
                crate::FileType::JavaScript
            } else if member.data.starts_with(b"MZ") {
                crate::FileType::Pe
            } else {
                crate::FileType::Data
            };
            let suffix = match kind {
                crate::FileType::JavaScript => "cjs",
                crate::FileType::Pe => "dll",
                _ => "bin",
            };
            self.attach_recovered(
                report,
                logical_path,
                &Recovered {
                    member_path: format!("node-sea/{}", member.name),
                    suffix,
                    data: &member.data,
                    kind,
                    encoding: "node-sea-resource",
                    label: "Node SEA member analysis",
                },
            );
        }

        // The x86 NRV2B stub's memory image: imports unresolved, never run.
        if self.engine.upx() && !self.is_cancelled() {
            match unpack::nrv32::recover(pe_data) {
                Ok(Some(data)) => {
                    self.attach_recovered(
                        report,
                        logical_path,
                        &Recovered {
                            member_path: "nrv2b/memory-image.dll".to_string(),
                            suffix: "dll",
                            data: &data,
                            kind: crate::FileType::Pe,
                            encoding: "nrv2b-memory-image",
                            label: "NRV memory-image analysis",
                        },
                    );
                }
                Ok(None) => {}
                Err(error) => report
                    .metadata
                    .errors
                    .push(format!("NRV recovery diagnostic: {error}")),
            }
        }

        // A DLL inside a feedback-stream and RC4 envelope.
        if !self.is_cancelled()
            && let Some(payload) = unpack::metamorphic_graft::recover(pe_data)
        {
            let attached = self.attach_recovered(
                report,
                logical_path,
                &Recovered {
                    member_path: format!("feedback-rc4/payload-{}.dll", payload.offset),
                    suffix: "dll",
                    data: &payload.data,
                    kind: crate::FileType::Pe,
                    encoding: "feedback-stream-rc4",
                    label: "Feedback/RC4 DLL",
                },
            );
            if attached {}
        }

        // PE files in a code-relative RC4 table.
        for payload in unpack::rc4_pe_table::recover(pe_data) {
            if self.is_cancelled() {
                break;
            }
            self.attach_recovered(
                report,
                logical_path,
                &Recovered {
                    member_path: format!("rc4-table/payload-{}.exe", payload.offset),
                    suffix: "exe",
                    data: &payload.data,
                    kind: crate::FileType::Pe,
                    encoding: "rc4-table",
                    label: "RC4 table member",
                },
            );
        }

        // Fragmented AES-GCM envelopes and hex/RC4 next-byte envelopes.
        let mut sealed = unpack::fragment_gcm_pe::recover_chain(pe_data);
        if let Some(payload) = unpack::hex_rc4_nextbyte::recover(pe_data) {
            sealed.push((
                unpack::fragment_gcm_pe::Member {
                    offset: payload.offset,
                    data: payload.data,
                },
                "hex-rc4-nextbyte",
            ));
        }
        for (payload, encoding) in sealed {
            if self.is_cancelled() {
                break;
            }
            self.attach_recovered(
                report,
                logical_path,
                &Recovered {
                    member_path: format!("{encoding}/payload-{}.exe", payload.offset),
                    suffix: "exe",
                    data: &payload.data,
                    kind: crate::FileType::Pe,
                    encoding,
                    label: "Fragmented GCM member",
                },
            );
        }

        self.analyze_converter_scripts(report, pe_data, logical_path);
    }

    /// Analyze `recovered` as a member of the host and attach it to `report`.
    /// Returns whether it was attached; a failure is recorded in the report.
    fn attach_recovered(
        &self,
        report: &mut AnalysisReport,
        logical_path: &Path,
        recovered: &Recovered<'_>,
    ) -> bool {
        let virtual_path = format!("{}!{}", logical_path.display(), recovered.member_path);
        let child = (|| -> Result<AnalysisReport> {
            let temp = tempfile::Builder::new()
                .suffix(&format!(".{}", recovered.suffix))
                .tempfile()?;
            std::fs::write(temp.path(), recovered.data)?;
            let input =
                AnalysisInput::new(Path::new(&virtual_path), recovered.data, recovered.kind)
                    .with_backing_path(temp.path())
                    .at_depth(1);
            if recovered.kind == crate::FileType::Pe {
                let mut analyzer = PEAnalyzer::new()
                    .with_engine(self.engine.clone())
                    .with_cancellation(self.cancellation.clone())
                    .without_embedded_scan();
                if let Some(yara) = &self.yara_engine {
                    analyzer = analyzer.with_yara_arc(yara.clone());
                }
                analyzer.analyze_input(&input)
            } else {
                crate::analyzers::generic::GenericAnalyzer::new(recovered.kind)
                    .with_engine(self.engine.clone())
                    .analyze_input(&input)
            }
        })();
        match child {
            Ok(child) => {
                let first = report.files.len();
                crate::analyzers::subfile::attach_member(
                    report,
                    child,
                    recovered.data,
                    recovered.kind,
                    &recovered.member_path,
                    &virtual_path,
                    &self.engine,
                );
                if let Some(file) = report.files.get_mut(first) {
                    file.encoding =
                        Some(recovered.encoding.split('/').map(str::to_string).collect());
                }
                true
            }
            Err(error) => {
                report
                    .metadata
                    .errors
                    .push(format!("{}: {error:#}", recovered.label));
                false
            }
        }
    }

    /// PowerShell scripts in a converter's RC4 resource: the decoded script owns
    /// its behavioral findings, the host records the encoding.
    fn analyze_converter_scripts(
        &self,
        report: &mut AnalysisReport,
        pe_data: &[u8],
        logical_path: &Path,
    ) {
        for payload in unpack::ps_to_exe::recover(pe_data) {
            if self.is_cancelled() {
                break;
            }
            let member_path = format!("ps-to-exe/resource-{}.ps1", payload.offset);
            let virtual_path = format!("{}!{}", logical_path.display(), member_path);
            let input = AnalysisInput::new(
                Path::new(&virtual_path),
                &payload.data,
                crate::FileType::PowerShell,
            )
            .at_depth(1);
            let analyzed = crate::analyzers::unified::UnifiedSourceAnalyzer::for_file_type(
                &crate::FileType::PowerShell,
            )
            .map(|a| a.with_engine(self.engine.clone()).analyze_input(&input));
            match analyzed {
                Some(Ok(child)) => {
                    crate::analyzers::subfile::attach_member(
                        report,
                        child,
                        &payload.data,
                        crate::FileType::PowerShell,
                        &member_path,
                        &virtual_path,
                        &self.engine,
                    );
                }
                Some(Err(error)) => report
                    .metadata
                    .errors
                    .push(format!("ps-to-exe resource: {error:#}")),
                None => {}
            }
        }
    }
}
