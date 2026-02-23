//! Section extraction command.
//!
//! Extracts section information from binary files (ELF, PE, Mach-O).
//! Provides section names, addresses, sizes, entropy, and permissions.

use crate::analyzers::{
    detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer, FileType,
};
use crate::cli;
use crate::commands::shared::SectionInfo;
use anyhow::Result;
use std::path::Path;

pub(crate) fn run(target: &str, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let mut sections: Vec<SectionInfo> = Vec::new();

    // Detect file type
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // Binary file - extract sections with addresses
                let capability_mapper = crate::capabilities::CapabilityMapper::empty();
                let report = match file_type {
                    FileType::Elf => ElfAnalyzer::new()
                        .with_capability_mapper(capability_mapper)
                        .analyze(path)?,
                    FileType::MachO => MachOAnalyzer::new()
                        .with_capability_mapper(capability_mapper)
                        .analyze(path)?,
                    FileType::Pe => PEAnalyzer::new()
                        .with_capability_mapper(capability_mapper)
                        .analyze(path)?,
                    _ => anyhow::bail!("unsupported binary file type for section extraction"),
                };

                // Convert sections to output format
                for section in report.sections {
                    sections.push(SectionInfo {
                        name: section.name,
                        address: section.address.map(|addr| format!("0x{:x}", addr)),
                        size: section.size,
                        entropy: section.entropy,
                        permissions: section.permissions,
                    });
                }
            }
            _ => {
                anyhow::bail!(
                    "Unsupported file type for section extraction: {:?}. Only ELF, PE, and Mach-O binaries are supported.",
                    file_type
                );
            }
        }
    } else {
        anyhow::bail!("Unable to detect file type for: {}", target);
    }

    // Sort sections by address (if available), then by name
    sections.sort_by(|a, b| {
        match (&a.address, &b.address) {
            (Some(addr_a), Some(addr_b)) => {
                // Parse hex addresses for proper numeric sorting
                let parse_addr =
                    |s: &str| -> u64 { s.trim_start_matches("0x").parse::<u64>().unwrap_or(0) };
                let num_a = parse_addr(addr_a);
                let num_b = parse_addr(addr_b);
                num_a.cmp(&num_b)
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        }
    });

    // Format output
    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&sections)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} sections from {}\n\n",
                sections.len(),
                target
            ));
            output.push_str(&format!(
                "{:<18} {:<30} {:<12} {:<10} {}\n",
                "ADDRESS", "NAME", "SIZE", "ENTROPY", "PERMISSIONS"
            ));
            output.push_str(&format!(
                "{:-<18} {:-<30} {:-<12} {:-<10} {:-<15}\n",
                "", "", "", "", ""
            ));

            for section in sections {
                let addr = section.address.unwrap_or_else(|| "-".to_string());
                let perms = section.permissions.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "{:<18} {:<30} {:<12} {:<10.2} {}\n",
                    addr, section.name, section.size, section.entropy, perms
                ));
            }

            Ok(output)
        }
    }
}
