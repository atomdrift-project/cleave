//! Retired with the cleave→expose migration.
//!
//! These tests asserted that Mach-O binary metrics were populated on
//! `AnalysisReport.metrics`. That field, the per-format metric
//! collection paths in cleave, and the radare2-failure fallback they
//! exercised all moved into expose (`expose/src/formats/macho.rs`,
//! `expose/src/rizin.rs`). The equivalent coverage lives in expose's
//! lib tests under `formats::macho::tests::*` and `rizin_impl::tests`.
