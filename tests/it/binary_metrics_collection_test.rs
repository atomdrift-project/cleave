//! Retired with the cleave→filefacts migration.
//!
//! These tests asserted that Mach-O binary metrics were populated on
//! `AnalysisReport.metrics`. That field, the per-format metric
//! collection paths in cleave, and the radare2-failure fallback they
//! exercised all moved into filefacts (`filefacts/src/formats/macho.rs`,
//! `filefacts/src/rizin.rs`). The equivalent coverage lives in filefacts's
//! lib tests under `formats::macho::tests::*` and `rizin_impl::tests`.
