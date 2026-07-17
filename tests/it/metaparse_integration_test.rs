//! Retired with the cleave→filefacts migration.
//!
//! These tests verified the `metaparse` crate's `ParsedFile` plumbing
//! into cleave's evaluation entry. `metaparse` was retired and its
//! responsibilities split into filefacts (`filefacts::ParsedFile` via
//! `filefacts::open()`) and metafile (file-type detection). The
//! `EvaluationContext.parsed` field now carries an `filefacts::ParsedFile`
//! directly; that integration is exercised by `tests/filefacts_view_test.rs`
//! and the broader trait/composite test suites.
