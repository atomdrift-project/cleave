//! Retired with the cleave→expose migration.
//!
//! These tests verified the `metaparse` crate's `ParsedFile` plumbing
//! into cleave's evaluation entry. `metaparse` was retired and its
//! responsibilities split into expose (`expose::ParsedFile` via
//! `expose::open()`) and metafile (file-type detection). The
//! `EvaluationContext.parsed` field now carries an `expose::ParsedFile`
//! directly; that integration is exercised by `tests/expose_view_test.rs`
//! and the broader trait/composite test suites.
