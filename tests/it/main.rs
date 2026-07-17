//! Consolidated integration-test crate.
//!
//! All integration tests live here as modules of a single test target, so
//! the `cleave` rlib links once instead of once per file (see
//! `docs/FAST_SAFE_TESTING_PLAN.md`, Phase 1). Add a new integration test by
//! dropping `tests/it/<name>.rs` and a `mod <name>;` line below.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

mod amos_traits_test;
mod apk_alpine_data_segment_test;
mod archive_determinism_test;
mod archive_member_payload_parity_test;
mod archive_tmp_regression;
mod ast_call_kind_cached_scan_test;
mod ast_call_kind_coverage;
mod batch_filefacts_view_test;
mod benign_binary_test;
mod binary_metrics_collection_test;
mod binary_traits_test;
mod chm_integration_test;
mod cli_integration_test;
mod cli_kv_office_test;
mod cli_kv_source_test;
mod diff_test;
mod directory_scan_test;
mod embedded_code_detection_test;
mod embedded_sfx_test;
mod format_emission_test;
mod ghostpenguin_extended_test;
mod host_info_composite_test;
mod json_rejection_test;
mod keylogger_detection_test;
mod known_bad_test;
mod metaparse_integration_test;
mod office_corpus_test;
mod php_ast_call_kind_regression;
mod string_vs_content_test;
mod subfile_pipeline_test;
mod symbol_extraction_test;
mod systemd_kv_test;
mod test_match_location_test;
mod tiny_manifest_value_traits_test;
mod trait_migration_regression_test;
mod trait_strictness_test;
mod utf16_pe_text_search_test;
mod utf16_support_test;
mod utf16_text_normalization_test;
mod utf16_trait_regression_test;
mod xor_source_detection_test;
mod yaml_capability_filtering_test;
mod yara_filtering_test;
mod yara_init_no_deadlock;
