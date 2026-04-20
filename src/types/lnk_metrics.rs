//! LNK (Windows Shell Link) derived metrics.
//!
//! These are computed from the parsed LNK structure rather than read directly
//! from the file. Raw file fields (`target_path`, `arguments`, `working_dir`,
//! `icon_location`, `show_command`, `hotkey`) remain queryable via `type: kv`;
//! the flags and whitespace statistics here are queryable via `type: metrics,
//! field: lnk.*` with numeric/boolean thresholds.

use super::is_zero_u32;
use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

/// Derived metrics for a Windows Shell Link file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct LnkMetrics {
    /// Link header flag: HAS_LINK_TARGET_ID_LIST bit is set.
    pub has_link_target_id_list: bool,
    /// Link header flag: HAS_LINK_INFO bit is set.
    pub has_link_info: bool,
    /// Link header flag: HAS_ARGUMENTS bit is set.
    pub has_arguments: bool,
    /// Link header flag: HAS_WORKING_DIR bit is set.
    pub has_working_dir: bool,
    /// Link header flag: HAS_ICON_LOCATION bit is set.
    pub has_icon_location: bool,

    /// Leading space characters in the arguments field.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_leading_spaces: u32,
    /// Leading tab characters in the arguments field.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_leading_tabs: u32,
    /// Total whitespace characters in the arguments field.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_whitespace_total: u32,
    /// Longest consecutive whitespace run in the arguments field.
    /// High values (>=50) match the ZDI-CAN-25373 obfuscation pattern.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_max_whitespace_run: u32,
    /// True when `args_max_whitespace_run` crosses the obfuscation threshold.
    pub args_excessive_whitespace: bool,
}
