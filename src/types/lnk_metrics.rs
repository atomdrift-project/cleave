//! LNK (Windows Shell Link) derived metrics.
//!
//! These are computed from the parsed LNK structure rather than read directly
//! from the file. Raw file fields (`target_path`, `arguments`, `working_dir`,
//! `icon_location`, `show_command`, `hotkey`, LinkInfo volume/network fields)
//! remain queryable via `type: kv`;
//! the flags and whitespace statistics here are queryable via `type: metrics,
//! field: lnk.*` with numeric/boolean thresholds.

use super::{is_false, is_zero_i32, is_zero_u32};
use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

/// Derived metrics for a Windows Shell Link file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct LnkMetrics {
    /// Link header flag: HAS_LINK_TARGET_ID_LIST bit is set.
    pub has_link_target_id_list: bool,
    /// Link header flag: HAS_LINK_INFO bit is set.
    pub has_link_info: bool,
    /// Link header flag: HAS_NAME bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_name: bool,
    /// Link header flag: HAS_RELATIVE_PATH bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_relative_path: bool,
    /// Link header flag: HAS_ARGUMENTS bit is set.
    pub has_arguments: bool,
    /// Link header flag: HAS_WORKING_DIR bit is set.
    pub has_working_dir: bool,
    /// Link header flag: HAS_ICON_LOCATION bit is set.
    pub has_icon_location: bool,
    /// Link header flag: HAS_EXP_STRING bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_exp_string: bool,
    /// Link header flag: HAS_DARWIN_ID bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_darwin_id: bool,
    /// Link header flag: HAS_EXP_ICON bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_exp_icon: bool,
    /// Link header flag: RUN_AS_USER bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub run_as_user: bool,
    /// Link header flag: RUN_WITH_SHIM_LAYER bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub run_with_shim_layer: bool,
    /// Link header flag: FORCE_NO_LINK_TRACK bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub force_no_link_track: bool,
    /// Link header flag: ENABLE_TARGET_METADATA bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enable_target_metadata: bool,
    /// Link header flag: DISABLE_LINK_PATH_TRACKING bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_link_path_tracking: bool,
    /// Link header flag: DISABLE_KNOWN_FOLDER_TRACKING bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_known_folder_tracking: bool,
    /// Link header flag: DISABLE_KNOWN_FOLDER_ALIAS bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_known_folder_alias: bool,
    /// Link header flag: ALLOW_LINK_TO_LINK bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_link_to_link: bool,
    /// Link header flag: UNALIAS_ON_SAVE bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unalias_on_save: bool,
    /// Link header flag: PREFER_ENVIRONMENT_PATH bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prefer_environment_path: bool,
    /// Link header flag: KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET bit is set.
    #[serde(default, skip_serializing_if = "is_false")]
    pub keep_local_id_list_for_unc_target: bool,
    /// ExtraData contains a TrackerDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_tracker_data: bool,
    /// ExtraData contains an EnvironmentVariableDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_environment_variable_data: bool,
    /// ExtraData contains an IconEnvironmentDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_icon_environment_data: bool,
    /// ExtraData contains a DarwinDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_darwin_data: bool,
    /// ExtraData contains a ShimDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_shim_data: bool,
    /// ExtraData contains a KnownFolderDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_known_folder_data: bool,
    /// ExtraData contains a SpecialFolderDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_special_folder_data: bool,
    /// ExtraData contains a PropertyStoreDataBlock.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_property_store_data: bool,
    /// LinkInfo contains a CommonNetworkRelativeLink target.
    #[serde(default, skip_serializing_if = "is_false")]
    pub target_is_on_network: bool,
    /// Target attributes mark the target hidden.
    #[serde(default, skip_serializing_if = "is_false")]
    pub target_is_hidden: bool,
    /// Target attributes mark the target as a directory.
    #[serde(default, skip_serializing_if = "is_false")]
    pub target_is_directory: bool,

    /// Link target size from the LNK header.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub target_size: u32,
    /// Raw link target file attribute bits from the LNK header.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub target_attributes: u32,
    /// Icon index from the LNK header.
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub icon_index: i32,

    /// Leading space characters in the arguments field.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_leading_spaces: u32,
    /// Leading tab characters in the arguments field.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_leading_tabs: u32,
    /// Total whitespace characters in the arguments field.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_whitespace_total: u32,
    /// Longest whitespace run in the arguments field
    ///
    /// High values (>=50) match the ZDI-CAN-25373 obfuscation pattern.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args_max_whitespace_run: u32,
    /// Arguments contain excessive whitespace obfuscation
    pub args_excessive_whitespace: bool,
}
