//! LNK (Windows Shell Link) file analyzer for cleave
//!
//! Parses Windows shortcut files (.lnk) to extract target paths, arguments,
//! working directory, and other metadata. Detects obfuscation techniques like
//! excessive whitespace padding (ZDI-CAN-25373).
use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::{lnk_metrics::LnkMetrics, AnalysisReport, Metrics, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// LNK file magic bytes: 4C 00 00 00 (header size)
/// followed by CLSID: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
const LNK_MAGIC: &[u8] = &[
    0x4C, 0x00, 0x00, 0x00, // HeaderSize (76 bytes in little-endian)
    0x01, 0x14, 0x02, 0x00, // LinkCLSID start
    0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, // LinkCLSID end
];

/// Threshold for "excessive" whitespace padding (ZDI-CAN-25373)
const EXCESSIVE_WHITESPACE_THRESHOLD: usize = 50;

const LINK_FLAG_HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
const LINK_FLAG_HAS_LINK_INFO: u32 = 0x0000_0002;
const LINK_FLAG_HAS_NAME: u32 = 0x0000_0004;
const LINK_FLAG_HAS_RELATIVE_PATH: u32 = 0x0000_0008;
const LINK_FLAG_HAS_WORKING_DIR: u32 = 0x0000_0010;
const LINK_FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;
const LINK_FLAG_HAS_ICON_LOCATION: u32 = 0x0000_0040;
const LINK_FLAG_IS_UNICODE: u32 = 0x0000_0080;
const LINK_FLAG_HAS_EXP_STRING: u32 = 0x0000_0200;
const LINK_FLAG_HAS_DARWIN_ID: u32 = 0x0000_1000;
const LINK_FLAG_RUN_AS_USER: u32 = 0x0000_2000;
const LINK_FLAG_HAS_EXP_ICON: u32 = 0x0000_4000;
const LINK_FLAG_RUN_WITH_SHIM_LAYER: u32 = 0x0002_0000;
const LINK_FLAG_FORCE_NO_LINK_TRACK: u32 = 0x0004_0000;
const LINK_FLAG_ENABLE_TARGET_METADATA: u32 = 0x0008_0000;
const LINK_FLAG_DISABLE_LINK_PATH_TRACKING: u32 = 0x0010_0000;
const LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING: u32 = 0x0020_0000;
const LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS: u32 = 0x0040_0000;
const LINK_FLAG_ALLOW_LINK_TO_LINK: u32 = 0x0080_0000;
const LINK_FLAG_UNALIAS_ON_SAVE: u32 = 0x0100_0000;
const LINK_FLAG_PREFER_ENVIRONMENT_PATH: u32 = 0x0200_0000;
const LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET: u32 = 0x0400_0000;

const EXTRA_ENVIRONMENT_VARIABLE_DATA: u32 = 0xA000_0001;
const EXTRA_TRACKER_DATA: u32 = 0xA000_0003;
const EXTRA_SPECIAL_FOLDER_DATA: u32 = 0xA000_0005;
const EXTRA_DARWIN_DATA: u32 = 0xA000_0006;
const EXTRA_ICON_ENVIRONMENT_DATA: u32 = 0xA000_0007;
const EXTRA_SHIM_DATA: u32 = 0xA000_0008;
const EXTRA_PROPERTY_STORE_DATA: u32 = 0xA000_0009;
const EXTRA_KNOWN_FOLDER_DATA: u32 = 0xA000_000B;

/// Extracted LNK file data for analysis
#[derive(Debug, Clone)]
pub(crate) struct LnkData {
    /// Target file path (e.g., "C:\Windows\System32\cmd.exe")
    pub target_path: Option<String>,
    /// Shortcut description / name string.
    pub name_string: Option<String>,
    /// Target path relative to the shortcut file, when present.
    pub relative_path: Option<String>,
    /// Command-line arguments
    pub arguments: Option<String>,
    /// Working directory
    pub working_dir: Option<String>,
    /// Icon file location
    pub icon_location: Option<String>,
    /// Icon index within the icon location.
    pub icon_index: i32,
    /// Link target size from the LNK header.
    pub target_size: u32,
    /// Raw link target file attribute bits from the LNK header.
    pub target_attributes: u32,
    /// Link target drive type from LinkInfo/VolumeID.
    pub target_volume_type: Option<String>,
    /// Link target drive serial number from LinkInfo/VolumeID.
    pub target_volume_serial: Option<u32>,
    /// Link target volume label from LinkInfo/VolumeID.
    pub target_volume_name: Option<String>,
    /// Network share/device name from LinkInfo/CommonNetworkRelativeLink.
    pub network_name: Option<String>,
    /// Environment-variable target from EnvironmentVariableDataBlock.
    pub environment_target: Option<String>,
    /// Environment-variable icon path from IconEnvironmentDataBlock.
    pub icon_environment_target: Option<String>,
    /// MSI/Darwin application identifier from DarwinDataBlock.
    pub darwin_data: Option<String>,
    /// Compatibility shim layer name from ShimDataBlock.
    pub shim_layer_name: Option<String>,
    /// Known folder GUID from KnownFolderDataBlock.
    pub known_folder_id: Option<String>,
    /// Special folder integer ID from SpecialFolderDataBlock.
    pub special_folder_id: Option<u32>,
    /// TrackerDataBlock machine ID.
    pub tracker_machine_id: Option<String>,
    /// TrackerDataBlock MAC address derived from the file Droid GUID.
    pub tracker_mac_address: Option<String>,
    /// TrackerDataBlock volume Droid GUID.
    pub tracker_volume_droid: Option<String>,
    /// TrackerDataBlock file Droid GUID.
    pub tracker_file_droid: Option<String>,
    /// ShowCommand value (0=SW_HIDE, 1=SW_NORMAL, 3=SW_MAXIMIZE, 7=SW_MINIMIZE)
    pub show_command: u32,
    /// Hotkey value
    pub hotkey: u16,
    /// Whether file has link target ID list
    pub has_link_target_id_list: bool,
    /// Whether file has link info
    pub has_link_info: bool,
    /// Whether file has a description/name string
    pub has_name: bool,
    /// Whether file has a relative target path
    pub has_relative_path: bool,
    /// Whether file has arguments
    pub has_arguments: bool,
    /// Whether file has working directory
    pub has_working_dir: bool,
    /// Whether file has icon location
    pub has_icon_location: bool,
    /// Link header flag: HAS_EXP_STRING bit is set.
    pub has_exp_string: bool,
    /// Link header flag: HAS_DARWIN_ID bit is set.
    pub has_darwin_id: bool,
    /// Link header flag: HAS_EXP_ICON bit is set.
    pub has_exp_icon: bool,
    /// Link header flag: RUN_AS_USER bit is set.
    pub run_as_user: bool,
    /// Link header flag: RUN_WITH_SHIM_LAYER bit is set.
    pub run_with_shim_layer: bool,
    /// Link header flag: FORCE_NO_LINK_TRACK bit is set.
    pub force_no_link_track: bool,
    /// Link header flag: ENABLE_TARGET_METADATA bit is set.
    pub enable_target_metadata: bool,
    /// Link header flag: DISABLE_LINK_PATH_TRACKING bit is set.
    pub disable_link_path_tracking: bool,
    /// Link header flag: DISABLE_KNOWN_FOLDER_TRACKING bit is set.
    pub disable_known_folder_tracking: bool,
    /// Link header flag: DISABLE_KNOWN_FOLDER_ALIAS bit is set.
    pub disable_known_folder_alias: bool,
    /// Link header flag: ALLOW_LINK_TO_LINK bit is set.
    pub allow_link_to_link: bool,
    /// Link header flag: UNALIAS_ON_SAVE bit is set.
    pub unalias_on_save: bool,
    /// Link header flag: PREFER_ENVIRONMENT_PATH bit is set.
    pub prefer_environment_path: bool,
    /// Link header flag: KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET bit is set.
    pub keep_local_id_list_for_unc_target: bool,
    /// ExtraData contains a TrackerDataBlock.
    pub has_tracker_data: bool,
    /// ExtraData contains an EnvironmentVariableDataBlock.
    pub has_environment_variable_data: bool,
    /// ExtraData contains an IconEnvironmentDataBlock.
    pub has_icon_environment_data: bool,
    /// ExtraData contains a DarwinDataBlock.
    pub has_darwin_data: bool,
    /// ExtraData contains a ShimDataBlock.
    pub has_shim_data: bool,
    /// ExtraData contains a KnownFolderDataBlock.
    pub has_known_folder_data: bool,
    /// ExtraData contains a SpecialFolderDataBlock.
    pub has_special_folder_data: bool,
    /// ExtraData contains a PropertyStoreDataBlock.
    pub has_property_store_data: bool,
    /// Whether LinkInfo points at a network location
    pub target_is_on_network: bool,
    /// Whether header attributes mark the target hidden
    pub target_is_hidden: bool,
    /// Whether header attributes mark the target as a directory
    pub target_is_directory: bool,
    /// Whitespace analysis results
    pub whitespace_analysis: WhitespaceAnalysis,
}

/// Whitespace analysis for detecting obfuscation
#[derive(Debug, Clone, Default)]
pub(crate) struct WhitespaceAnalysis {
    /// Number of leading spaces in arguments
    pub leading_spaces: usize,
    /// Number of leading tabs in arguments
    pub leading_tabs: usize,
    /// Total whitespace characters in arguments
    pub total_whitespace: usize,
    /// Longest consecutive whitespace run in arguments
    pub max_consecutive_whitespace: usize,
    /// Whether arguments have excessive padding (>50 consecutive whitespace chars)
    pub has_excessive_padding: bool,
}

#[derive(Debug, Clone, Default)]
struct LnkRawSupplement {
    link_flags: u32,
    environment_target: Option<String>,
    icon_environment_target: Option<String>,
    darwin_data: Option<String>,
    shim_layer_name: Option<String>,
    known_folder_id: Option<String>,
    special_folder_id: Option<u32>,
    tracker_machine_id: Option<String>,
    tracker_mac_address: Option<String>,
    tracker_volume_droid: Option<String>,
    tracker_file_droid: Option<String>,
    has_tracker_data: bool,
    has_environment_variable_data: bool,
    has_icon_environment_data: bool,
    has_darwin_data: bool,
    has_shim_data: bool,
    has_known_folder_data: bool,
    has_special_folder_data: bool,
    has_property_store_data: bool,
}

/// Check if data looks like a LNK file
#[must_use]
pub(crate) fn is_lnk(data: &[u8]) -> bool {
    data.len() >= LNK_MAGIC.len() && data.starts_with(LNK_MAGIC)
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_guid_string(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..offset + 16)?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn read_fixed_ansi_string(data: &[u8], offset: usize, len: usize) -> Option<String> {
    let bytes = data.get(offset..offset + len)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn read_fixed_utf16le_string(data: &[u8], offset: usize, len: usize) -> Option<String> {
    let bytes = data.get(offset..offset + len)?;
    let mut words = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    let value = String::from_utf16_lossy(&words).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn skip_lnk_string(data: &[u8], mut offset: usize, is_unicode: bool) -> Option<usize> {
    let len = usize::from(read_u16_le(data, offset)?);
    offset = offset.checked_add(2)?;
    let byte_len = if is_unicode { len.checked_mul(2)? } else { len };
    offset
        .checked_add(byte_len)
        .filter(|end| *end <= data.len())
}

fn extra_data_offset(data: &[u8], link_flags: u32) -> Option<usize> {
    let mut offset = 76usize;

    if link_flags & LINK_FLAG_HAS_LINK_TARGET_ID_LIST != 0 {
        let id_list_size = usize::from(read_u16_le(data, offset)?);
        offset = offset.checked_add(2)?.checked_add(id_list_size)?;
    }

    if link_flags & LINK_FLAG_HAS_LINK_INFO != 0 {
        let link_info_size = usize::try_from(read_u32_le(data, offset)?).ok()?;
        offset = offset.checked_add(link_info_size)?;
    }

    let is_unicode = link_flags & LINK_FLAG_IS_UNICODE != 0;
    for flag in [
        LINK_FLAG_HAS_NAME,
        LINK_FLAG_HAS_RELATIVE_PATH,
        LINK_FLAG_HAS_WORKING_DIR,
        LINK_FLAG_HAS_ARGUMENTS,
        LINK_FLAG_HAS_ICON_LOCATION,
    ] {
        if link_flags & flag != 0 {
            offset = skip_lnk_string(data, offset, is_unicode)?;
        }
    }

    (offset <= data.len()).then_some(offset)
}

fn parse_lnk_raw_supplement(data: &[u8]) -> LnkRawSupplement {
    let Some(link_flags) = read_u32_le(data, 20) else {
        return LnkRawSupplement::default();
    };
    let mut supplement = LnkRawSupplement {
        link_flags,
        ..LnkRawSupplement::default()
    };

    let Some(mut offset) = extra_data_offset(data, link_flags) else {
        return supplement;
    };

    while offset + 8 <= data.len() {
        let Some(block_size) =
            read_u32_le(data, offset).and_then(|size| usize::try_from(size).ok())
        else {
            break;
        };
        if block_size < 8 || offset + block_size > data.len() {
            break;
        }
        let block = &data[offset..offset + block_size];
        let Some(signature) = read_u32_le(block, 4) else {
            break;
        };

        match signature {
            EXTRA_ENVIRONMENT_VARIABLE_DATA => {
                supplement.has_environment_variable_data = true;
                supplement.environment_target = read_fixed_utf16le_string(block, 268, 520)
                    .or_else(|| read_fixed_ansi_string(block, 8, 260));
            }
            EXTRA_TRACKER_DATA => {
                supplement.has_tracker_data = true;
                supplement.tracker_machine_id = read_fixed_ansi_string(block, 16, 16);
                supplement.tracker_volume_droid = read_guid_string(block, 0x20);
                supplement.tracker_file_droid = read_guid_string(block, 0x30);
                if let Some(file_droid) = supplement.tracker_file_droid.as_deref() {
                    let mac = file_droid
                        .rsplit('-')
                        .next()
                        .filter(|tail| tail.len() == 12)
                        .map(|tail| {
                            tail.as_bytes()
                                .chunks(2)
                                .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                                .collect::<Vec<_>>()
                                .join(":")
                        });
                    supplement.tracker_mac_address = mac;
                }
            }
            EXTRA_SPECIAL_FOLDER_DATA => {
                supplement.has_special_folder_data = true;
                supplement.special_folder_id = read_u32_le(block, 8);
            }
            EXTRA_DARWIN_DATA => {
                supplement.has_darwin_data = true;
                supplement.darwin_data = read_fixed_utf16le_string(block, 268, 520)
                    .or_else(|| read_fixed_ansi_string(block, 8, 260));
            }
            EXTRA_ICON_ENVIRONMENT_DATA => {
                supplement.has_icon_environment_data = true;
                supplement.icon_environment_target = read_fixed_utf16le_string(block, 268, 520)
                    .or_else(|| read_fixed_ansi_string(block, 8, 260));
            }
            EXTRA_SHIM_DATA => {
                supplement.has_shim_data = true;
                supplement.shim_layer_name =
                    read_fixed_utf16le_string(block, 8, block_size.saturating_sub(8));
            }
            EXTRA_PROPERTY_STORE_DATA => {
                supplement.has_property_store_data = true;
            }
            EXTRA_KNOWN_FOLDER_DATA => {
                supplement.has_known_folder_data = true;
                supplement.known_folder_id = read_guid_string(block, 8);
            }
            _ => {}
        }

        offset += block_size;
    }

    supplement
}

/// Extract LNK data from file content
#[must_use]
pub(crate) fn extract_lnk_data(data: &[u8]) -> Option<LnkData> {
    let raw_supplement = parse_lnk_raw_supplement(data);

    // Write data to a temporary file since lnk crate requires a path
    let temp_file = tempfile::NamedTempFile::new().ok()?;
    std::fs::write(temp_file.path(), data).ok()?;

    // Parse using lnk crate with Windows-1252 encoding (default for LNK files)
    let shell_link =
        ::lnk::ShellLink::open(temp_file.path(), ::lnk::encoding::WINDOWS_1252).ok()?;

    // Extract full target path from link info. This joins the base path with
    // the common path suffix and handles network targets.
    let target_path = shell_link.link_target().or_else(|| {
        shell_link
            .link_info()
            .as_ref()
            .and_then(|info| info.local_base_path())
            .map(String::from)
    });

    // Extract string data using string_data accessor
    let string_data = shell_link.string_data();
    let name_string = string_data
        .name_string()
        .as_ref()
        .map(std::string::ToString::to_string);
    let relative_path = string_data
        .relative_path()
        .as_ref()
        .map(std::string::ToString::to_string);
    let arguments = string_data
        .command_line_arguments()
        .as_ref()
        .map(std::string::ToString::to_string);
    let working_dir = string_data
        .working_dir()
        .as_ref()
        .map(std::string::ToString::to_string);
    let icon_location = string_data
        .icon_location()
        .as_ref()
        .map(std::string::ToString::to_string);

    // Analyze whitespace in arguments
    let whitespace_analysis = analyze_whitespace(arguments.as_deref());

    // Get header flags and show command
    let header = shell_link.header();
    let link_flags = header.link_flags();
    let file_attributes = header.file_attributes();
    let target_attributes = file_attributes.bits();
    let target_is_hidden =
        file_attributes.contains(::lnk::FileAttributeFlags::FILE_ATTRIBUTE_HIDDEN);
    let target_is_directory =
        file_attributes.contains(::lnk::FileAttributeFlags::FILE_ATTRIBUTE_DIRECTORY);
    let icon_index = *header.icon_index();
    let target_size = *header.file_size();

    let link_info = shell_link.link_info();
    let target_is_on_network = link_info.as_ref().is_some_and(|info| {
        info.link_info_flags()
            .has_common_network_relative_link_and_path_suffix()
    });
    let (target_volume_type, target_volume_serial, target_volume_name) = if let Some(volume_id) =
        link_info
            .as_ref()
            .and_then(|info| info.volume_id().as_ref())
    {
        (
            Some(format!("{:?}", volume_id.drive_type())),
            Some(*volume_id.drive_serial_number()),
            Some(volume_id.volume_label().to_string()).filter(|s| !s.is_empty()),
        )
    } else {
        (None, None, None)
    };
    let network_name = link_info
        .as_ref()
        .and_then(|info| info.common_network_relative_link().as_ref())
        .map(::lnk::linkinfo::CommonNetworkRelativeLink::name);

    // Convert ShowCommand enum to u32
    let show_command = match header.show_command() {
        ::lnk::ShowCommand::ShowNormal => 1,
        ::lnk::ShowCommand::ShowMaximized => 3,
        ::lnk::ShowCommand::ShowMinNoActive => 7,
    };

    // Hotkey is rarely important for malware detection - use 0 as placeholder
    let hotkey = 0u16;

    Some(LnkData {
        target_path,
        name_string,
        relative_path,
        arguments,
        working_dir,
        icon_location,
        icon_index,
        target_size,
        target_attributes,
        target_volume_type,
        target_volume_serial,
        target_volume_name,
        network_name,
        environment_target: raw_supplement.environment_target,
        icon_environment_target: raw_supplement.icon_environment_target,
        darwin_data: raw_supplement.darwin_data,
        shim_layer_name: raw_supplement.shim_layer_name,
        known_folder_id: raw_supplement.known_folder_id,
        special_folder_id: raw_supplement.special_folder_id,
        tracker_machine_id: raw_supplement.tracker_machine_id,
        tracker_mac_address: raw_supplement.tracker_mac_address,
        tracker_volume_droid: raw_supplement.tracker_volume_droid,
        tracker_file_droid: raw_supplement.tracker_file_droid,
        show_command,
        hotkey,
        has_link_target_id_list: link_flags.contains(::lnk::LinkFlags::HAS_LINK_TARGET_ID_LIST),
        has_link_info: link_flags.contains(::lnk::LinkFlags::HAS_LINK_INFO),
        has_name: link_flags.contains(::lnk::LinkFlags::HAS_NAME),
        has_relative_path: link_flags.contains(::lnk::LinkFlags::HAS_RELATIVE_PATH),
        has_arguments: link_flags.contains(::lnk::LinkFlags::HAS_ARGUMENTS),
        has_working_dir: link_flags.contains(::lnk::LinkFlags::HAS_WORKING_DIR),
        has_icon_location: link_flags.contains(::lnk::LinkFlags::HAS_ICON_LOCATION),
        has_exp_string: raw_supplement.link_flags & LINK_FLAG_HAS_EXP_STRING != 0,
        has_darwin_id: raw_supplement.link_flags & LINK_FLAG_HAS_DARWIN_ID != 0,
        has_exp_icon: raw_supplement.link_flags & LINK_FLAG_HAS_EXP_ICON != 0,
        run_as_user: raw_supplement.link_flags & LINK_FLAG_RUN_AS_USER != 0,
        run_with_shim_layer: raw_supplement.link_flags & LINK_FLAG_RUN_WITH_SHIM_LAYER != 0,
        force_no_link_track: raw_supplement.link_flags & LINK_FLAG_FORCE_NO_LINK_TRACK != 0,
        enable_target_metadata: raw_supplement.link_flags & LINK_FLAG_ENABLE_TARGET_METADATA != 0,
        disable_link_path_tracking: raw_supplement.link_flags
            & LINK_FLAG_DISABLE_LINK_PATH_TRACKING
            != 0,
        disable_known_folder_tracking: raw_supplement.link_flags
            & LINK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING
            != 0,
        disable_known_folder_alias: raw_supplement.link_flags
            & LINK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS
            != 0,
        allow_link_to_link: raw_supplement.link_flags & LINK_FLAG_ALLOW_LINK_TO_LINK != 0,
        unalias_on_save: raw_supplement.link_flags & LINK_FLAG_UNALIAS_ON_SAVE != 0,
        prefer_environment_path: raw_supplement.link_flags & LINK_FLAG_PREFER_ENVIRONMENT_PATH != 0,
        keep_local_id_list_for_unc_target: raw_supplement.link_flags
            & LINK_FLAG_KEEP_LOCAL_ID_LIST_FOR_UNC_TARGET
            != 0,
        has_tracker_data: raw_supplement.has_tracker_data,
        has_environment_variable_data: raw_supplement.has_environment_variable_data,
        has_icon_environment_data: raw_supplement.has_icon_environment_data,
        has_darwin_data: raw_supplement.has_darwin_data,
        has_shim_data: raw_supplement.has_shim_data,
        has_known_folder_data: raw_supplement.has_known_folder_data,
        has_special_folder_data: raw_supplement.has_special_folder_data,
        has_property_store_data: raw_supplement.has_property_store_data,
        target_is_on_network,
        target_is_hidden,
        target_is_directory,
        whitespace_analysis,
    })
}

/// Analyze whitespace in arguments string for obfuscation detection
fn analyze_whitespace(arguments: Option<&str>) -> WhitespaceAnalysis {
    let Some(args) = arguments else {
        return WhitespaceAnalysis::default();
    };

    let mut leading_spaces = 0usize;
    let mut leading_tabs = 0usize;
    let mut total_whitespace = 0usize;
    let mut current_run = 0usize;
    let mut max_consecutive_whitespace = 0usize;
    let mut in_leading = true;

    for c in args.chars() {
        if c.is_whitespace() {
            total_whitespace += 1;
            current_run += 1;
            if in_leading {
                if c == ' ' {
                    leading_spaces += 1;
                } else if c == '\t' {
                    leading_tabs += 1;
                }
            }
        } else {
            in_leading = false;
            if current_run > max_consecutive_whitespace {
                max_consecutive_whitespace = current_run;
            }
            current_run = 0;
        }
    }

    // Check final run
    if current_run > max_consecutive_whitespace {
        max_consecutive_whitespace = current_run;
    }

    // Excessive padding is detected by either leading or consecutive whitespace
    let has_excessive = max_consecutive_whitespace >= EXCESSIVE_WHITESPACE_THRESHOLD;

    WhitespaceAnalysis {
        leading_spaces,
        leading_tabs,
        total_whitespace,
        max_consecutive_whitespace,
        has_excessive_padding: has_excessive,
    }
}

/// LNK file analyzer
#[derive(Debug)]
pub(crate) struct LnkAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
}

impl LnkAnalyzer {
    /// Create a new LNK analyzer with an empty capability mapper
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            string_extractor: StringExtractor::new(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_lnk(
        &self,
        file_path: &Path,
        data: &[u8],
        stng_strings: Option<&[stng::ExtractedString]>,
    ) -> AnalysisReport {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "lnk".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("lnk-parser".to_string());

        // Parse LNK file
        if let Some(lnk_data) = extract_lnk_data(data) {
            // Add extracted data to strings for trait evaluation
            if let Some(ref path) = lnk_data.target_path {
                report.strings.push(crate::types::StringInfo {
                    value: path.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: None,
                    section: Some("lnk:target_path".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref name) = lnk_data.name_string {
                report.strings.push(crate::types::StringInfo {
                    value: name.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: None,
                    section: Some("lnk:name_string".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref path) = lnk_data.relative_path {
                report.strings.push(crate::types::StringInfo {
                    value: path.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: None,
                    section: Some("lnk:relative_path".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref args) = lnk_data.arguments {
                report.strings.push(crate::types::StringInfo {
                    value: args.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: None,
                    section: Some("lnk:arguments".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref wd) = lnk_data.working_dir {
                report.strings.push(crate::types::StringInfo {
                    value: wd.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: None,
                    section: Some("lnk:working_dir".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref icon) = lnk_data.icon_location {
                report.strings.push(crate::types::StringInfo {
                    value: icon.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: None,
                    section: Some("lnk:icon_location".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            for (section, value) in [
                (
                    "lnk:environment_target",
                    lnk_data.environment_target.as_ref(),
                ),
                (
                    "lnk:icon_environment_target",
                    lnk_data.icon_environment_target.as_ref(),
                ),
                ("lnk:darwin_data", lnk_data.darwin_data.as_ref()),
                ("lnk:shim_layer_name", lnk_data.shim_layer_name.as_ref()),
                ("lnk:known_folder_id", lnk_data.known_folder_id.as_ref()),
                (
                    "lnk:tracker_machine_id",
                    lnk_data.tracker_machine_id.as_ref(),
                ),
                (
                    "lnk:tracker_mac_address",
                    lnk_data.tracker_mac_address.as_ref(),
                ),
                (
                    "lnk:tracker_volume_droid",
                    lnk_data.tracker_volume_droid.as_ref(),
                ),
                (
                    "lnk:tracker_file_droid",
                    lnk_data.tracker_file_droid.as_ref(),
                ),
            ] {
                if let Some(value) = value {
                    report.strings.push(crate::types::StringInfo {
                        value: value.clone(),
                        offset: None,
                        encoding: "utf-16le".to_string(),
                        string_type: None,
                        section: Some(section.to_string()),
                        encoding_chain: Vec::new(),
                        fragments: None,
                    });
                }
            }

            // Populate derived LNK metrics. The kv evaluator still reparses the
            // raw bytes for target_path/arguments/working_dir/icon_location
            // queries; presence flags and argument whitespace stats now live
            // under metrics.lnk.*.
            let lnk_metrics = LnkMetrics {
                has_link_target_id_list: lnk_data.has_link_target_id_list,
                has_link_info: lnk_data.has_link_info,
                has_name: lnk_data.has_name,
                has_relative_path: lnk_data.has_relative_path,
                has_arguments: lnk_data.has_arguments,
                has_working_dir: lnk_data.has_working_dir,
                has_icon_location: lnk_data.has_icon_location,
                has_exp_string: lnk_data.has_exp_string,
                has_darwin_id: lnk_data.has_darwin_id,
                has_exp_icon: lnk_data.has_exp_icon,
                run_as_user: lnk_data.run_as_user,
                run_with_shim_layer: lnk_data.run_with_shim_layer,
                force_no_link_track: lnk_data.force_no_link_track,
                enable_target_metadata: lnk_data.enable_target_metadata,
                disable_link_path_tracking: lnk_data.disable_link_path_tracking,
                disable_known_folder_tracking: lnk_data.disable_known_folder_tracking,
                disable_known_folder_alias: lnk_data.disable_known_folder_alias,
                allow_link_to_link: lnk_data.allow_link_to_link,
                unalias_on_save: lnk_data.unalias_on_save,
                prefer_environment_path: lnk_data.prefer_environment_path,
                keep_local_id_list_for_unc_target: lnk_data.keep_local_id_list_for_unc_target,
                has_tracker_data: lnk_data.has_tracker_data,
                has_environment_variable_data: lnk_data.has_environment_variable_data,
                has_icon_environment_data: lnk_data.has_icon_environment_data,
                has_darwin_data: lnk_data.has_darwin_data,
                has_shim_data: lnk_data.has_shim_data,
                has_known_folder_data: lnk_data.has_known_folder_data,
                has_special_folder_data: lnk_data.has_special_folder_data,
                has_property_store_data: lnk_data.has_property_store_data,
                target_is_on_network: lnk_data.target_is_on_network,
                target_is_hidden: lnk_data.target_is_hidden,
                target_is_directory: lnk_data.target_is_directory,
                target_size: lnk_data.target_size,
                target_attributes: lnk_data.target_attributes,
                icon_index: lnk_data.icon_index,
                args_leading_spaces: lnk_data.whitespace_analysis.leading_spaces as u32,
                args_leading_tabs: lnk_data.whitespace_analysis.leading_tabs as u32,
                args_whitespace_total: lnk_data.whitespace_analysis.total_whitespace as u32,
                args_max_whitespace_run: lnk_data.whitespace_analysis.max_consecutive_whitespace
                    as u32,
                args_excessive_whitespace: lnk_data.whitespace_analysis.has_excessive_padding,
            };
            let metrics = report.metrics.get_or_insert_with(Metrics::default);
            metrics.lnk = Some(lnk_metrics);
        }

        if let Some(strings) = stng_strings {
            report
                .strings
                .extend(self.string_extractor.convert_stng_strings(strings));
        }

        // Evaluate YAML traits against the file content
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

impl Default for LnkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for LnkAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_lnk(input.path, input.data, Some(input.strings)))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_lnk(file_path, &data, None))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext.to_string_lossy().to_lowercase() == "lnk"
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_lnk_magic_detection() {
        // Valid LNK header
        let valid = [
            0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        assert!(is_lnk(&valid));

        // Invalid - too short
        assert!(!is_lnk(&[0x4C, 0x00, 0x00]));

        // Invalid - wrong magic
        assert!(!is_lnk(&[0x00; 20]));
    }

    #[test]
    fn test_whitespace_analysis() {
        // Normal arguments
        let normal = analyze_whitespace(Some("/c dir"));
        assert_eq!(normal.leading_spaces, 0);
        assert_eq!(normal.max_consecutive_whitespace, 1);
        assert!(!normal.has_excessive_padding);

        // Excessive leading spaces (obfuscation)
        let spaces = " ".repeat(60) + "cmd.exe";
        let padded = analyze_whitespace(Some(&spaces));
        assert_eq!(padded.leading_spaces, 60);
        assert_eq!(padded.max_consecutive_whitespace, 60);
        assert!(padded.has_excessive_padding);

        // Tabs
        let tabs = "\t".repeat(55) + "cmd.exe";
        let tabbed = analyze_whitespace(Some(&tabs));
        assert_eq!(tabbed.leading_tabs, 55);
        assert_eq!(tabbed.max_consecutive_whitespace, 55);
        assert!(tabbed.has_excessive_padding);

        // Whitespace AFTER command switch (ZDI-CAN-25373 pattern)
        let after_switch = "/c".to_string() + &" ".repeat(100) + "calc.exe";
        let after_result = analyze_whitespace(Some(&after_switch));
        assert_eq!(after_result.leading_spaces, 0);
        assert_eq!(after_result.max_consecutive_whitespace, 100);
        assert!(after_result.has_excessive_padding);

        // Mixed but under threshold
        let mixed = " ".repeat(20) + "\t".repeat(20).as_str() + "cmd.exe";
        let mixed_result = analyze_whitespace(Some(&mixed));
        assert_eq!(mixed_result.leading_spaces, 20);
        assert_eq!(mixed_result.leading_tabs, 20);
        assert_eq!(mixed_result.max_consecutive_whitespace, 40);
        assert!(!mixed_result.has_excessive_padding);

        // None
        let none = analyze_whitespace(None);
        assert_eq!(none.leading_spaces, 0);
        assert_eq!(none.max_consecutive_whitespace, 0);
        assert!(!none.has_excessive_padding);
    }

    #[test]
    fn test_analyzer_basic() {
        let analyzer = LnkAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.lnk")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.LNK")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.exe")));
    }

    #[test]
    fn test_parse_whitespace_obfuscated_fixture() {
        // Test parsing of generated LNK fixture
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lnk/whitespace_obfuscated.lnk");

        if !fixture_path.exists() {
            eprintln!(
                "Fixture not found: {:?} - run generate.py first",
                fixture_path
            );
            return;
        }

        let data = std::fs::read(&fixture_path).expect("Failed to read fixture");
        assert!(is_lnk(&data), "Should detect LNK magic");

        let lnk_data = extract_lnk_data(&data);
        assert!(lnk_data.is_some(), "Should parse LNK file");

        let lnk = lnk_data.unwrap();

        // pylnk3 uses Minimized (7) since it doesn't support SW_HIDE (0)
        assert_eq!(lnk.show_command, 7, "Should have minimized window");

        // Arguments should exist and have excessive consecutive whitespace
        assert!(lnk.has_arguments, "Should have arguments");
        assert!(
            lnk.whitespace_analysis.max_consecutive_whitespace >= 100,
            "Should have 100+ consecutive whitespace chars, got {}",
            lnk.whitespace_analysis.max_consecutive_whitespace
        );
        assert!(
            lnk.whitespace_analysis.has_excessive_padding,
            "Should detect excessive padding"
        );
    }

    #[test]
    fn test_parse_benign_notepad_fixture() {
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lnk/benign_notepad.lnk");

        if !fixture_path.exists() {
            eprintln!(
                "Fixture not found: {:?} - run generate.py first",
                fixture_path
            );
            return;
        }

        let data = std::fs::read(&fixture_path).expect("Failed to read fixture");
        assert!(is_lnk(&data), "Should detect LNK magic");

        let lnk_data = extract_lnk_data(&data);
        assert!(lnk_data.is_some(), "Should parse LNK file");

        let lnk = lnk_data.unwrap();
        // Normal window (1)
        assert_eq!(lnk.show_command, 1, "Should have normal window");
        // No excessive whitespace
        assert!(
            !lnk.whitespace_analysis.has_excessive_padding,
            "Should not have excessive padding"
        );
        // No arguments
        assert!(!lnk.has_arguments, "Should not have arguments");
    }
}
