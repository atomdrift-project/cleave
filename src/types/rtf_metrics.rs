//! RTF-specific analysis metrics

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};
use super::{is_zero_u64, is_zero_u32};

/// Metrics specific to RTF (Rich Text Format) documents
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct RtfMetrics {
    /// Total number of embedded OLE objects
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub object_count: u64,
    
    /// Maximum group nesting depth encountered (detects RTF bombs)
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_nesting_depth: u64,
    
    /// Whether any \objupdate directives were found
    pub has_objupdate: bool,
    
    /// Whether any \objautlink directives were found
    pub has_objautlink: bool,
    
    /// Count of different OLE class names found
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_class_count: u32,
    
    /// Count of suspicious flags detected during structural analysis
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub suspicious_flag_count: u32,
}
