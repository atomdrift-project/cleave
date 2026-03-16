//! JPEG image analyzer for steganography detection
//!
//! Analyzes JPEG images for indicators of steganographic payloads:
//! - Data appended after the EOI marker (FF D9)
//! - Unusually large JFIF comment (COM) markers
//! - Unusually large APP1/EXIF blocks
//! - High pixel entropy (LSB steganography in DCT coefficients)
//! - Flat color histogram (uniform distribution)
//! - Lack of visual structure (no edges/gradients)

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::calculate_entropy;
use crate::types::{AnalysisReport, JpegMetrics, Metrics, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// JPEG analyzer for steganography detection
#[derive(Debug)]
pub(crate) struct JpegAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl JpegAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_jpeg(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "jpeg".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("jpeg-analyzer".to_string());

        if let Some(jpeg_metrics) = analyze_jpeg_data(data) {
            report.metrics = Some(Metrics {
                jpeg: Some(jpeg_metrics),
                ..Default::default()
            });
        }

        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

impl Default for JpegAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JpegAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_jpeg(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_jpeg(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(
                ext.to_string_lossy().to_lowercase().as_str(),
                "jpg" | "jpeg"
            )
        } else {
            false
        }
    }
}

/// Scan JPEG markers to find appended data, comment size, and EXIF size.
///
/// Returns `(appended_bytes, comment_bytes, exif_size)`.
fn scan_jpeg_markers(data: &[u8]) -> (u64, u64, u64) {
    let mut pos = 0;
    let mut comment_bytes: u64 = 0;
    let mut exif_size: u64 = 0;

    // JPEG must start with SOI (FF D8)
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return (0, 0, 0);
    }
    pos += 2;

    loop {
        // Find next marker (FF byte, skip any padding FF bytes)
        while pos < data.len() && data[pos] != 0xFF {
            pos += 1;
        }
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }

        let marker = data[pos];
        pos += 1;

        match marker {
            // EOI — end of image; anything after is appended data
            0xD9 => {
                let appended = data.len().saturating_sub(pos) as u64;
                return (appended, comment_bytes, exif_size);
            }
            // Markers with no length field (standalone)
            0xD0..=0xD8 | 0x01 => continue,
            // SOS — start of scan: entropy-coded data follows, scan for next EOI
            0xDA => {
                // Skip the SOS header
                if pos + 1 >= data.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += seg_len;
                // The compressed bitstream follows; skip to the next marker
                // by scanning for FF xx where xx != 00 and xx != FF
                while pos + 1 < data.len() {
                    if data[pos] == 0xFF && data[pos + 1] != 0x00 && data[pos + 1] != 0xFF {
                        break;
                    }
                    pos += 1;
                }
            }
            _ => {
                // Normal segment: 2-byte length (includes the length bytes)
                if pos + 1 >= data.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                if seg_len < 2 {
                    break;
                }
                let payload_len = seg_len - 2;

                // COM marker (FF FE): comment field
                if marker == 0xFE {
                    comment_bytes += payload_len as u64;
                }
                // APP1 (FF E1): typically EXIF
                if marker == 0xE1 {
                    exif_size += payload_len as u64;
                }

                pos += seg_len;
            }
        }
    }

    (0, comment_bytes, exif_size)
}

/// Analyze JPEG data and extract steganography-relevant metrics
fn analyze_jpeg_data(data: &[u8]) -> Option<JpegMetrics> {
    use jpeg_decoder::Decoder;
    use std::io::Cursor;

    let (appended_bytes, comment_bytes, exif_size) = scan_jpeg_markers(data);

    let mut decoder = Decoder::new(Cursor::new(data));
    let pixels = decoder.decode().ok()?;
    let info = decoder.info()?;

    let width = info.width as u32;
    let height = info.height as u32;
    let channels = match info.pixel_format {
        jpeg_decoder::PixelFormat::L8 | jpeg_decoder::PixelFormat::L16 => 1u32,
        jpeg_decoder::PixelFormat::RGB24 => 3,
        jpeg_decoder::PixelFormat::CMYK32 => 4,
    };

    let pixel_entropy = calculate_entropy(&pixels) as f32;
    let histogram_flatness = {
        let entropy = calculate_entropy(&pixels);
        (entropy / 8.0) as f32
    };
    let edge_density =
        calculate_edge_density(&pixels, width as usize, height as usize, channels as usize);

    Some(JpegMetrics {
        width,
        height,
        channels,
        pixel_entropy,
        histogram_flatness,
        edge_density,
        appended_bytes,
        comment_bytes,
        exif_size,
    })
}

/// Calculate edge density using simple gradient detection (mirrors PNG analyzer)
fn calculate_edge_density(pixels: &[u8], width: usize, height: usize, channels: usize) -> f32 {
    if width < 2 || height < 2 || pixels.is_empty() || channels == 0 {
        return 0.0;
    }

    let row_stride = width * channels;
    let mut edge_count = 0u64;
    let mut total_pairs = 0u64;
    const EDGE_THRESHOLD: i32 = 30;

    for y in 0..height {
        for x in 0..(width - 1) {
            let idx1 = y * row_stride + x * channels;
            let idx2 = y * row_stride + (x + 1) * channels;
            if idx2 + channels <= pixels.len() {
                let diff = (pixels[idx1] as i32 - pixels[idx2] as i32).abs();
                if diff > EDGE_THRESHOLD {
                    edge_count += 1;
                }
                total_pairs += 1;
            }
        }
    }

    for y in 0..(height - 1) {
        for x in 0..width {
            let idx1 = y * row_stride + x * channels;
            let idx2 = (y + 1) * row_stride + x * channels;
            if idx2 + channels <= pixels.len() {
                let diff = (pixels[idx1] as i32 - pixels[idx2] as i32).abs();
                if diff > EDGE_THRESHOLD {
                    edge_count += 1;
                }
                total_pairs += 1;
            }
        }
    }

    if total_pairs == 0 {
        return 0.0;
    }

    edge_count as f32 / total_pairs as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid 1×1 white JPEG (JFIF, no EXIF)
    const MINIMAL_JPEG: &[u8] = &[
        0xFF, 0xD8, // SOI
        0xFF, 0xE0, 0x00, 0x10, // APP0 marker, length=16
        0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
        0x01, 0x01, // version 1.1
        0x00, // aspect ratio units
        0x00, 0x01, 0x00, 0x01, // X/Y density
        0x00, 0x00, // thumbnail size
        0xFF, 0xDB, 0x00, 0x43, 0x00, // DQT marker, length=67
        // quantization table (64 bytes, quality 50)
        16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69,
        56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81,
        104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99, 0xFF,
        0xD9, // EOI
    ];

    #[test]
    fn test_can_analyze() {
        let analyzer = JpegAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.jpg")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.jpeg")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.JPG")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.png")));
    }

    #[test]
    fn test_scan_jpeg_markers_no_appended_data() {
        let (appended, comment, exif) = scan_jpeg_markers(MINIMAL_JPEG);
        assert_eq!(appended, 0, "No data should be appended");
        assert_eq!(comment, 0, "No comment marker");
        assert_eq!(exif, 0, "No EXIF");
    }

    #[test]
    fn test_scan_jpeg_markers_appended_data() {
        let mut data = MINIMAL_JPEG.to_vec();
        data.extend_from_slice(b"hidden payload here");
        let (appended, _, _) = scan_jpeg_markers(&data);
        assert_eq!(appended, 19, "Should detect 19 bytes after EOI");
    }

    #[test]
    fn test_scan_jpeg_markers_comment() {
        // Build a JPEG with a COM marker before EOI
        let comment = b"this is a comment";
        let com_len = (comment.len() + 2) as u16;
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]); // SOI
        data.extend_from_slice(&[0xFF, 0xFE]); // COM
        data.extend_from_slice(&com_len.to_be_bytes());
        data.extend_from_slice(comment);
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI
        let (appended, comment_bytes, _) = scan_jpeg_markers(&data);
        assert_eq!(appended, 0);
        assert_eq!(comment_bytes, comment.len() as u64);
    }

    #[test]
    fn test_edge_density_constant() {
        let pixels = vec![128u8; 100 * 100 * 3];
        let density = calculate_edge_density(&pixels, 100, 100, 3);
        assert!(
            density < 0.01,
            "Constant image should have near-zero edge density: {density}"
        );
    }
}
