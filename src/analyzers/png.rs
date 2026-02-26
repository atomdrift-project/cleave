//! PNG image analyzer for steganography detection
//!
//! Analyzes PNG images for indicators of steganographic payloads:
//! - High pixel entropy (random-looking data)
//! - Flat color histogram (uniform distribution)
//! - Lack of visual structure (no edges/gradients)
//! - Poor compression ratio (random data doesn't compress well)

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::calculate_entropy;
use crate::types::{AnalysisReport, Metrics, PngMetrics, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// PNG analyzer for steganography detection
#[derive(Debug)]
pub(crate) struct PngAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl PngAnalyzer {
    /// Create a new PNG analyzer with an empty capability mapper
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
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

    fn analyze_png(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "png".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("png-analyzer".to_string());

        // Parse and analyze PNG
        if let Some(png_metrics) = analyze_png_data(data) {
            report.metrics = Some(Metrics {
                png: Some(png_metrics),
                ..Default::default()
            });
        }

        // Evaluate YAML traits against the file content
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

impl Default for PngAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PngAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_png(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_png(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext.to_string_lossy().to_lowercase() == "png"
        } else {
            false
        }
    }
}

/// Analyze PNG data and extract steganography-relevant metrics
fn analyze_png_data(data: &[u8]) -> Option<PngMetrics> {
    use png::Decoder;

    let decoder = Decoder::new(data);
    let mut reader = decoder.read_info().ok()?;

    let info = reader.info();
    let width = info.width;
    let height = info.height;
    let bit_depth = info.bit_depth as u32;
    let color_type = info.color_type;

    // Determine number of channels
    let channels = match color_type {
        png::ColorType::Grayscale | png::ColorType::Indexed => 1, // Indexed is palette-based
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
    };

    // Decode pixel data
    let mut pixels = vec![0u8; reader.output_buffer_size()];
    let output_info = reader.next_frame(&mut pixels).ok()?;
    let pixels = &pixels[..output_info.buffer_size()];

    // Calculate raw pixel size for compression ratio
    let raw_size = (width as usize)
        * (height as usize)
        * (channels as usize)
        * (bit_depth as usize / 8).max(1);
    let compression_ratio = if raw_size > 0 {
        data.len() as f32 / raw_size as f32
    } else {
        1.0
    };

    // Calculate overall pixel entropy
    let pixel_entropy = calculate_entropy(pixels) as f32;

    // Calculate per-channel entropy for RGB/RGBA images
    let (r_entropy, g_entropy, b_entropy, a_entropy) = if channels >= 3 {
        calculate_channel_entropy(pixels, channels as usize)
    } else {
        (pixel_entropy, 0.0, 0.0, 0.0)
    };

    // Calculate histogram flatness
    let histogram_flatness = calculate_histogram_flatness(pixels);

    // Calculate edge density (measure of visual structure)
    let edge_density =
        calculate_edge_density(pixels, width as usize, height as usize, channels as usize);

    Some(PngMetrics {
        width,
        height,
        bit_depth,
        channels,
        pixel_entropy,
        histogram_flatness,
        edge_density,
        compression_ratio,
        r_entropy,
        g_entropy,
        b_entropy,
        a_entropy,
    })
}

/// Calculate entropy for each color channel separately
fn calculate_channel_entropy(pixels: &[u8], channels: usize) -> (f32, f32, f32, f32) {
    if channels < 3 {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let pixel_count = pixels.len() / channels;
    let mut r_data = Vec::with_capacity(pixel_count);
    let mut g_data = Vec::with_capacity(pixel_count);
    let mut b_data = Vec::with_capacity(pixel_count);
    let mut a_data = Vec::with_capacity(pixel_count);

    for chunk in pixels.chunks(channels) {
        if chunk.len() >= 3 {
            r_data.push(chunk[0]);
            g_data.push(chunk[1]);
            b_data.push(chunk[2]);
            if channels >= 4 && chunk.len() >= 4 {
                a_data.push(chunk[3]);
            }
        }
    }

    let r_entropy = calculate_entropy(&r_data) as f32;
    let g_entropy = calculate_entropy(&g_data) as f32;
    let b_entropy = calculate_entropy(&b_data) as f32;
    let a_entropy = if !a_data.is_empty() {
        calculate_entropy(&a_data) as f32
    } else {
        0.0
    };

    (r_entropy, g_entropy, b_entropy, a_entropy)
}

/// Calculate histogram flatness (0.0 = peaked, 1.0 = perfectly uniform)
///
/// Uses normalized entropy: actual_entropy / max_possible_entropy
/// For byte values, max entropy is 8.0 bits (256 equally likely values)
fn calculate_histogram_flatness(pixels: &[u8]) -> f32 {
    if pixels.is_empty() {
        return 0.0;
    }

    let entropy = calculate_entropy(pixels);
    // Normalize to 0-1 range (max entropy for bytes is 8.0)
    (entropy / 8.0) as f32
}

/// Calculate edge density using simple gradient detection
///
/// Measures how many adjacent pixel pairs have significant differences.
/// Real images have edges; pure noise has no structure.
fn calculate_edge_density(pixels: &[u8], width: usize, height: usize, channels: usize) -> f32 {
    if width < 2 || height < 2 || pixels.is_empty() {
        return 0.0;
    }

    let row_stride = width * channels;
    let mut edge_count = 0u64;
    let mut total_pairs = 0u64;

    // Threshold for "significant" edge (out of 255)
    const EDGE_THRESHOLD: i32 = 30;

    // Scan horizontal edges
    for y in 0..height {
        for x in 0..(width - 1) {
            let idx1 = y * row_stride + x * channels;
            let idx2 = y * row_stride + (x + 1) * channels;

            if idx2 + channels <= pixels.len() {
                // Compare first channel (or average for better accuracy)
                let diff = (pixels[idx1] as i32 - pixels[idx2] as i32).abs();
                if diff > EDGE_THRESHOLD {
                    edge_count += 1;
                }
                total_pairs += 1;
            }
        }
    }

    // Scan vertical edges
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

    #[test]
    fn test_histogram_flatness_uniform() {
        // Uniform distribution should have high flatness
        let mut data: Vec<u8> = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for i in 0..=255u8 {
                data.push(i);
            }
        }
        let flatness = calculate_histogram_flatness(&data);
        assert!(
            flatness > 0.95,
            "Uniform data should have high flatness: {}",
            flatness
        );
    }

    #[test]
    fn test_histogram_flatness_constant() {
        // All same values should have zero flatness
        let data = vec![128u8; 1000];
        let flatness = calculate_histogram_flatness(&data);
        assert!(
            flatness < 0.01,
            "Constant data should have near-zero flatness: {}",
            flatness
        );
    }

    #[test]
    fn test_edge_density_constant() {
        // Constant image has no edges
        let pixels = vec![128u8; 100 * 100 * 3]; // 100x100 RGB
        let density = calculate_edge_density(&pixels, 100, 100, 3);
        assert!(
            density < 0.01,
            "Constant image should have near-zero edge density: {}",
            density
        );
    }

    #[test]
    fn test_edge_density_noise() {
        // Random noise should have some edges but not many strong ones
        // (random differences average to ~85, some will be above threshold)
        let mut pixels = vec![0u8; 100 * 100 * 3];
        for (i, p) in pixels.iter_mut().enumerate() {
            *p = ((i * 17 + 31) % 256) as u8; // Pseudo-random pattern
        }
        let density = calculate_edge_density(&pixels, 100, 100, 3);
        // Noise has SOME edges but not the structured edges of real images
        assert!(
            density > 0.0 && density < 1.0,
            "Noise edge density: {}",
            density
        );
    }

    #[test]
    fn test_analyzer_basic() {
        let analyzer = PngAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.png")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.PNG")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.jpg")));
    }
}
