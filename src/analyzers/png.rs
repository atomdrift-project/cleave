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
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// PNG analyzer for steganography detection
#[derive(Debug)]
pub(crate) struct PngAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
}

impl PngAnalyzer {
    /// Create a new PNG analyzer with an empty capability mapper
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

    fn analyze_png(
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
            file_type: "png".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("png-analyzer".to_string());

        // Pixel-statistic pass — entropy / dimensions / bit-depth
        // metrics that aren't part of expose's chunk-table view.
        // Chunk-level kv (`png.dimensions`, `png.text.*`,
        // `png.chunks`, `png.features`, …) comes from expose via
        // the dual-emission step in `evaluate_and_merge_findings`.
        // Pixel-stat metrics flow into the report's flat metric
        // map under `image.*` / `png.*` keys.
        let flat = report.expose_metrics.get_or_insert_with(Default::default);
        if analyze_png_data(data, flat).is_some() {
            use crate::types::MetricsExt;
            flat.set_f("binary.overall_entropy", calculate_entropy(data));
        }

        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
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
        Ok(self.analyze_png(input.path, input.data, Some(input.strings)))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_png(file_path, &data, None))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext.to_string_lossy().to_lowercase() == "png"
        } else {
            false
        }
    }
}

/// Analyze PNG data and push steganography-relevant metrics into
/// the report's flat metric map under `image.*` and `png.*` keys.
/// Returns `Some(())` when the PNG header parsed; `None` when the
/// bytes aren't a recognisable PNG.
fn analyze_png_data(
    data: &[u8],
    metrics: &mut std::collections::BTreeMap<String, f64>,
) -> Option<()> {
    use crate::types::MetricsExt;
    use png::Decoder;

    let decoder = Decoder::new(data);
    let mut reader = decoder.read_info().ok()?;

    let info = reader.info();
    let width = info.width;
    let height = info.height;
    let bit_depth = info.bit_depth as u32;
    let color_type = info.color_type;

    let channels: u32 = match color_type {
        png::ColorType::Grayscale | png::ColorType::Indexed => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
    };

    metrics.set_u("image.width", width.into());
    metrics.set_u("image.height", height.into());
    metrics.set_u("image.channels", channels.into());
    metrics.set_u("png.bit_depth", bit_depth.into());

    // Decode pixel data. Skip the entropy/edge analysis when the
    // decoded buffer would exceed `MAX_DECODE_BYTES` — a malicious
    // or merely huge PNG shouldn't allocate hundreds of MiB per
    // worker. Structural metadata above is preserved; only the
    // per-channel entropy is skipped.
    const MAX_DECODE_BYTES: usize = 32 * 1024 * 1024;
    let buf_size = reader.output_buffer_size();
    if buf_size > MAX_DECODE_BYTES {
        tracing::debug!(
            width,
            height,
            channels,
            buf_size_mb = buf_size / 1024 / 1024,
            "Skipping PNG pixel-entropy analysis: decoded buffer exceeds cap"
        );
        return Some(());
    }
    let mut pixels = vec![0u8; buf_size];
    let output_info = reader.next_frame(&mut pixels).ok()?;
    let pixels = &pixels[..output_info.buffer_size()];

    let raw_size = (width as usize)
        * (height as usize)
        * (channels as usize)
        * (bit_depth as usize / 8).max(1);
    let compression_ratio = if raw_size > 0 {
        data.len() as f32 / raw_size as f32
    } else {
        1.0
    };

    let pixel_entropy = calculate_entropy(pixels) as f32;

    let (r_entropy, g_entropy, b_entropy, a_entropy) = if channels >= 3 {
        calculate_channel_entropy(pixels, channels as usize)
    } else {
        (pixel_entropy, 0.0, 0.0, 0.0)
    };

    let histogram_flatness = calculate_histogram_flatness(pixels);
    let edge_density =
        calculate_edge_density(pixels, width as usize, height as usize, channels as usize);

    metrics.set_f("image.pixel_entropy", f64::from(pixel_entropy));
    metrics.set_f("image.histogram_flatness", f64::from(histogram_flatness));
    metrics.set_f("image.edge_density", f64::from(edge_density));
    metrics.set_f("image.r_entropy", f64::from(r_entropy));
    metrics.set_f("image.g_entropy", f64::from(g_entropy));
    metrics.set_f("image.b_entropy", f64::from(b_entropy));
    metrics.set_f("png.compression_ratio", f64::from(compression_ratio));
    metrics.set_f("png.a_entropy", f64::from(a_entropy));
    Some(())
}

/// Calculate entropy for each color channel separately
fn calculate_channel_entropy(pixels: &[u8], channels: usize) -> (f32, f32, f32, f32) {
    if channels < 3 {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let mut hr = [0u32; 256];
    let mut hg = [0u32; 256];
    let mut hb = [0u32; 256];
    let mut ha = [0u32; 256];
    let mut rgb_count: u32 = 0;
    let mut a_count: u32 = 0;

    for chunk in pixels.chunks_exact(channels) {
        hr[chunk[0] as usize] += 1;
        hg[chunk[1] as usize] += 1;
        hb[chunk[2] as usize] += 1;
        rgb_count += 1;
        if channels >= 4 {
            ha[chunk[3] as usize] += 1;
            a_count += 1;
        }
    }

    let r = entropy_from_histogram(&hr, rgb_count);
    let g = entropy_from_histogram(&hg, rgb_count);
    let b = entropy_from_histogram(&hb, rgb_count);
    let a = if a_count > 0 {
        entropy_from_histogram(&ha, a_count)
    } else {
        0.0
    };
    (r, g, b, a)
}

/// Shannon entropy directly from a 256-bin byte histogram. Equivalent to
/// `calculate_entropy(data)` but avoids materializing the per-channel slices.
fn entropy_from_histogram(freq: &[u32; 256], total: u32) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f32;
    freq.iter().filter(|&&c| c > 0).fold(0.0f32, |e, &c| {
        let p = c as f32 / total;
        e - p * p.log2()
    })
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
