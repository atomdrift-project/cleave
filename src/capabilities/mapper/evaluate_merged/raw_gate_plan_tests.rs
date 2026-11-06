use super::{
    RAW_GATE_MAX_BYTES, RAW_GATE_THIN_SOURCE_MAX_BYTES, raw_gate_plan_with_caps,
    raw_gate_plan_with_source_cap,
};

#[test]
fn source_records_offsets_up_to_its_own_band_binaries_keep_the_small_one() {
    const FULL: usize = RAW_GATE_MAX_BYTES;
    const SRC: usize = 16 << 20;
    const THIN: usize = RAW_GATE_THIN_SOURCE_MAX_BYTES;
    let plan = |len, src| raw_gate_plan_with_source_cap(len, src, FULL, SRC, THIN);
    assert_eq!(plan(9 << 20, true), Some(true), "9 MB bundle: windowed");
    assert_eq!(plan(SRC, true), Some(true));
    assert_eq!(
        plan(SRC + 1, true),
        Some(false),
        "above the band: presence only"
    );
    assert_eq!(plan(THIN + 1, true), None);
    assert_eq!(plan(9 << 20, false), None, "9 MB binary: no gate");
    assert_eq!(plan(2 << 20, false), Some(false), "binaries never record");
}

const FULL: usize = RAW_GATE_MAX_BYTES;
const THIN: usize = RAW_GATE_THIN_SOURCE_MAX_BYTES;

#[test]
fn source_below_full_records_offsets() {
    assert_eq!(
        raw_gate_plan_with_caps(2 << 20, true, FULL, THIN),
        Some(true)
    );
}

#[test]
fn source_thin_band_presence_only() {
    assert_eq!(
        raw_gate_plan_with_caps(FULL + 1, true, FULL, THIN),
        Some(false)
    );
    assert_eq!(raw_gate_plan_with_caps(THIN, true, FULL, THIN), Some(false));
}

#[test]
fn source_above_thin_skips_gate() {
    assert_eq!(raw_gate_plan_with_caps(THIN + 1, true, FULL, THIN), None);
}

#[test]
fn pe_above_full_skips_gate() {
    assert_eq!(raw_gate_plan_with_caps(FULL + 1, false, FULL, THIN), None);
}

#[test]
fn pe_below_full_gates_without_offsets() {
    assert_eq!(
        raw_gate_plan_with_caps(2 << 20, false, FULL, THIN),
        Some(false)
    );
}
