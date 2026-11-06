//! Offline screen: classify every `type: text` regex of a rule set by
//! whether `eval_raw` can window it around its atom hits. Run with:
//! `PROBE_PATTERNS=<file> cargo test -p cleave --lib window_shape_probe -- --ignored --nocapture`
#[test]
#[ignore = "offline probe: set PROBE_PATTERNS"]
fn classify_patterns() {
    let Ok(path) = std::env::var("PROBE_PATTERNS") else {
        return;
    };
    let text = std::fs::read_to_string(path).unwrap();
    let (mut windowed, mut unbounded, mut invalid) = (0usize, 0usize, 0usize);
    for pat in text.lines().filter(|l| !l.is_empty()) {
        let raw =
            crate::composite_rules::condition::raw_regex_pattern(None, Some(pat), false).unwrap();
        if super::parse_hir_like_engine(&raw).is_none() {
            invalid += 1;
            continue;
        }
        match super::window_shape(&raw) {
            Some((line, look, radius)) => {
                windowed += 1;
                println!("W\tline={line}\tlook={look}\tr={radius}\t{pat}");
            }
            None => {
                unbounded += 1;
                let hir = super::parse_hir_like_engine(&raw).unwrap();
                let (abs, _, _) = super::look_info(&hir);
                let bounded = super::bounded_consumed_bytes(&raw).is_some();
                let line_local = super::unbounded_reps_are_line_local(&hir);
                let newline = super::hir_can_match_newline(&hir);
                println!(
                    "U\tabs={abs}\tbounded={bounded}\tline_local={line_local}\tnewline={newline}\t{pat}"
                );
            }
        }
    }
    println!("SUMMARY windowed={windowed} unbounded={unbounded} invalid={invalid}");
}
