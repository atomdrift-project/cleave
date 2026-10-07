//! The engine an analysis runs under.
//!
//! An [`Engine`] bundles everything besides the input that decides what an
//! analysis reports: the trait rules, the YARA rules, and the settings that
//! change what is unpacked and what is kept. Analyzers carry the engine and
//! read all of this from it, never from process-wide state, so a result
//! depends only on the engine and the input, and engines with different
//! settings can analyze side by side in one process.

use crate::capabilities::CapabilityMapper;
use crate::types::AnalysisReport;
use crate::yara_engine::YaraEngine;
use crate::{AnalysisOptions, EngineFor};
use std::path::Path;
use std::sync::{Arc, LazyLock};

/// Rules plus the settings that change a result. Cheap to clone: one `Arc`.
#[derive(Clone)]
pub struct Engine(Arc<Inner>);

struct Inner {
    rules: Arc<CapabilityMapper>,
    yara: Option<Arc<YaraEngine>>,
    settings: Settings,
}

/// Everything an engine was built for that changes a result: the inputs the
/// rules were loaded with and the analysis settings. The analysis cache key is
/// derived from these (plus the per-call inputs), so a report is only ever
/// served to an engine that would have produced it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Settings {
    /// Unpack UPX-packed executables and analyze the unpacked image too.
    pub(crate) upx: bool,
    /// Recover symbols and code metrics by disassembling native binaries with
    /// rizin (filefacts' per-file `OpenOptions::rizin`).
    pub(crate) radare2: bool,
    /// filefacts' `OpenOptions::rizin_timeout`; `None` is its default.
    pub(crate) rizin_timeout: Option<std::time::Duration>,
    pub(crate) rizin_retry_timeout: Option<std::time::Duration>,
    /// filefacts' `OpenOptions::rizin_max_bytes`; `None` is no cap.
    pub(crate) rizin_max_bytes: Option<usize>,
    /// filefacts' `OpenOptions::rizin_native_arch_only`.
    pub(crate) rizin_native_arch_only: bool,
    /// Fold archive members into the compact projection: fields only the full
    /// v3 output reads (`kv` no rule reaches, `filefacts.values`, findings no
    /// rule references) are dropped as each member folds into its container.
    pub(crate) compact_members: bool,
    /// The engine scans with YARA.
    pub(crate) yara: bool,
    /// Third-party YARA rules were requested (subject to the builtin-only override).
    pub(crate) third_party_yara: bool,
    /// The rule-loading inputs of [`crate::AnalysisOptions`] the rules were built with.
    pub(crate) platforms: Vec<crate::composite_rules::Platform>,
    pub(crate) min_hostile_precision: f32,
    pub(crate) min_suspicious_precision: f32,
    pub(crate) precision_scoring: bool,
    pub(crate) full_validation: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            upx: true,
            radare2: true,
            rizin_timeout: None,
            rizin_retry_timeout: None,
            rizin_max_bytes: None,
            rizin_native_arch_only: false,
            compact_members: false,
            yara: false,
            third_party_yara: false,
            platforms: vec![crate::composite_rules::Platform::All],
            min_hostile_precision: CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            min_suspicious_precision: CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            precision_scoring: false,
            full_validation: false,
        }
    }
}

/// The filefacts options an engine with `settings` parses files with: its
/// rizin settings, and filefacts' disk cache only when `FILEFACTS_CACHE` turns
/// it on and cleave's own cache is in use.
pub(crate) fn filefacts_options(settings: &Settings) -> filefacts::OpenOptions<'static> {
    let mut options = filefacts::OpenOptions::new()
        .rizin(settings.radare2)
        .rizin_native_arch_only(settings.rizin_native_arch_only)
        .cache(!crate::cache::skip_cache() && filefacts::cache::env_override().unwrap_or(false));
    if let Some(timeout) = settings.rizin_timeout {
        options = options.rizin_timeout(timeout);
    }
    if let Some(timeout) = settings.rizin_retry_timeout {
        options = options.rizin_retry_timeout(timeout);
    }
    if let Some(max_bytes) = settings.rizin_max_bytes {
        options = options.rizin_max_bytes(max_bytes);
    }
    options
}

/// The engine with no rules, no YARA and default settings.
static EMPTY: LazyLock<Engine> =
    LazyLock::new(|| Engine::from_rules(Arc::new(CapabilityMapper::empty())));

impl Engine {
    #[must_use]
    pub(crate) fn new(
        rules: Arc<CapabilityMapper>,
        yara: Option<Arc<YaraEngine>>,
        mut settings: Settings,
    ) -> Self {
        settings.yara = yara.is_some();
        Self(Arc::new(Inner {
            rules,
            yara,
            settings,
        }))
    }

    /// An engine over `rules` with no YARA and default settings.
    #[must_use]
    pub fn from_rules(rules: Arc<CapabilityMapper>) -> Self {
        Self::new(rules, None, Settings::default())
    }

    /// The engine with no rules: what an analyzer runs under until given one.
    #[must_use]
    pub fn empty() -> Self {
        EMPTY.clone()
    }

    /// The trait rules.
    #[must_use]
    pub fn rules(&self) -> &Arc<CapabilityMapper> {
        &self.0.rules
    }

    /// The YARA rules the top-level pipeline scans with; `None` when YARA is off.
    #[must_use]
    pub(crate) fn yara(&self) -> Option<&Arc<YaraEngine>> {
        self.0.yara.as_ref()
    }

    #[must_use]
    pub(crate) fn settings(&self) -> &Settings {
        &self.0.settings
    }

    /// Whether UPX-packed executables are unpacked.
    #[must_use]
    pub(crate) fn upx(&self) -> bool {
        self.0.settings.upx
    }

    /// Whether native binaries are disassembled with rizin.
    #[must_use]
    pub(crate) fn radare2(&self) -> bool {
        self.0.settings.radare2
    }

    /// The filefacts options this engine's analyses parse files with. Per
    /// parse, so another engine's settings never reach these files.
    pub(crate) fn filefacts_options(&self) -> filefacts::OpenOptions<'static> {
        filefacts_options(&self.0.settings)
    }

    /// Whether archive members fold into the compact projection.
    #[must_use]
    pub(crate) fn compact_members(&self) -> bool {
        self.0.settings.compact_members
    }

    /// This engine with different analysis settings, sharing its rules and YARA.
    #[must_use]
    pub(crate) fn with_settings(&self, settings: Settings) -> Self {
        if settings == self.0.settings {
            return self.clone();
        }
        Self::new(self.0.rules.clone(), self.0.yara.clone(), settings)
    }

    /// This engine, folding archive members into the compact projection or not.
    ///
    /// Compact folding drops what only the full v3 output reads as each member
    /// folds into its container; a caller that consumes only the compact
    /// projection saves most of an archive's member memory with it.
    #[must_use]
    pub fn with_compact_members(&self, compact: bool) -> Self {
        self.with_settings(Settings {
            compact_members: compact,
            ..self.0.settings.clone()
        })
    }
}

/// Building an engine and analyzing with it.
///
/// Every `analyze_*` method takes the per-call inputs from `options`: zip
/// passwords, cancellation, size limits, sample extraction and phase
/// tracking. What the engine was built with (rules, YARA, UPX, radare2 and its
/// limits, platforms, precision thresholds, member folding) comes from the
/// engine, and the fields of `options` that describe it are not consulted.
impl Engine {
    /// The engine `options` describe: the process's shared rules and YARA
    /// engine for them (loaded on first use, then reused), with `options`'
    /// YARA, UPX and radare2 settings and full member retention. Build one at startup
    /// and analyze every file with it.
    ///
    /// Only `options` count: unlike the `AnalysisOptions` free functions, the
    /// process-wide switches ([`crate::disable_upx`],
    /// [`crate::set_compact_member_retention`]) do not apply. Use
    /// [`Self::with_compact_members`] for compact folding.
    ///
    /// # Errors
    /// When the rules cannot be loaded.
    pub fn for_options(options: &AnalysisOptions) -> anyhow::Result<Self> {
        crate::shared_resources::explicit_engine_for_options(options)
    }

    /// Analyze the file at `path`.
    ///
    /// # Errors
    /// When the file cannot be read, or analysis fails or panics.
    pub fn analyze_file<P: AsRef<Path>>(
        &self,
        path: P,
        options: &AnalysisOptions,
    ) -> anyhow::Result<AnalysisReport> {
        crate::analyze_path_under(path.as_ref(), options, &EngineFor::Given(self))
    }

    /// Analyze `data`, labeled `filename` for type detection and reporting
    /// (it need not exist on disk).
    ///
    /// # Errors
    /// When analysis fails or panics.
    pub fn analyze_bytes(
        &self,
        data: Vec<u8>,
        filename: &str,
        options: &AnalysisOptions,
    ) -> anyhow::Result<AnalysisReport> {
        crate::analyze_data_under(
            crate::file_io::FileData::Owned(data),
            filename,
            options,
            &EngineFor::Given(self),
        )
    }

    /// [`Self::analyze_bytes`] over a refcounted buffer, adopted without a copy.
    ///
    /// # Errors
    /// When analysis fails or panics.
    pub fn analyze_bytes_shared(
        &self,
        data: bytes::Bytes,
        filename: &str,
        options: &AnalysisOptions,
    ) -> anyhow::Result<AnalysisReport> {
        crate::analyze_data_under(
            crate::file_io::FileData::Shared(data),
            filename,
            options,
            &EngineFor::Given(self),
        )
    }
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("traits", &self.0.rules.trait_definitions_count())
            .field("composites", &self.0.rules.composite_rules_count())
            .field("yara", &self.0.yara.is_some())
            .field("settings", &self.0.settings)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::TargetInfo;

    fn member_report(path: &str) -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo {
            path: path.to_string(),
            file_type: "json".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        report.values_tree = Some(Box::new(serde_json::json!({"name": "x"})));
        report
    }

    /// Compact folding keeps a member's `kv` only when a rule reads it as a
    /// sibling (`config.json::name`). Which rules count is the folding
    /// engine's to say: this once consulted the process-wide mapper instead,
    /// so a caller analyzing with its own rules had member facts dropped
    /// whenever that slot was empty.
    #[test]
    fn compact_folding_keeps_what_the_engines_rules_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("kv.yaml"),
            r#"
defaults:
  for: [binaries, scripts, source, manifests, documents, media, data, archives]

traits:
  - id: "test/kv::reads-config-name"
    desc: "Reads a sibling config value"
    crit: baseline
    if:
      type: value
      path: "config.json::name"
      exact: "x"
"#,
        )
        .unwrap();
        let rules = CapabilityMapper::from_directory_with_options(
            dir.path(),
            CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false,
            false,
        )
        .unwrap();
        assert!(rules.kv_sibling_basenames().contains("config.json"));
        let reading = Engine::from_rules(Arc::new(rules)).with_compact_members(true);
        let blind = Engine::empty().with_compact_members(true);

        let (kept, _, _) = member_report("pkg/config.json").into_file_analysis(1, &reading);
        let (dropped, _, _) = member_report("pkg/config.json").into_file_analysis(1, &blind);
        assert_eq!(kept.kv.get("name"), Some(&serde_json::json!("x")));
        assert!(dropped.kv.is_empty(), "{:?}", dropped.kv);

        // Full retention keeps it either way.
        let (full, _, _) = member_report("pkg/config.json").into_file_analysis(1, &Engine::empty());
        assert_eq!(full.kv.get("name"), Some(&serde_json::json!("x")));
    }

    /// Rizin is a per-file setting: a vendored native module inside a package
    /// skips it while the same binary elsewhere in the package does not, even
    /// though identical bytes would otherwise share one analysis and one cache
    /// entry. Before filefacts 2 this skip muted rizin only around `open`, so
    /// it never took effect.
    #[test]
    fn archive_member_rizin_skip_is_per_member() {
        if !filefacts::rizin::available() {
            eprintln!("rizin not installed; skipping");
            return;
        }
        let elf = std::fs::read("tests/fixtures/lang_strings/go_linux_amd64").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("pkg.zip");
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let stored = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            for name in ["node_modules/x/prebuilds/linux-x64/x.node", "bin/tool"] {
                zip.start_file(name, stored).unwrap();
                std::io::Write::write_all(&mut zip, &elf).unwrap();
            }
            zip.finish().unwrap();
        }
        let options = AnalysisOptions {
            disable_yara: true,
            ..AnalysisOptions::default()
        };
        let report = Engine::for_options(&options)
            .unwrap()
            .analyze_file(&zip_path, &options)
            .unwrap();
        let disassembled = |suffix: &str| {
            let file = report
                .files
                .iter()
                .find(|f| f.path.ends_with(suffix))
                .expect("both members are in the report");
            file.filefacts_metrics
                .as_ref()
                .is_some_and(|m| m.contains_key("binary.basic_block_count"))
        };
        assert!(disassembled("bin/tool"));
        assert!(!disassembled("x.node"));
    }

    #[test]
    fn settings_changes_share_rules_and_yara() {
        let engine = Engine::empty();
        let compact = engine.with_compact_members(true);
        assert!(Arc::ptr_eq(engine.rules(), compact.rules()));
        assert!(compact.compact_members() && !engine.compact_members());
        // An unchanged setting reuses the engine itself.
        assert!(Arc::ptr_eq(
            &compact.0,
            &compact.with_compact_members(true).0
        ));
    }
}

#[cfg(test)]
mod retry_settings_tests {
    #[test]
    fn native_retry_setting_survives_engine_configuration() {
        let options = crate::AnalysisOptions {
            rizin_timeout: Some(std::time::Duration::from_secs(60)),
            rizin_retry_timeout: Some(std::time::Duration::from_secs(120)),
            ..crate::AnalysisOptions::default()
        };
        let settings = crate::shared_resources::settings_from_options(&options);
        assert_eq!(settings.rizin_timeout, options.rizin_timeout);
        assert_eq!(settings.rizin_retry_timeout, options.rizin_retry_timeout);
        let _parser_options = super::filefacts_options(&settings);
    }
}
