//! Element mapping from malware categories to periodic table symbols.
//!
//! Maps finding categories to real periodic table elements for visualization
//! in molecular viewers like MolView or Three.js.
//!
//! Mnemonic guide for security engineers reading formulas:
//!
//! Top-level: O(bjectives) H(micro-behaviors) Md(metadata) K(nown) Th(ird-party)
//!
//! Objectives:  Al(anti-analysis) As(anti-static) C(2/c&c) Ca(credential-access)
//!   Co(llection) Dy(discoverY) Er(vasion) Eu(xfiltration) I(mpact) La(teral)
//!   P(ersistence) Pr(ivilege) S(upply-chain) Xe(xecution)
//!
//! Micro-behaviors: Br(owser-extension) Cm(comms) Cr(ypto) Db(data) Ds(dylib/shared)
//!   F(ilesystem) Hf(hardware) Mg(memory) Os(operating-system) Po(process) Ti(me) U(I)
//!
//! Metadata: Ar(ch) Bi(nary) Bk(build) Cf(config) He(hardening) In(import)
//!   Ir(image) Li(brary) Pa(ckage) Pd(ocument) Pm(ermission) Pt(lang)
//!   Re(gistry) Rh(ights/entitlements) Si(gned) V(endor)
//!   + deeper: Ag(format) Au(quality) B(undle) Ce(compiler) Ne(archive)
//!
//! Well-known: Am(pp) Ga(me) Li(b — shared with metadata/library) Lu(duaL-Use)
//!   Mc(malware-code) Nd(uNwanteD) Te(ool)

use rustc_hash::FxHashMap;

/// Atomic number and symbol for a periodic table element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Element {
    /// Atomic number (1-118)
    pub(crate) number: u8,
    /// Element symbol (1-2 chars)
    pub(crate) symbol: &'static str,
    /// Full element name
    pub(crate) name: &'static str,
}

impl Element {
    const fn new(number: u8, symbol: &'static str, name: &'static str) -> Self {
        Self {
            number,
            symbol,
            name,
        }
    }
}

// ── Top-level categories ────────────────────────────────────────────────────

/// O for Objectives.
pub(crate) const OXYGEN: Element = Element::new(8, "O", "Oxygen");
/// H for micro-behaviors (small and common, like hydrogen).
pub(crate) const HYDROGEN_MICRO: Element = Element::new(1, "H", "Hydrogen");
/// Md for MetaData.
pub(crate) const MENDELEVIUM: Element = Element::new(101, "Md", "Mendelevium");
/// K for Known (well-known malware/tools).
pub(crate) const POTASSIUM: Element = Element::new(19, "K", "Potassium");
/// Th for THird-party signatures.
pub(crate) const THORIUM: Element = Element::new(90, "Th", "Thorium");

// ── Objective subcategories ─────────────────────────────────────────────────

/// Al for Anti-anaLysis.
pub(crate) const ALUMINUM: Element = Element::new(13, "Al", "Aluminum");
/// As for Anti-Static.
pub(crate) const ARSENIC: Element = Element::new(33, "As", "Arsenic");
/// C for C2 / Command-and-control.
pub(crate) const CARBON: Element = Element::new(6, "C", "Carbon");
/// Co for COllection.
pub(crate) const COBALT: Element = Element::new(27, "Co", "Cobalt");
/// Ca for Credential-Access.
pub(crate) const CALCIUM: Element = Element::new(20, "Ca", "Calcium");
/// Dy for DiscoverY.
pub(crate) const DYSPROSIUM: Element = Element::new(66, "Dy", "Dysprosium");
/// Er for Evasion.
pub(crate) const ERBIUM: Element = Element::new(68, "Er", "Erbium");
/// Eu for Exfiltration.
pub(crate) const EUROPIUM: Element = Element::new(63, "Eu", "Europium");
/// I for Impact.
pub(crate) const IODINE: Element = Element::new(53, "I", "Iodine");
/// La for LAteral-movement.
pub(crate) const LANTHANUM: Element = Element::new(57, "La", "Lanthanum");
/// P for Persistence.
pub(crate) const PHOSPHORUS: Element = Element::new(15, "P", "Phosphorus");
/// Pr for PRivilege-escalation.
pub(crate) const PRASEODYMIUM: Element = Element::new(59, "Pr", "Praseodymium");
/// S for Supply-chain.
pub(crate) const SULFUR: Element = Element::new(16, "S", "Sulfur");
/// Xe for eXEcution.
pub(crate) const XENON: Element = Element::new(54, "Xe", "Xenon");

// ── Micro-behavior subcategories ────────────────────────────────────────────

/// Br for BRowser-extension.
pub(crate) const BROMINE: Element = Element::new(35, "Br", "Bromine");
/// Cm for CoMms/communications.
pub(crate) const CURIUM: Element = Element::new(96, "Cm", "Curium");
/// Cr for CRypto.
pub(crate) const CHROMIUM: Element = Element::new(24, "Cr", "Chromium");
/// Db for Data(Base).
pub(crate) const DUBNIUM: Element = Element::new(105, "Db", "Dubnium");
/// Ds for Dylib/Dynamic-Shared.
pub(crate) const DARMSTADTIUM: Element = Element::new(110, "Ds", "Darmstadtium");
/// F for Filesystem.
pub(crate) const FLUORINE: Element = Element::new(9, "F", "Fluorine");
/// Hf for HardFare → Hardware.
pub(crate) const HAFNIUM: Element = Element::new(72, "Hf", "Hafnium");
/// Mg for MeMory.
pub(crate) const MAGNESIUM: Element = Element::new(12, "Mg", "Magnesium");
/// Os for Operating System.
pub(crate) const OSMIUM: Element = Element::new(76, "Os", "Osmium");
/// Po for PrOcess.
pub(crate) const POLONIUM: Element = Element::new(84, "Po", "Polonium");
/// Ti for TIme.
pub(crate) const TITANIUM: Element = Element::new(22, "Ti", "Titanium");
/// U for UI.
pub(crate) const URANIUM: Element = Element::new(92, "U", "Uranium");

// ── Metadata subcategories ──────────────────────────────────────────────────

/// Ar for ARchitecture.
pub(crate) const ARGON: Element = Element::new(18, "Ar", "Argon");
/// Bi for BInary.
pub(crate) const BISMUTH: Element = Element::new(83, "Bi", "Bismuth");
/// Bk for Build (Kit).
pub(crate) const BERKELIUM: Element = Element::new(97, "Bk", "Berkelium");
/// Cf for ConFig.
pub(crate) const CALIFORNIUM: Element = Element::new(98, "Cf", "Californium");
/// Pd for PDF/Document.
pub(crate) const PALLADIUM: Element = Element::new(46, "Pd", "Palladium");
/// Rh for RigHts/entitlements.
pub(crate) const RHODIUM: Element = Element::new(45, "Rh", "Rhodium");
/// He for HardEning.
pub(crate) const HELIUM: Element = Element::new(2, "He", "Helium");
/// In for Import.
pub(crate) const INDIUM: Element = Element::new(49, "In", "Indium");
/// Ir for Image.
pub(crate) const IRIDIUM: Element = Element::new(77, "Ir", "Iridium");
/// Pt for lang (precious metal, like Au/Ag).
pub(crate) const PLATINUM: Element = Element::new(78, "Pt", "Platinum");
/// Li for LIbrary.
pub(crate) const LITHIUM: Element = Element::new(3, "Li", "Lithium");
/// Pa for PAckage.
pub(crate) const PROTACTINIUM: Element = Element::new(91, "Pa", "Protactinium");
/// Pm for PerMission.
pub(crate) const PROMETHIUM: Element = Element::new(61, "Pm", "Promethium");
/// Re for REgistry.
pub(crate) const RHENIUM: Element = Element::new(75, "Re", "Rhenium");
/// Si for SIgned.
pub(crate) const SILICON: Element = Element::new(14, "Si", "Silicon");
/// V for Vendor.
pub(crate) const VANADIUM: Element = Element::new(23, "V", "Vanadium");

// Deeper-segment metadata matches (3rd+ level, not in formulas but used by
// finding_to_element for atom labeling):

/// Au for quality (gold standard).
pub(crate) const GOLD: Element = Element::new(79, "Au", "Gold");
/// Ag for format (precious metal theme).
pub(crate) const SILVER: Element = Element::new(47, "Ag", "Silver");
/// B for Bundle.
pub(crate) const BORON: Element = Element::new(5, "B", "Boron");
/// Ce for CompilEr.
pub(crate) const CERIUM: Element = Element::new(58, "Ce", "Cerium");
/// Ne for archive (swapped from arch for better Ar mnemonic).
pub(crate) const NEON: Element = Element::new(10, "Ne", "Neon");

// ── Well-known subcategories ────────────────────────────────────────────────

/// Am for APplication (Americium).
pub(crate) const AMERICIUM: Element = Element::new(95, "Am", "Americium");
/// Ga for GAme.
pub(crate) const GALLIUM: Element = Element::new(31, "Ga", "Gallium");
/// Lu for duaL-Use.
pub(crate) const LUTETIUM: Element = Element::new(71, "Lu", "Lutetium");
/// Mc for Malicious-Code → malware (synthetic transuranic, fits the
/// engineered-toxin theme).
pub(crate) const MOSCOVIUM: Element = Element::new(115, "Mc", "Moscovium");
/// Nd for uNwanteD.
pub(crate) const NEODYMIUM: Element = Element::new(60, "Nd", "Neodymium");
/// Te for Tool (Tellurium retained from the prior `tools` mapping).
pub(crate) const TELLURIUM: Element = Element::new(52, "Te", "Tellurium");
// Note: well-known/lib reuses LITHIUM (Li) — same concept as metadata/library,
// disambiguated by parent (K vs Md) in the formula.

// ── Decoration ──────────────────────────────────────────────────────────────

/// Maps a category path segment to its element.
#[must_use]
pub(crate) fn category_to_element(category: &str) -> Option<Element> {
    static MAP: std::sync::OnceLock<FxHashMap<&'static str, Element>> = std::sync::OnceLock::new();

    let map = MAP.get_or_init(|| {
        let mut m = FxHashMap::default();

        // Top-level categories
        m.insert("objectives", OXYGEN);
        m.insert("micro-behaviors", HYDROGEN_MICRO);
        m.insert("metadata", MENDELEVIUM);
        m.insert("well-known", POTASSIUM);
        m.insert("third_party", THORIUM);
        m.insert("third-party", THORIUM);

        // Objective subcategories
        m.insert("anti-analysis", ALUMINUM);
        m.insert("anti-static", ARSENIC);
        m.insert("collection", COBALT);
        m.insert("command-and-control", CARBON);
        m.insert("credential-access", CALCIUM);
        m.insert("discovery", DYSPROSIUM);
        m.insert("evasion", ERBIUM);
        m.insert("execution", XENON);
        m.insert("exfiltration", EUROPIUM);
        m.insert("impact", IODINE);
        m.insert("lateral-movement", LANTHANUM);
        m.insert("persistence", PHOSPHORUS);
        m.insert("privilege-escalation", PRASEODYMIUM);
        m.insert("supply-chain", SULFUR);

        // Micro-behavior subcategories
        m.insert("browser-extension", BROMINE);
        m.insert("communications", CURIUM);
        m.insert("crypto", CHROMIUM);
        m.insert("data", DUBNIUM);
        m.insert("dylib", DARMSTADTIUM);
        m.insert("fs", FLUORINE);
        m.insert("hardware", HAFNIUM);
        m.insert("mem", MAGNESIUM);
        m.insert("os", OSMIUM);
        m.insert("process", POLONIUM);
        m.insert("time", TITANIUM);
        m.insert("ui", URANIUM);

        // Metadata subcategories (top-level under metadata/)
        m.insert("arch", ARGON);
        m.insert("binary", BISMUTH);
        m.insert("build", BERKELIUM);
        m.insert("document", PALLADIUM);
        // NOTE: "file" deliberately omitted — collides with micro-behaviors/fs/file.
        // metadata/file findings fall through to parent Md (Mendelevium).
        m.insert("hardening", HELIUM);
        m.insert("image", IRIDIUM);
        m.insert("import", INDIUM);
        m.insert("lang", PLATINUM);
        m.insert("library", LITHIUM);
        m.insert("package", PROTACTINIUM);
        m.insert("permission", PROMETHIUM);
        m.insert("registry", RHENIUM);
        m.insert("signed", SILICON);
        m.insert("vendor", VANADIUM);

        // Metadata deeper-segment matches (3rd+ level, for finding_to_element)
        m.insert("archive", NEON);
        m.insert("bundle", BORON);
        m.insert("compiler", CERIUM);
        m.insert("config", CALIFORNIUM);
        m.insert("entitlements", RHODIUM);
        m.insert("format", SILVER);
        m.insert("quality", GOLD);

        // Well-known subcategories
        m.insert("malware", MOSCOVIUM);
        m.insert("app", AMERICIUM);
        m.insert("dual-use", LUTETIUM);
        m.insert("game", GALLIUM);
        m.insert("lib", LITHIUM);
        m.insert("tool", TELLURIUM);
        m.insert("unwanted", NEODYMIUM);

        m
    });

    map.get(category).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_mapping() {
        assert_eq!(category_to_element("objectives"), Some(OXYGEN));
        assert_eq!(category_to_element("lateral-movement"), Some(LANTHANUM));
        assert_eq!(category_to_element("fs"), Some(FLUORINE));
        assert_eq!(category_to_element("nonexistent"), None);
    }

    #[test]
    fn test_new_mappings() {
        assert_eq!(category_to_element("document"), Some(PALLADIUM));
        assert_eq!(category_to_element("build"), Some(BERKELIUM));
        assert_eq!(category_to_element("arch"), Some(ARGON));
        assert_eq!(category_to_element("third-party"), Some(THORIUM));
    }

    #[test]
    fn test_well_known_subcategories() {
        // well-known/{app,game,lib,tool,malware} must each map to a distinct
        // element so a formula can distinguish e.g. an app finding from a
        // malware finding under the K (well-known) parent.
        assert_eq!(category_to_element("app"), Some(AMERICIUM));
        assert_eq!(category_to_element("game"), Some(GALLIUM));
        assert_eq!(category_to_element("lib"), Some(LITHIUM));
        assert_eq!(category_to_element("malware"), Some(MOSCOVIUM));
        assert_eq!(category_to_element("tool"), Some(TELLURIUM));
        // Formerly mapped under the typoed `tools` key.
        assert_eq!(category_to_element("tools"), None);
    }

    #[test]
    fn test_removed_mappings() {
        // These directories no longer exist
        assert_eq!(category_to_element("resource-development"), None);
        assert_eq!(category_to_element("dev"), None);
        assert_eq!(category_to_element("analytics"), None);
        assert_eq!(category_to_element("encoded-payload"), None);
        assert_eq!(category_to_element("builder"), None);
        // Removed during the 2026-05 trait-hierarchy resync — no findings
        // reference these paths anymore.
        assert_eq!(category_to_element("host"), None);
        assert_eq!(category_to_element("network"), None);
        // NOTE: metadata/vendor was believed removed during the 2026-05
        // resync but is present again in traits-dev — see
        // test_2026_09_resync_mappings.
    }

    /// Directories added to the traits taxonomy map to their own elements.
    #[test]
    fn newer_taxonomy_directories_have_elements() {
        assert_eq!(category_to_element("browser-extension"), Some(BROMINE));
        assert_eq!(category_to_element("dual-use"), Some(LUTETIUM));
        assert_eq!(category_to_element("unwanted"), Some(NEODYMIUM));
        assert_eq!(category_to_element("image"), Some(IRIDIUM));
        assert_eq!(category_to_element("permission"), Some(PROMETHIUM));
        assert_eq!(category_to_element("registry"), Some(RHENIUM));
        assert_eq!(category_to_element("vendor"), Some(VANADIUM));
    }
}
