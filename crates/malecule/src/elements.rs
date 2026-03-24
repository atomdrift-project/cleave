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
//! Micro-behaviors: Cm(comms) Cr(ypto) Db(data) Ds(dylib/shared) F(ilesystem)
//!   Hf(hardware) Ho(st) Mg(memory) N(etwork) Os(operating-system) Po(process)
//!   Ti(me) U(I)
//!
//! Metadata: Ar(ch) Bi(nary) Bk(build) Cf(config) He(hardening) In(import)
//!   Li(brary) Pa(ckage) Pd(ocument) Pt(lang) Rh(ights/entitlements) Si(gned)
//!   V(endor) + deeper: Ag(format) Au(quality) B(undle) Ce(compiler) Ne(archive)

use rustc_hash::FxHashMap;

/// Atomic number and symbol for a periodic table element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element {
    /// Atomic number (1-118)
    pub number: u8,
    /// Element symbol (1-2 chars)
    pub symbol: &'static str,
    /// Full element name
    pub name: &'static str,
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
pub const OXYGEN: Element = Element::new(8, "O", "Oxygen");
/// H for micro-behaviors (small and common, like hydrogen).
pub const HYDROGEN_MICRO: Element = Element::new(1, "H", "Hydrogen");
/// Md for MetaData.
pub const MENDELEVIUM: Element = Element::new(101, "Md", "Mendelevium");
/// K for Known (well-known malware/tools).
pub const POTASSIUM: Element = Element::new(19, "K", "Potassium");
/// Th for THird-party signatures.
pub const THORIUM: Element = Element::new(90, "Th", "Thorium");

// ── Objective subcategories ─────────────────────────────────────────────────

/// Al for Anti-anaLysis.
pub const ALUMINUM: Element = Element::new(13, "Al", "Aluminum");
/// As for Anti-Static.
pub const ARSENIC: Element = Element::new(33, "As", "Arsenic");
/// C for C2 / Command-and-control.
pub const CARBON: Element = Element::new(6, "C", "Carbon");
/// Co for COllection.
pub const COBALT: Element = Element::new(27, "Co", "Cobalt");
/// Ca for Credential-Access.
pub const CALCIUM: Element = Element::new(20, "Ca", "Calcium");
/// Dy for DiscoverY.
pub const DYSPROSIUM: Element = Element::new(66, "Dy", "Dysprosium");
/// Er for Evasion.
pub const ERBIUM: Element = Element::new(68, "Er", "Erbium");
/// Eu for Exfiltration.
pub const EUROPIUM: Element = Element::new(63, "Eu", "Europium");
/// I for Impact.
pub const IODINE: Element = Element::new(53, "I", "Iodine");
/// La for LAteral-movement.
pub const LANTHANUM: Element = Element::new(57, "La", "Lanthanum");
/// P for Persistence.
pub const PHOSPHORUS: Element = Element::new(15, "P", "Phosphorus");
/// Pr for PRivilege-escalation.
pub const PRASEODYMIUM: Element = Element::new(59, "Pr", "Praseodymium");
/// S for Supply-chain.
pub const SULFUR: Element = Element::new(16, "S", "Sulfur");
/// Xe for eXEcution.
pub const XENON: Element = Element::new(54, "Xe", "Xenon");

// ── Micro-behavior subcategories ────────────────────────────────────────────

/// Cm for CoMms/communications.
pub const CURIUM: Element = Element::new(96, "Cm", "Curium");
/// Cr for CRypto.
pub const CHROMIUM: Element = Element::new(24, "Cr", "Chromium");
/// Db for Data(Base).
pub const DUBNIUM: Element = Element::new(105, "Db", "Dubnium");
/// Ds for Dylib/Dynamic-Shared.
pub const DARMSTADTIUM: Element = Element::new(110, "Ds", "Darmstadtium");
/// F for Filesystem.
pub const FLUORINE: Element = Element::new(9, "F", "Fluorine");
/// Hf for HardFare → Hardware.
pub const HAFNIUM: Element = Element::new(72, "Hf", "Hafnium");
/// Ho for HOst.
pub const HOLMIUM: Element = Element::new(67, "Ho", "Holmium");
/// Mg for MeMory.
pub const MAGNESIUM: Element = Element::new(12, "Mg", "Magnesium");
/// N for Network.
pub const NITROGEN: Element = Element::new(7, "N", "Nitrogen");
/// Os for Operating System.
pub const OSMIUM: Element = Element::new(76, "Os", "Osmium");
/// Po for PrOcess.
pub const POLONIUM: Element = Element::new(84, "Po", "Polonium");
/// Ti for TIme.
pub const TITANIUM: Element = Element::new(22, "Ti", "Titanium");
/// U for UI.
pub const URANIUM: Element = Element::new(92, "U", "Uranium");

// ── Metadata subcategories ──────────────────────────────────────────────────

/// Ar for ARchitecture.
pub const ARGON: Element = Element::new(18, "Ar", "Argon");
/// Bi for BInary.
pub const BISMUTH: Element = Element::new(83, "Bi", "Bismuth");
/// Bk for Build (Kit).
pub const BERKELIUM: Element = Element::new(97, "Bk", "Berkelium");
/// Cf for ConFig.
pub const CALIFORNIUM: Element = Element::new(98, "Cf", "Californium");
/// Pd for PDF/Document.
pub const PALLADIUM: Element = Element::new(46, "Pd", "Palladium");
/// Rh for RigHts/entitlements.
pub const RHODIUM: Element = Element::new(45, "Rh", "Rhodium");
/// He for HardEning.
pub const HELIUM: Element = Element::new(2, "He", "Helium");
/// In for Import.
pub const INDIUM: Element = Element::new(49, "In", "Indium");
/// Pt for lang (precious metal, like Au/Ag).
pub const PLATINUM: Element = Element::new(78, "Pt", "Platinum");
/// Li for LIbrary.
pub const LITHIUM: Element = Element::new(3, "Li", "Lithium");
/// Pa for PAckage.
pub const PROTACTINIUM: Element = Element::new(91, "Pa", "Protactinium");
/// Si for SIgned.
pub const SILICON: Element = Element::new(14, "Si", "Silicon");
/// V for Vendor.
pub const VANADIUM: Element = Element::new(23, "V", "Vanadium");

// Deeper-segment metadata matches (3rd+ level, not in formulas but used by
// finding_to_element for atom labeling):

/// Au for quality (gold standard).
pub const GOLD: Element = Element::new(79, "Au", "Gold");
/// Ag for format (precious metal theme).
pub const SILVER: Element = Element::new(47, "Ag", "Silver");
/// B for Bundle.
pub const BORON: Element = Element::new(5, "B", "Boron");
/// Ce for CompilEr.
pub const CERIUM: Element = Element::new(58, "Ce", "Cerium");
/// Ne for archive (swapped from arch for better Ar mnemonic).
pub const NEON: Element = Element::new(10, "Ne", "Neon");

// ── Well-known subcategories ────────────────────────────────────────────────

/// Te for Tools.
pub const TELLURIUM: Element = Element::new(52, "Te", "Tellurium");

// ── Decoration ──────────────────────────────────────────────────────────────

/// Hydrogen - for count decoration.
pub const HYDROGEN: Element = Element::new(1, "H", "Hydrogen");

/// Maps a category path segment to its element.
#[must_use]
pub fn category_to_element(category: &str) -> Option<Element> {
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
        m.insert("communications", CURIUM);
        m.insert("crypto", CHROMIUM);
        m.insert("data", DUBNIUM);
        m.insert("dylib", DARMSTADTIUM);
        m.insert("fs", FLUORINE);
        m.insert("hardware", HAFNIUM);
        m.insert("host", HOLMIUM);
        m.insert("mem", MAGNESIUM);
        m.insert("network", NITROGEN);
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
        m.insert("import", INDIUM);
        m.insert("lang", PLATINUM);
        m.insert("library", LITHIUM);
        m.insert("package", PROTACTINIUM);
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
        m.insert("malware", POTASSIUM);
        m.insert("tools", TELLURIUM);

        m
    });

    map.get(category).copied()
}

/// Returns the parent category element for a given category.
#[must_use]
pub fn parent_element(category: &str) -> Option<Element> {
    match category {
        // Objective subcategories -> O
        "anti-analysis"
        | "anti-static"
        | "collection"
        | "command-and-control"
        | "credential-access"
        | "discovery"
        | "evasion"
        | "execution"
        | "exfiltration"
        | "impact"
        | "lateral-movement"
        | "persistence"
        | "privilege-escalation"
        | "supply-chain" => Some(OXYGEN),

        // Micro-behavior subcategories -> H
        "communications" | "crypto" | "data" | "dylib" | "fs" | "hardware" | "host" | "mem"
        | "network" | "os" | "process" | "time" | "ui" => Some(HYDROGEN_MICRO),

        // Metadata subcategories -> Md
        "arch" | "binary" | "build" | "document" | "file" | "hardening" | "import" | "lang"
        | "library" | "package" | "signed" | "vendor"
        // deeper metadata segments
        | "archive" | "bundle" | "compiler" | "config" | "entitlements" | "format"
        | "quality" => Some(MENDELEVIUM),

        // Well-known
        "malware" | "tools" => Some(POTASSIUM),

        _ => None,
    }
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
        assert_eq!(category_to_element("network"), Some(NITROGEN));
        assert_eq!(category_to_element("arch"), Some(ARGON));
        assert_eq!(category_to_element("third-party"), Some(THORIUM));
    }

    #[test]
    fn test_removed_mappings() {
        // These directories no longer exist
        assert_eq!(category_to_element("resource-development"), None);
        assert_eq!(category_to_element("dev"), None);
        assert_eq!(category_to_element("analytics"), None);
        assert_eq!(category_to_element("encoded-payload"), None);
        assert_eq!(category_to_element("builder"), None);
    }

    #[test]
    fn test_parent_element() {
        assert_eq!(parent_element("lateral-movement"), Some(OXYGEN));
        assert_eq!(parent_element("fs"), Some(HYDROGEN_MICRO));
        assert_eq!(parent_element("quality"), Some(MENDELEVIUM));
        assert_eq!(parent_element("document"), Some(MENDELEVIUM));
        assert_eq!(parent_element("build"), Some(MENDELEVIUM));
    }
}
