//! Element mapping from malware categories to periodic table symbols.
//!
//! Maps finding categories to real periodic table elements for visualization
//! in molecular viewers like MolView or Three.js.

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

/// Carbon - Command and Control objective.
pub const CARBON: Element = Element::new(6, "C", "Carbon");
/// Oxygen - Objectives category.
pub const OXYGEN: Element = Element::new(8, "O", "Oxygen");
/// Hydrogen - Micro-behaviors category (small and common).
pub const HYDROGEN_MICRO: Element = Element::new(1, "H", "Hydrogen");
/// Mendelevium - Metadata category.
pub const MENDELEVIUM: Element = Element::new(101, "Md", "Mendelevium");

/// Aluminum - anti-analysis objective.
pub const ALUMINUM: Element = Element::new(13, "Al", "Aluminum");
/// Arsenic - anti-static objective.
pub const ARSENIC: Element = Element::new(33, "As", "Arsenic");
/// Cobalt - collection objective.
pub const COBALT: Element = Element::new(27, "Co", "Cobalt");
/// Copper - (unused, command-and-control now uses Carbon).
pub const COPPER: Element = Element::new(29, "Cu", "Copper");
/// Calcium - credential-access objective.
pub const CALCIUM: Element = Element::new(20, "Ca", "Calcium");
/// Dysprosium - discovery objective.
pub const DYSPROSIUM: Element = Element::new(66, "Dy", "Dysprosium");
/// Xenon - execution objective.
pub const XENON: Element = Element::new(54, "Xe", "Xenon");
/// Europium - exfiltration objective.
pub const EUROPIUM: Element = Element::new(63, "Eu", "Europium");
/// Iodine - impact objective.
pub const IODINE: Element = Element::new(53, "I", "Iodine");
/// Lanthanum - lateral-movement objective.
pub const LANTHANUM: Element = Element::new(57, "La", "Lanthanum");
/// Phosphorus - persistence objective.
pub const PHOSPHORUS: Element = Element::new(15, "P", "Phosphorus");
/// Praseodymium - privilege-escalation objective.
pub const PRASEODYMIUM: Element = Element::new(59, "Pr", "Praseodymium");
/// Erbium - evasion objective.
pub const ERBIUM: Element = Element::new(68, "Er", "Erbium");
/// Rubidium - resource-development objective.
pub const RUBIDIUM: Element = Element::new(37, "Rb", "Rubidium");

/// Chromium - crypto micro-behavior.
pub const CHROMIUM: Element = Element::new(24, "Cr", "Chromium");
/// Curium - communications micro-behavior.
pub const CURIUM: Element = Element::new(96, "Cm", "Curium");
/// Fluorine - filesystem micro-behavior.
pub const FLUORINE: Element = Element::new(9, "F", "Fluorine");
/// Polonium - process micro-behavior.
pub const POLONIUM: Element = Element::new(84, "Po", "Polonium");
/// Osmium - OS micro-behavior.
pub const OSMIUM: Element = Element::new(76, "Os", "Osmium");
/// Dubnium - data micro-behavior.
pub const DUBNIUM: Element = Element::new(105, "Db", "Dubnium");
/// Holmium - host micro-behavior.
pub const HOLMIUM: Element = Element::new(67, "Ho", "Holmium");
/// Hafnium - hardware micro-behavior.
pub const HAFNIUM: Element = Element::new(72, "Hf", "Hafnium");
/// Neptunium - network micro-behavior.
pub const NEPTUNIUM: Element = Element::new(93, "Np", "Neptunium");
/// Darmstadtium - dylib micro-behavior.
pub const DYLIB: Element = Element::new(110, "Ds", "Darmstadtium");
/// Actinium - anti-analysis micro-behavior.
pub const ACTINIUM: Element = Element::new(89, "Ac", "Actinium");
/// Astatine - anti-static micro-behavior.
pub const ASTATINE: Element = Element::new(85, "At", "Astatine");
/// Einsteinium - execution micro-behavior.
pub const EINSTEINIUM: Element = Element::new(99, "Es", "Einsteinium");

/// Gold - quality metadata.
pub const GOLD: Element = Element::new(79, "Au", "Gold");
/// Silver - format metadata.
pub const SILVER: Element = Element::new(47, "Ag", "Silver");
/// Platinum - lang metadata.
pub const PLATINUM: Element = Element::new(78, "Pt", "Platinum");
/// Bismuth - binary metadata (Bi for Binary).
pub const BISMUTH: Element = Element::new(83, "Bi", "Bismuth");
/// Protactinium - package metadata (Pa for Package).
pub const PROTACTINIUM: Element = Element::new(91, "Pa", "Protactinium");
/// Silicon - signed metadata (Si for Signed).
pub const SILICON: Element = Element::new(14, "Si", "Silicon");
/// Vanadium - vendor metadata (V for Vendor).
pub const VANADIUM: Element = Element::new(23, "V", "Vanadium");
/// Lithium - library metadata (Li for Library).
pub const LITHIUM: Element = Element::new(3, "Li", "Lithium");
/// Argon - archive metadata (Ar for Archive).
pub const ARGON: Element = Element::new(18, "Ar", "Argon");
/// Berkelium - builder metadata (Bk for Build).
pub const BERKELIUM: Element = Element::new(97, "Bk", "Berkelium");
/// Boron - bundle metadata (B for Bundle).
pub const BORON: Element = Element::new(5, "B", "Boron");
/// Cerium - compiler metadata (Ce for Compile).
pub const CERIUM: Element = Element::new(58, "Ce", "Cerium");
/// Californium - config metadata (Cf for Config).
pub const CALIFORNIUM: Element = Element::new(98, "Cf", "Californium");
/// Germanium - dev metadata.
pub const GERMANIUM: Element = Element::new(32, "Ge", "Germanium");
/// Rhodium - entitlements metadata (Rh for Rights).
pub const RHODIUM: Element = Element::new(45, "Rh", "Rhodium");
/// Iron - file metadata (Fe for File).
pub const IRON: Element = Element::new(26, "Fe", "Iron");
/// Helium - hardening metadata (He for Hardening).
pub const HELIUM: Element = Element::new(2, "He", "Helium");
/// Indium - import metadata (In for Import).
pub const INDIUM: Element = Element::new(49, "In", "Indium");
/// Americium - analytics metadata (Am for Analytics).
pub const AMERICIUM: Element = Element::new(95, "Am", "Americium");
/// Neon - arch metadata (Ne for nearest match).
pub const NEON: Element = Element::new(10, "Ne", "Neon");
/// Terbium - encoded-payload metadata.
pub const TERBIUM: Element = Element::new(65, "Tb", "Terbium");

/// Potassium - well-known (K for "Known") malware families.
pub const POTASSIUM: Element = Element::new(19, "K", "Potassium");
/// Tellurium - well-known tools (Te for Tools).
pub const TELLURIUM: Element = Element::new(52, "Te", "Tellurium");

/// Thorium - third-party signatures/rules.
pub const THORIUM: Element = Element::new(90, "Th", "Thorium");

/// Sulfur - supply-chain objective (S for Supply).
pub const SULFUR: Element = Element::new(16, "S", "Sulfur");
/// Magnesium - mem micro-behavior (Mg for Memory).
pub const MAGNESIUM: Element = Element::new(12, "Mg", "Magnesium");
/// Titanium - time micro-behavior (Ti for Time).
pub const TITANIUM: Element = Element::new(22, "Ti", "Titanium");
/// Uranium - UI micro-behavior (U for UI).
pub const URANIUM: Element = Element::new(92, "U", "Uranium");

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

        // Objective subcategories
        m.insert("anti-analysis", ALUMINUM);
        m.insert("anti-static", ARSENIC);
        m.insert("collection", COBALT);
        m.insert("command-and-control", CARBON);
        m.insert("credential-access", CALCIUM);
        m.insert("discovery", DYSPROSIUM);
        m.insert("execution", XENON);
        m.insert("exfiltration", EUROPIUM);
        m.insert("impact", IODINE);
        m.insert("lateral-movement", LANTHANUM);
        m.insert("persistence", PHOSPHORUS);
        m.insert("privilege-escalation", PRASEODYMIUM);
        m.insert("evasion", ERBIUM);
        m.insert("resource-development", RUBIDIUM);
        m.insert("supply-chain", SULFUR);

        // Micro-behavior subcategories
        m.insert("crypto", CHROMIUM);
        m.insert("communications", CURIUM);
        m.insert("fs", FLUORINE);
        m.insert("process", POLONIUM);
        m.insert("os", OSMIUM);
        m.insert("data", DUBNIUM);
        m.insert("host", HOLMIUM);
        m.insert("hardware", HAFNIUM);
        m.insert("network", NEPTUNIUM);
        m.insert("dylib", DYLIB);
        m.insert("mem", MAGNESIUM);
        m.insert("time", TITANIUM);
        m.insert("ui", URANIUM);

        // Metadata subcategories
        m.insert("quality", GOLD);
        m.insert("format", SILVER);
        m.insert("lang", PLATINUM);
        m.insert("binary", BISMUTH);
        m.insert("package", PROTACTINIUM);
        m.insert("signed", SILICON);
        m.insert("vendor", VANADIUM);
        m.insert("library", LITHIUM);
        m.insert("archive", ARGON);
        m.insert("builder", BERKELIUM);
        m.insert("bundle", BORON);
        m.insert("compiler", CERIUM);
        m.insert("config", CALIFORNIUM);
        m.insert("dev", GERMANIUM);
        m.insert("entitlements", RHODIUM);
        // NOTE: "file" deliberately omitted — it collides with micro-behaviors/fs/file path segments.
        // metadata/file findings will fall through to parent Md (Mendelevium).
        m.insert("hardening", HELIUM);
        m.insert("import", INDIUM);
        m.insert("analytics", AMERICIUM);
        m.insert("arch", NEON);
        m.insert("encoded-payload", TERBIUM);

        // Malware families (well-known)
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
        | "execution"
        | "exfiltration"
        | "impact"
        | "lateral-movement"
        | "persistence"
        | "privilege-escalation"
        | "evasion"
        | "resource-development"
        | "supply-chain" => Some(OXYGEN),

        // Micro-behavior subcategories -> H
        "crypto" | "communications" | "fs" | "process" | "os" | "data" | "host" | "hardware"
        | "network" | "dylib" | "mem" | "time" | "ui" => Some(HYDROGEN_MICRO),

        // Metadata subcategories -> Md
        "quality" | "format" | "lang" | "binary" | "package" | "signed" | "vendor" | "library"
        | "archive" | "builder" | "bundle" | "compiler" | "config" | "dev" | "entitlements"
        | "file" | "hardening" | "import" | "analytics" | "arch" | "encoded-payload" => {
            Some(MENDELEVIUM)
        }

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
    fn test_parent_element() {
        assert_eq!(parent_element("lateral-movement"), Some(OXYGEN));
        assert_eq!(parent_element("fs"), Some(HYDROGEN_MICRO));
        assert_eq!(parent_element("quality"), Some(MENDELEVIUM));
    }
}
