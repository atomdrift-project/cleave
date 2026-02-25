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

/// Potassium - well-known (K for "Known") malware families.
pub const POTASSIUM: Element = Element::new(19, "K", "Potassium");

/// Thorium - third-party signatures/rules.
pub const THORIUM: Element = Element::new(90, "Th", "Thorium");

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

        // Metadata subcategories
        m.insert("quality", GOLD);
        m.insert("format", SILVER);
        m.insert("lang", PLATINUM);

        // Malware families (well-known)
        m.insert("malware", POTASSIUM);

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
        | "resource-development" => Some(OXYGEN),

        // Micro-behavior subcategories -> H
        "crypto" | "communications" | "fs" | "process" | "os" | "data" | "host" | "hardware"
        | "network" | "dylib" => Some(HYDROGEN_MICRO),

        // Metadata subcategories -> Mg
        "quality" | "format" | "lang" => Some(MENDELEVIUM),

        // Well-known -> W
        "malware" => Some(POTASSIUM),

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
