//! PE side-by-side manifest extraction.
//!
//! Modern PE binaries embed a Windows side-by-side assembly manifest
//! as `RT_MANIFEST` (resource type 24).  It's an XML document declaring:
//!
//! - **assemblyIdentity**: name + version + processorArchitecture +
//!   publicKeyToken — the binary's own identity in the SxS world.
//! - **trustInfo / requestedExecutionLevel**: `asInvoker` |
//!   `requireAdministrator` | `highestAvailable` — the UAC
//!   privilege-elevation request.  Plus `uiAccess` (rare; requires
//!   special trust) and `autoElevate` (UAC-bypass tooling).
//! - **compatibility / supportedOS**: GUIDs naming the Windows
//!   versions the binary opted into. Tells you the minimum target OS.
//! - **windowsSettings**: dpiAware / dpiAwareness / longPathAware
//!   (GUI / shell behaviour).
//! - **dependencies**: side-by-side assembly references (e.g.
//!   "Common-Controls v6" enables modern visual styles).
//!
//! For supply-chain detection: vendors typically ship the same
//! manifest across releases. A version drift, requestedExecutionLevel
//! escalation, or a previously-absent autoElevate is a swap signal.
//!
//! Lookup strategy: scan the file for the literal `<assembly`
//! opening and matching `</assembly>` close, then parse with
//! roxmltree. This is more robust than walking the resource directory
//! tree (no dependence on goblin internals; works even when the
//! resource section is mildly malformed).

use roxmltree::{Document, Node};
use serde_json::{json, Map, Value};

const MAX_FILE_SCAN_HORIZON: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_SIZE: usize = 1 << 16;

/// Locate, parse, and structure a PE manifest into a JSON value
/// suitable for direct kv-tree insertion.  Returns `None` for non-PE
/// input, missing manifest, or unrecoverable XML errors.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    let xml = locate_manifest_xml(data)?;
    parse_manifest(xml)
}

/// Scan for the embedded manifest's XML byte range.  Manifests are
/// typically <2 KB and live in the .rsrc section — we cap the scan
/// at 16 MB and the manifest itself at 64 KB.
fn locate_manifest_xml(data: &[u8]) -> Option<&[u8]> {
    let horizon = data.len().min(MAX_FILE_SCAN_HORIZON);
    let haystack = &data[..horizon];

    // Anchor on `<assembly` — the canonical SxS manifest root.
    // Plain ASCII; PE manifests are always UTF-8 (no UTF-16 BOMs).
    let needle = b"<assembly";
    let start = memchr::memmem::find(haystack, needle)?;
    let end_needle = b"</assembly>";
    let end_rel = memchr::memmem::find(&haystack[start..], end_needle)?;
    let end = start + end_rel + end_needle.len();
    if end - start > MAX_MANIFEST_SIZE {
        return None;
    }
    Some(&haystack[start..end])
}

fn parse_manifest(xml: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(xml).ok()?;
    let doc = Document::parse(text).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "assembly" {
        return None;
    }

    let mut out = Map::new();

    // assemblyIdentity — top-level identity of the manifest itself.
    if let Some(ident) = find_child(&root, "assemblyIdentity") {
        let m = element_attrs_snake(&ident);
        if !m.is_empty() {
            out.insert("assembly_identity".into(), Value::Object(m));
        }
    }

    if let Some(desc) = find_child(&root, "description").and_then(|n| text_content(&n)) {
        if !desc.trim().is_empty() {
            out.insert("description".into(), json!(desc.trim().to_string()));
        }
    }

    // trustInfo > security > requestedPrivileges > requestedExecutionLevel
    if let Some(req_level) = root
        .descendants()
        .find(|n| n.has_tag_name("requestedExecutionLevel"))
    {
        if let Some(level) = req_level.attribute("level") {
            out.insert("requested_execution_level".into(), json!(level));
        }
        if let Some(ui_access) = req_level.attribute("uiAccess") {
            out.insert(
                "ui_access".into(),
                json!(parse_xml_bool(ui_access).unwrap_or(false)),
            );
        }
    }

    // compatibility > application > supportedOS
    let supported: Vec<Value> = root
        .descendants()
        .filter(|n| n.has_tag_name("supportedOS"))
        .filter_map(|n| n.attribute("Id"))
        .map(|guid| {
            let canonical = canonical_windows_version(guid);
            json!({"guid": guid, "name": canonical})
        })
        .collect();
    if !supported.is_empty() {
        out.insert("supported_os".into(), Value::Array(supported));
    }

    // windowsSettings nested children — dpiAware, dpiAwareness,
    // autoElevate, longPathAware, gdiScaling, etc.
    let mut window_settings = Map::new();
    if let Some(ws) = root
        .descendants()
        .find(|n| n.has_tag_name("windowsSettings"))
    {
        for child in ws.children().filter(Node::is_element) {
            if let Some(text) = text_content(&child) {
                let key = snake_case(child.tag_name().name());
                let value = parse_xml_bool(text.trim())
                    .map(Value::Bool)
                    .unwrap_or_else(|| json!(text.trim().to_string()));
                window_settings.insert(key, value);
            }
        }
    }
    if !window_settings.is_empty() {
        // Hoist autoElevate to the top level (high-value signal).
        if let Some(v) = window_settings.remove("auto_elevate") {
            out.insert("auto_elevate".into(), v);
        }
        if let Some(v) = window_settings.remove("dpi_aware") {
            out.insert("dpi_aware".into(), v);
        }
        if let Some(v) = window_settings.remove("dpi_awareness") {
            out.insert("dpi_awareness".into(), v);
        }
        if let Some(v) = window_settings.remove("long_path_aware") {
            out.insert("long_path_aware".into(), v);
        }
        if !window_settings.is_empty() {
            out.insert("windows_settings".into(), Value::Object(window_settings));
        }
    }

    // dependency > dependentAssembly > assemblyIdentity (one per dep).
    let deps: Vec<Value> = root
        .descendants()
        .filter(|n| n.has_tag_name("dependentAssembly"))
        .filter_map(|d| {
            d.descendants()
                .find(|n| n.has_tag_name("assemblyIdentity"))
                .map(|ai| Value::Object(element_attrs_snake(&ai)))
        })
        .filter(|v| v.as_object().is_some_and(|m| !m.is_empty()))
        .collect();
    if !deps.is_empty() {
        out.insert("dependencies".into(), Value::Array(deps));
    }

    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

/// Find a direct-child element by local name.
fn find_child<'a, 'd>(node: &'a Node<'a, 'd>, name: &str) -> Option<Node<'a, 'd>> {
    node.children().find(|n| n.has_tag_name(name))
}

/// Concatenate a node's text children, trimmed.
fn text_content(node: &Node<'_, '_>) -> Option<String> {
    let s: String = node.children().filter_map(|n| n.text()).collect();
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Extract a node's attributes into a snake_case-keyed JSON map.
fn element_attrs_snake(node: &Node<'_, '_>) -> Map<String, Value> {
    let mut m = Map::new();
    for attr in node.attributes() {
        m.insert(snake_case(attr.name()), json!(attr.value()));
    }
    m
}

fn parse_xml_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "True" | "TRUE" | "yes" | "1" => Some(true),
        "false" | "False" | "FALSE" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// Canonical Windows version names for the well-known supportedOS
/// GUIDs.  Microsoft assigns one GUID per OS major release.
fn canonical_windows_version(guid: &str) -> &'static str {
    let g = guid.trim_matches(|c| c == '{' || c == '}').to_lowercase();
    match g.as_str() {
        "e2011457-1546-43c5-a5fe-008deee3d3f0" => "vista",
        "35138b9a-5d96-4fbd-8e2d-a2440225f93a" => "win7",
        "4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38" => "win8",
        "1f676c76-80e1-4239-95bb-83d0f6d0da78" => "win8.1",
        "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a" => "win10",
        _ => "unknown",
    }
}

/// PascalCase / camelCase to snake_case. Same shape as the helper in
/// `binary_extractors`; kept private here so the manifest extractor
/// is self-contained.
fn snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_returns_none_for_no_manifest() {
        let buf = b"random bytes with no embedded manifest";
        assert!(extract(buf).is_none());
    }

    #[test]
    fn extract_full_manifest_round_trip() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="My.App" version="1.2.3.4" processorArchitecture="amd64"/>
  <description>Test application</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <autoElevate xmlns="http://schemas.microsoft.com/SMI/2017/WindowsSettings">true</autoElevate>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>"#;
        let mut buf = vec![0u8; 64];
        buf.extend_from_slice(manifest);
        buf.extend_from_slice(&[0u8; 16]);

        let v = extract(&buf).expect("manifest parsed");
        assert_eq!(v["assembly_identity"]["name"], "My.App");
        assert_eq!(v["assembly_identity"]["version"], "1.2.3.4");
        assert_eq!(v["assembly_identity"]["processor_architecture"], "amd64");
        assert_eq!(v["description"], "Test application");
        assert_eq!(v["requested_execution_level"], "requireAdministrator");
        assert_eq!(v["ui_access"], false);
        assert_eq!(v["dpi_aware"], true);
        assert_eq!(v["auto_elevate"], true);

        let supported = v["supported_os"].as_array().expect("array");
        assert_eq!(supported.len(), 2);
        assert_eq!(supported[0]["name"], "win10");
        assert_eq!(supported[1]["name"], "win8.1");

        let deps = v["dependencies"].as_array().expect("array");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0]["name"], "Microsoft.Windows.Common-Controls");
        assert_eq!(deps[0]["version"], "6.0.0.0");
    }

    #[test]
    fn extract_minimal_as_invoker() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#;
        let v = extract(manifest).expect("parsed");
        assert_eq!(v["requested_execution_level"], "asInvoker");
        assert!(v.get("auto_elevate").is_none());
    }

    #[test]
    fn canonical_windows_version_known_guids() {
        assert_eq!(
            canonical_windows_version("{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"),
            "win10"
        );
        assert_eq!(
            canonical_windows_version("e2011457-1546-43c5-a5fe-008deee3d3f0"),
            "vista"
        );
        assert_eq!(canonical_windows_version("not-a-known-guid"), "unknown");
    }
}
