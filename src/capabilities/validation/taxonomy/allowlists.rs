//! Reviewed directory and scope allowlists kept in validator code.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Trait path prefixes where broad file type coverage is permitted.
///
/// These directories contain patterns (network indicators, encoding schemes, etc.)
/// that legitimately appear across compiled binaries, scripts, source code, and
/// documents — so requiring narrow file type targeting would silently drop coverage.
/// Directory subtrees permitted to exceed the per-type file-type cap, qualified
/// by matcher type: an entry `"<type>:<dir-prefix>"` lifts the cap only for
/// matchers of `<type>` whose source file is in that subtree of the rules root.
/// Entries without a trailing slash name one exact source file. A broad
/// `text` matcher in an allowlisted `text:` directory passes; the same directory
/// does **not** license a broad `value`/`symbol`/etc. matcher.
pub(crate) const BROAD_FILETYPE_ALLOWLIST: &[&str] = &[
    // Shared XOR AST productions are portable across the explicitly scoped
    // grammars. Lua exponentiation and other grammars are excluded; Swift has
    // its own production. One canonical predicate avoids per-language copies.
    "tree-sitter:micro-behaviors/data/bitwise/xor/expression/xor-split-parsed-xor.yaml",
    // Normalized call names describe the same XOR-named helper observation
    // across script/source frontends, without claiming a particular algorithm.
    "symbol:micro-behaviors/data/bitwise/xor/expression/xor-split-parsed-xor.yaml",
    // GIF byte-zero magic has the same meaning under a GIF, PHP/ASP, or
    // mistyped source identity. The canonical hex matcher must retain all
    // original header consumers without relying on extracted text offsets.
    "hex:metadata/file/magic/identity/gif.yaml",
    // Opening PHP tags are byte delimiters, including when a newline makes
    // the tag too short for a media string extractor. Only this reviewed
    // marker file may scan the original bytes across passive carriers.
    "raw:micro-behaviors/data/embedded/payload/media/php.yaml",
    // Preserve the same four carriers when the neutral find-next opcode
    // moves out of infection objectives. This exact source-file exception
    // does not broaden the remaining filesystem-search rules.
    "hex:micro-behaviors/fs/search/command/dos-find-next.yaml",
    // IP addresses and port numbers are embedded in binaries, scripts, manifests, docs
    "text:micro-behaviors/communications/ip/",
    // URLs and URL fragments appear in any file type
    "text:micro-behaviors/communications/url/",
    // C2 infrastructure indicators (IPs, domains, ports, tunnels) appear in any file
    "text:objectives/command-and-control/infrastructure/",
    // Filesystem path strings (/etc/passwd, ~/.aws/credentials, %APPDATA%\…) are
    // language-agnostic content — the same path literal appears in any source,
    // script, config, doc, or binary that references it.
    "text:micro-behaviors/fs/path/",
    // Ordered character alphabets can occur in source or compiled artifacts.
    "text:metadata/lang/natural/",
    "text:objectives/command-and-control/remote-command/llm/",
    "text:objectives/evasion/security-bypass/llm/",
    // Natural-language destructive tasking can be embedded in any source or
    // script language; objective composites require an unattended agent with
    // tool-permission bypass before assigning hostile intent.
    "text:well-known/tool/detection/",
    // Marking a file executable (chmod +x / mode 0o755) is a delivery step that
    // appears across every script, source language, and manifest that drops and
    // launches a payload — so the chmod-executable atoms scan broadly.
    "text:micro-behaviors/fs/chmod/executable/",
    // "Code generated … DO NOT EDIT" markers appear in generated code of every language.
    "text:metadata/lang/generated/generated.yaml",
    // Cryptographic vocabulary (ciphertext, shared secret, key-material labels)
    // appears in crypto implementations of every language.
    "text:micro-behaviors/crypto/",
];

/// Reviewed directory contracts where OS-independent evidence may declare
/// `platforms: [all]`. Permission is not an assertion that every rule in a
/// directory is portable: OS-specific observations still need explicit scopes.
/// Keep this list limited to taxonomy contracts currently used by the ruleset.
pub(crate) const ALL_PLATFORM_DIRECTORY_ALLOWLIST: &[&str] = &[
    // Description claims are metadata; OS-specific rules still need explicit scopes.
    "metadata/package/description/function",
    "metadata/package/documentation",
    // Publication/custody/history describe the registry record, not execution.
    "metadata/registry",
    // Security-held status does not depend on the OS consuming the package.
    "objectives/supply-chain/security-hold",
    // Host syntax and spelling do not depend on the OS consuming a URL.
    "micro-behaviors/communications/url/host",
];

/// Reviewed directory/platform-set contracts, not permission to use `all`.
/// Descendants inherit the contract; sibling paths and changed platform sets
/// return to review. Matcher and file-type validation still apply.
pub(super) const REVIEWED_BROAD_PLATFORM_SCOPES: &[(&str, &[Platform])] = &[
    // Browser HTTP callbacks and OAST content use browser APIs with the same
    // semantics on desktop and mobile. Keep their mobile coverage intact.
    (
        "objectives/exfiltration/oob",
        &[
            Platform::Unix,
            Platform::Windows,
            Platform::Android,
            Platform::Ios,
        ],
    ),
    // Degradation includes portable browser main-thread blocking.
    (
        "objectives/impact/degrade",
        &[
            Platform::Unix,
            Platform::Windows,
            Platform::Android,
            Platform::Ios,
        ],
    ),
    // Wireless configuration is supported on these desktop/mobile systems.
    (
        "micro-behaviors/hardware/wireless",
        &[
            Platform::Windows,
            Platform::Linux,
            Platform::MacOS,
            Platform::Android,
            Platform::Ios,
        ],
    ),
];
