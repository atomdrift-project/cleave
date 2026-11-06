//! Reviewed directory and scope allowlists. Each entry is to become an `exempt:` entry on the rules it covers.

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
/// matchers of `<type>` whose source file path contains `<dir-prefix>`. A broad
/// `text` matcher in an allowlisted `text:` directory passes; the same directory
/// does **not** license a broad `value`/`symbol`/etc. matcher.
pub(crate) const BROAD_FILETYPE_ALLOWLIST: &[&str] = &[
    // Plex API routes remain recognizable in source, binaries, and embedded data.
    "text:well-known/app/media/plex/timeline-subscribe.yaml",
    "text:well-known/app/media/plex/universal-transcode.yaml",
    // Graph endpoint references remain useful in source, scripts, and compiled carriers.
    "text:well-known/app/enterprise/microsoft-graph/graph-application-credential-add-path.yaml",
    "text:well-known/app/enterprise/microsoft-graph/graph-service-principal-credential-add-path.yaml",
    // Preserve the original cross-format coverage of these command-call text references.
    "text:micro-behaviors/os/handler/open/node-spawn-explorer-argument-text.yaml",
    "text:micro-behaviors/os/container/orchestration/system-call-kubectl-parenthesized-text.yaml",
    // A quoted word is contextual evidence across the original source and
    // binary carriers; the rule remains a component rather than an identity.
    "text:metadata/file/profile/text-shape/quoted-cuckoo-word-reference.yaml",
    // A literal password assignment can occur in any of the original source,
    // script, or compiled carriers; preserve its cross-format match scope.
    "text:micro-behaviors/os/security/auth/password/password-qwerty-config-text.yaml",
    // Ethereum RPC method names and JSON fields occur across source and binary
    // carriers; preserve the reviewed scope of these protocol observations.
    "text:micro-behaviors/communications/blockchain/ethereum/blockchain-rpc-review-ethereum.yaml",
    "literal:micro-behaviors/communications/blockchain/ethereum/blockchain-rpc-review-ethereum.yaml",
    // Plex's plugin route is a neutral text reference in every original carrier.
    "text:well-known/app/media/plex/network-function-route.yaml",
    // Raw GitHub URL references apply across source, script, and binary
    // carriers; retain the reviewed scope for this file's text matchers.
    "text:well-known/app/development/code-forge/github/raw.yaml",
    // This literal configuration value is evidence in source and binaries.
    "text:micro-behaviors/communications/socket/port/credential-keyword-review-traits.yaml",
    // These two neutral service-domain references retain the reviewed cross-format
    // scope of the original shared observation, including supported archives.
    "text:well-known/app/storage/filen/cloud-url-references.yaml",
    "text:well-known/app/storage/koofr/cloud-url-references.yaml",
    // An abbreviated command is documentation in every original carrier,
    // including embedded document text. Consolidation must retain that union.
    "text:metadata/package/documentation/source/review-identity-shell-examples.yaml",
    // Directory-shaped references occur across source, script, and binary
    // carriers. Preserve the scope of this single neutral path observation.
    "text:metadata/path/directory/storage-default-reference.yaml",
    // Scanner identifier and rule names are also quoted in security documentation.
    "text:metadata/lang/source/naming/security/query-review-scanner-types-detection-security-scanner-traits.yaml",
    // Shared XOR AST productions are portable across the explicitly scoped
    // grammars. Lua exponentiation and other grammars are excluded; Swift has
    // its own production. One canonical predicate avoids per-language copies.
    "tree-sitter:micro-behaviors/data/bitwise/xor/expression/xor-split-parsed-xor.yaml",
    // Normalized call names describe the same XOR-named helper observation
    // across script/source frontends, without claiming a particular algorithm.
    "symbol:micro-behaviors/data/bitwise/xor/expression/xor-split-parsed-xor.yaml",
    // Named-call references use the normalized call-symbol namespace across
    // script frontends. The printenv reference currently matches 13 script
    // types; narrowing it to seven would discard existing call facts. This
    // exact-file exception applies only to symbol matchers, and changes no
    // parsing, decoding, match predicates, or runtime behavior.
    "symbol:micro-behaviors/os/env/enumerate/enumeration-query.yaml",
    // A declared digest label and hexadecimal value has the same meaning in
    // bootstrap source and manifests. Preserve its existing scope when the
    // declaration moves from hash operations to integrity metadata.
    "text:metadata/package/integrity/digest-value.yaml",
    // The file's own directory components have the same meaning across
    // content formats. Preserve the original scope when this neutral path
    // observations move to naming metadata; their matchers scan no body.
    "path:metadata/path/directory/directory-components.yaml",
    "path:metadata/path/software/directory-components.yaml",
    // Browser SQL schemas are shared by source and compiled carriers. These
    // bounded query matchers require specific columns and tables in any format.
    "text:micro-behaviors/data/db/access/chromium-queries.yaml",
    // The same carrier-independent SQL predicates, relocated to the read operation.
    "text:micro-behaviors/data/db/read/column/migration-read-review-access-chromium-queries.yaml",
    // Referenced application/product names can occur in source, binaries,
    // manifests and embedded markup. Preserve that coverage when name markers
    // move out of artifact/library or objective-keyword categories. This only
    // affects text matcher scope, never the combined per-directory rule cap.
    "text:micro-behaviors/os/application/target/",
    // `media.*` is one fact namespace shared by every passive container that
    // can carry a payload — font, png, jpeg, wav, aiff, mp3, mp4, ico, gif,
    // bmp, webp. The namespace exists precisely so a carrier rule is written
    // once instead of eleven times, and the value paths it reads are emitted
    // only for those types, so breadth here is the design rather than a
    // missing filter. Splitting the rules per format to satisfy the cap would
    // duplicate the same matcher eleven times, which the near-duplicate check
    // rejects anyway.
    "value:metadata/file/format/media/",
    // Parsed embedded-PHP call relationships are shared across the same
    // passive carriers. Replacing the former text scan with these values
    // must not discard audio/font carriers or duplicate rules per format.
    // Keep this exception on the reviewed file and value matcher only.
    "value:micro-behaviors/data/embedded/payload/media/php-command-input.yaml",
    // GIF byte-zero magic has the same meaning under a GIF, PHP/ASP, or
    // mistyped source identity. The canonical hex matcher must retain all
    // original header consumers without relying on extracted text offsets.
    "hex:metadata/file/magic/identity/gif.yaml",
    // Opening PHP tags are byte delimiters, including when a newline makes
    // the tag too short for a media string extractor. Only this reviewed
    // marker file may scan the original bytes across passive carriers.
    "raw:micro-behaviors/data/embedded/payload/media/php.yaml",
    // DOS INT 21h service sequences are the same 16-bit code wherever the
    // infector body sits: a .COM, an untyped dump (`data`), a `.a`-named copy
    // (`static-lib`), or a batch/COM polyglot. Per-type twins of one hex
    // pattern are what the scope-twin check rejects, so the cap yields here.
    "hex:objectives/impact/infect/binary/dos/interrupt/",
    // Preserve the same four carriers when the neutral find-next opcode
    // moves out of infection objectives. This exact source-file exception
    // does not broaden the remaining filesystem-search rules.
    "hex:micro-behaviors/fs/search/command/dos-find-next.yaml",
    // IP addresses and port numbers are embedded in binaries, scripts, manifests, docs
    "text:micro-behaviors/communications/ip/",
    // URLs and URL fragments appear in any file type
    "text:micro-behaviors/communications/url/",
    // IDN homograph / non-ASCII URL checks are deliberately host-format-agnostic:
    // a spoofed source URL can hide in a PKGBUILD, package manifest, source file,
    // config, or document, so narrowing `for:` would silently drop coverage.
    "text:objectives/supply-chain/impersonation/homograph/",
    // C2 infrastructure indicators (IPs, domains, ports, tunnels) appear in any file
    "text:objectives/command-and-control/infrastructure/",
    // HTTP header names and values appear in binaries, scripts, and documents
    "text:micro-behaviors/communications/http/header/",
    // Credential access patterns (passwords, tokens, keys, wallets) appear in any file
    "text:objectives/credential-access/",
    // Filesystem path strings (/etc/passwd, ~/.aws/credentials, %APPDATA%\…) are
    // language-agnostic content — the same path literal appears in any source,
    // script, config, doc, or binary that references it.
    "text:micro-behaviors/fs/path/",
    // IP discovery service hostnames are embedded in any executable (scripts, binaries, config)
    "text:micro-behaviors/communications/http/ip-discovery/",
    // Service API hostnames (api.telegram.org, slack.com, …) are host-string
    // literals that appear in any language that talks to the service — script,
    // compiled binary, or source. Narrowing `for:` would silently drop coverage.
    "text:micro-behaviors/communications/http/services/",
    // Recursive configuration values retain their meaning across source and binary carriers.
    // Preserve the former service-leaf scope after moving this generic option to its subject.
    "text:micro-behaviors/data/config/syntax/recursive-option.yaml",
    // IMDS credential-header constants are independent of the source/binary carrier.
    "text:micro-behaviors/communications/http/token-auth/aws-imds-headers.yaml",
    // The decoded form of the same dropper one-liner. These match the *decoded*
    // string corpus, so the host language is whatever happened to carry the
    // blob: the identical payload has been observed in a Gradle Kotlin task, an
    // Xcode build setting, a Makefile recipe, `build.rs`, and `setup.py`. The
    // encoding is what travels between build systems, so narrowing `for:` here
    // drops whole ecosystems rather than trimming a matcher — the file type is
    // not a property of the technique.
    "encoded:micro-behaviors/communications/http/download/encoded/",
    // Stacked-encoding rules match on the recovered *chain* (`base64+base64`),
    // which is a property of the wrapping and not of the file that carries it.
    // The same doubly-wrapped payload turns up in a git hook, a Makefile recipe
    // and an Xcode build setting, so a narrow `for:` here would scope a rule by
    // the one thing the technique is indifferent to.
    "encoded:micro-behaviors/data/decode/multiple-encoding/",
    // Hardcoded C2 URL string literals (IP-pinned URLs, .php panel endpoints)
    // appear in any source language — same rationale as communications/url/.
    // The directory's -encoded and -binary legs are already narrowly scoped.
    "text:micro-behaviors/communications/http/url/",
    // Cross-language file text/format properties (license headers, text
    // profiles, catalog strings, generic string identities) appear broadly.
    "text:metadata/file/catalog/",
    "text:metadata/file/format/",
    // Ordered character alphabets can occur in source or compiled artifacts.
    "text:metadata/lang/encoding/shape/alphabet/review-literal-charset.yaml",
    "text:metadata/lang/natural/",
    "text:metadata/lang/locale/",
    "text:metadata/file/extension/",
    "text:micro-behaviors/data/format/media/",
    "text:micro-behaviors/data/runtime/keywords/",
    "text:micro-behaviors/communications/http/keywords/",
    "text:micro-behaviors/data/parse/vocabulary/",
    "text:micro-behaviors/ui/window/notify/keywords-terms.yaml",
    "text:objectives/command-and-control/backdoor/keywords/",
    "text:objectives/command-and-control/botnet/keywords/",
    "text:objectives/command-and-control/backdoor/rat/keywords/",
    "text:objectives/command-and-control/remote-command/keywords/",
    "text:objectives/command-and-control/remote-command/llm/",
    "text:objectives/evasion/kernel-hide/keywords/",
    "text:objectives/evasion/indicator-removal/keywords/",
    "text:objectives/evasion/security-bypass/edr/",
    "text:objectives/evasion/security-bypass/llm/",
    "text:objectives/impact/destroy/keywords/",
    // Natural-language destructive tasking can be embedded in any source or
    // script language; objective composites require an unattended agent with
    // tool-permission bypass before assigning hostile intent.
    "text:objectives/impact/destroy/agent-directed/",
    "text:objectives/impact/dos/keywords/",
    "text:objectives/impact/ransom/keywords/",
    "text:objectives/privilege-escalation/exploit/keywords/",
    "text:micro-behaviors/hardware/input/keyboard/label/",
    "text:well-known/tool/detection/",
    // The rickroll delimiter moved here when `trojan/family` was split up: a
    // joke token used as a field separator is a packer property, not a family.
    "text:objectives/anti-static/obfuscation/string/delimiter/",
    "text:well-known/tool/offensive/payload-corpus/",
    // Marking a file executable (chmod +x / mode 0o755) is a delivery step that
    // appears across every script, source language, and manifest that drops and
    // launches a payload — so the chmod-executable atoms scan broadly.
    "text:micro-behaviors/fs/chmod/executable/",
    // "Code generated … DO NOT EDIT" markers appear in generated code of every language.
    "text:metadata/lang/generated/generated.yaml",
    // The Racket language classifier matches `#lang racket` to identify the
    // language of otherwise-unknown files, so it must scan broadly.
    "text:metadata/lang/scripted/racket.yaml",
    // Cryptographic vocabulary (ciphertext, shared secret, key-material labels)
    // appears in crypto implementations of every language.
    "text:micro-behaviors/crypto/",
    // C2 messaging-channel indicators (e.g. Discord webhook URLs) are string
    // markers embedded in malware written in any language.
    "text:objectives/command-and-control/channel/messaging/",
    // String *literals* (parser-extracted) for the same cross-language content
    // classes allowlisted for `text:` above: a hardcoded C2 IP/port, URL,
    // credential path, or text marker is written as a quoted literal in source
    // of every language. Same cross-language rationale, different matcher type.
    "literal:micro-behaviors/communications/ip/",
    // Preserve the reviewed cross-carrier scope of this PHP upload URL literal.
    "literal:micro-behaviors/communications/url/http-path/resource/php-upload-url-reference.yaml",
    "literal:micro-behaviors/communications/http/url/",
    "literal:objectives/command-and-control/infrastructure/",
    "literal:metadata/file/catalog/",
    "literal:metadata/file/extension/",
    "literal:metadata/file/format/",
    "literal:objectives/impact/destroy/keywords/",
    "literal:objectives/command-and-control/remote-command/llm/",
    // Archive-member structural matchers (a vim-swap file, go.mod, .go source,
    // or Package.swift shipped inside a package) legitimately span the whole
    // archive family — the same member can appear in an npm tarball, gem, whl,
    // crate, etc. — so these value paths scan broadly.
    "value:metadata/package/files/",
    // README-name-vs-package-name mismatch is checked against the README of
    // every ecosystem's package archive, so the structural readme value paths
    // span the archive family.
    "value:objectives/supply-chain/impersonation/readme-clone/",
    // Test/fixture/example directory layouts (`/tests/`, `/winetests/`,
    // `__fixtures__/`) are detected inside package archives of every ecosystem,
    // so these path matchers legitimately span the archive family.
    "path:metadata/package/testing/presence/harness/",
    "path:metadata/package/testing/presence/path/",
    "path:metadata/package/testing/presence/suite/paths.yaml",
    // Whole-file size / "is-binary" filters carry a match-anything path pattern
    // and apply to the entire native+bytecode binary family (elf/macho/pe/
    // class/pyc) and beyond.
    "path:metadata/binary/",
    // Well-known app/library identification by file path (release-archive names,
    // source-tree directories, executable names) is inherently multi-format —
    // an app ships as an exe, a tarball, a zip, and source at once.
    "path:well-known/",
    // Package-registry record facts read the normalized `registry.*` value tree
    // and metrics that fletch materializes from an upstream listing. That record
    // is package-level context, not a property of any one member file, so the
    // matchers run regardless of which file type carries the package.
    "value:metadata/registry/",
    "metrics:metadata/registry/",
];

/// Reviewed directory contracts where OS-independent evidence may declare
/// `platforms: [all]`. Permission is not an assertion that every rule in a
/// directory is portable: OS-specific observations still need explicit scopes.
/// Keep this list synchronized with TAXONOMY.md's platform scope contracts.
pub(crate) const ALL_PLATFORM_DIRECTORY_ALLOWLIST: &[&str] = &[
    // Package text/resource facts retain their meaning on every target OS.
    "metadata/package/description/disclosure",
    // Description claims are metadata; OS-specific rules still need explicit scopes.
    "metadata/package/description/function",
    "metadata/package/documentation/claims",
    "metadata/package/documentation/security-advisory",
    "metadata/package/documentation/source",
    // Scanned filenames and naming measurements are OS-independent properties.
    // OS-specific filename rules still require their own explicit platform scope.
    "metadata/filename",
    "metadata/path",
    // Transparent test-indication profiles defer all target-OS and file-type
    // filtering to their referenced metadata/name observations. The OR itself
    // means the same on every OS; it asserts neither purpose nor portability.
    "metadata/file/profile/test-indications",
    // Source-indication reference profiles retain each named child's OS/type
    // gate. Their OR asserts no execution, benign intent or portability.
    "metadata/file/profile/source-indications",
    // Publication/custody/history describe the registry record, not execution.
    "metadata/registry",
    // Security-held status does not depend on the OS consuming the package.
    "objectives/supply-chain/security-hold",
    // Host syntax and spelling do not depend on the OS consuming a URL.
    "micro-behaviors/communications/url/host",
];

/// Reviewed enumerated scopes, not permission to use `all`. Match the exact
/// atom and platform set; changed scopes return to review. In particular neither
/// wireless configuration nor Swift Foundation is supported on z/OS by these
/// observations. Source-language and matcher changes still receive their normal
/// file-type, duplicate, and condition validation.
pub(super) const REVIEWED_BROAD_PLATFORM_SCOPES: &[(&str, &[Platform])] = &[
    (
        "micro-behaviors/fs/read/file/content/unspecified::swift-direct-file-read-api",
        &[
            Platform::Ios,
            Platform::MacOS,
            Platform::Linux,
            Platform::Windows,
        ],
    ),
    (
        "micro-behaviors/fs/read/file/content/unspecified::swift-data-file-read",
        &[
            Platform::Ios,
            Platform::MacOS,
            Platform::Linux,
            Platform::Windows,
        ],
    ),
    (
        "micro-behaviors/hardware/wireless/network::wifi-ssid-identifier",
        &[
            Platform::Windows,
            Platform::Linux,
            Platform::MacOS,
            Platform::Android,
            Platform::Ios,
        ],
    ),
    (
        "micro-behaviors/hardware/wireless/network::wifi-password-key",
        &[
            Platform::Windows,
            Platform::Linux,
            Platform::MacOS,
            Platform::Android,
            Platform::Ios,
        ],
    ),
];
