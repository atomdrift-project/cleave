![cleave](media/logo.png)

AST-aware software decomposition engine for supply-chain security. Detects capabilities and behaviors across 20+ languages and six binary formats in a single pass — built for security engineers and ML classification pipelines alike.

![screenshot](media/screenshot.png)

## What It Analyzes

- **Binaries** (header parsing + optional disassembly via Rizin): Mach-O, ELF, PE, Java .class, Python .pyc, compiled AppleScript
- **Source code** (tree-sitter AST): Python, JavaScript, TypeScript, Go, Rust, C/C++, Java, C#, Swift, Objective-C, Ruby, PHP, Perl, Lua, Shell, PowerShell, Groovy, Scala, Zig, Elixir
- **Archives** (recursive unpacking): ZIP, TAR, 7z, RAR, plus JAR/WAR, deb, rpm, apk, gem, crate, whl, nupkg, phar, vsix, xpi, crx, ipa, epub
- **Documents & data**: RTF, LNK, PNG (steganography), PDF, plist, VBScript, Batch, package manifests, GitHub Actions workflows

## Quick Start

```bash
# macOS (Homebrew)
brew tap atomdrift/tap https://codeberg.org/atomdrift/homebrew-tap.git
brew install atomdrift/tap/cleave

# From source
make install
```

```bash
cleave suspect.bin
cleave /tmp/box-o-malware   # recursive, unpacks archives
```

Optionally install [rizin](https://github.com/rizinorg/rizin) for disassembly and [upx](https://github.com/upx/upx) for runtime unpacking.

## Under the Hood

**Tree-sitter** for language-aware AST traversal, **Rizin** for binary reverse engineering, **Goblin** for header parsing, **YARA-X** for signature matching, and **[stng](https://codeberg.org/atomdrift/stng)** for payload decoding (Base64, hex, AES, XOR key material).

## Detection Philosophy

cleave does not judge whether a program is malicious — it extracts what a program *can do*, producing structured output for classifiers like [litmus](https://codeberg.org/atomdrift/litmus). Detection rules ([traits](https://codeberg.org/atomdrift/cleave-traits)) align with the [MBC](https://github.com/MBCProject/mbc-markdown) hierarchy:

- **[micro-behaviors](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/micro-behaviors)**: atomic capabilities (`mmap`, `gethostbyname`)
- **[objectives](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/objectives)**: composite traits indicating behavior in service of a goal
- **[well-known](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/well-known)**: specific malware family signatures
- **[meta](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/meta)**: structural traits
- **[third-party](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/third-party)**: third-party YARA rules

## Related Tools

- [malcontent](https://github.com/chainguard-dev/malcontent) — our previous approach. cleave replaces it with ~2× accuracy through AST-aware analysis.
- [capa](https://github.com/mandiant/capa) — our original inspiration. cleave is faster, with 15× rule coverage and broader format support.

## License

Apache-2.0
