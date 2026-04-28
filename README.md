<p align="center">
  <img src="media/logo.svg" alt="cleave" width="240">
</p>

cleave answers one question — *what can this program do?* It extracts capabilities from binaries, source, and archives, scoring each against **[50,000+ behavior rules](https://codeberg.org/atomdrift/cleave-traits)** aligned to [MBC](https://github.com/MBCProject/mbc-markdown) and [ATT&CK](https://attack.mitre.org/). Built for supply-chain and malware triage — useful standalone, and designed to be embedded in other open-source or commercial software via JSON. cleave is designed to be the kind of feature extractor you'd want to plug into an ML pipeline *wink wink*.

Apache-2.0, no telemetry.

![screenshot](media/screenshot.png)

## What It Analyzes

- **Binaries**: Mach-O, ELF, PE, Java `.class`, Python `.pyc`, compiled AppleScript
- **Source** (~20 languages via tree-sitter): Python, JS/TS, Go, Rust, C/C++, Java, C#, Swift, ObjC, Ruby, PHP, Perl, Lua, Shell, PowerShell, Groovy, Scala, Zig, Elixir
- **Archives** (recursive): zip, tar, 7z, rar, jar/war, deb, rpm, apk, gem, crate, whl, nupkg, phar, vsix, xpi, crx, ipa, epub
- **Documents & data**: RTF, LNK, PNG (steganography), PDF, plist, VBScript, Batch, package manifests, GitHub Actions workflows

## Quick Start

Install via make (requires rust):

```bash
make install
```

Install via Homebrew:

```bash
brew tap atomdrift/tap https://codeberg.org/atomdrift/homebrew-tap.git
brew install atomdrift/tap/cleave
```

Usage:

```bash
cleave suspect.bin                            # single sample
cleave /tmp/box-o-malware                     # recursive, unpacks archives
cleave --format jsonl --min-crit suspicious   # streaming triage feed
cleave diff old.tgz new.tgz                   # behavior delta across releases
```

Optional: [rizin](https://github.com/rizinorg/rizin) for disassembly, [upx](https://github.com/upx/upx) for runtime unpacking.

## Design

- **Capabilities, not verdicts.** Findings ranked from `baseline` to `hostile`. Downstream classifiers (e.g. [litmus](https://codeberg.org/atomdrift/litmus)) consume the JSONL directly.
- **No skips.** Every archive member is analyzed regardless of size or filename.
- **Layered unpacking.** UPX, embedded binaries, and base64/hex/AES/XOR payloads via [stng](https://codeberg.org/atomdrift/stng).
- **Deterministic output.** JSONL streaming, SHA256-keyed cache, same input → same output.
- **AST matching** via tree-sitter; YARA-X for signatures; [Goblin](https://github.com/m4b/goblin) for headers.

## Related

- [malcontent](https://github.com/chainguard-dev/malcontent) — cleave's predecessor; cleave significantly improves upon its accuracy with 3X the rule coverage, AST, and automated reverse-engineering.

- [capa](https://github.com/mandiant/capa) — original inspiration; cleave has 20× the rule coverage, broader format support, and is an order of magnitude faster. capa does integrate better with reverse engineering tools.

## License

Apache-2.0
