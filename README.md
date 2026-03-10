![cleave](media/logo.png)

AST-aware software decomposition. Takes binaries and source apart into their atomic components.

cleave combines abstract syntax tree inspection with automated binary reverse engineering to detect capabilities and behaviors across 20+ languages and three binary formats (ELF, PE, machO) in a single pass.

![screenshot](media/screenshot.png)

## Why Cleave?

Because you might want to analyze files in a multitude of formats:

- **Binaries**: Mach-O, ELF, PE
- **Source**: Shell, Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, C, PHP, Lua, Perl, PowerShell, C#, Swift, Objective-C, Groovy, Scala, Zig, Elixir
- **Packages**: npm, Chrome extensions, VSCode extensions
- **Archives**: ZIP, TAR, 7z, RAR, XAR (unpacked recursively)
- **Bytecode**: Java .class files and JAR constant pool analysis

Cleave is designed to output data to be consumed by ML pipelines.

## Requirements

- A modern version of [Rust](https://rust-lang.org/)
- OPTIONAL, but highly recommended: [rizin](https://github.com/rizinorg/rizin) for binary reverse-engineering
- OPTIONAL: [upx](https://github.com/upx/upx) for on-the-fly unpacking

## Quick Start

```bash
cargo install --path .

# Analyze target
cleave binary-or-source.py

# Analyze directory recursively (including archives)
cleave /tmp/box-o-malware
```

## Under the Hood

- **Tree-sitter** for language-aware AST traversal
- **Radare2/Rizin** for deep binary reverse engineering (functions, control flow, syscalls, sections)
- **Goblin** for binary header parsing (Mach-O, ELF, PE)
- **YARA-X** for signature matching
- **Payload decoding**: Base64, hex, AES, XOR key material - through [stng](https://codeberg.org/atomdrift/stng)

## Detection Philosophy

cleave does not attempt to assess the hostility or suspicion level of an entire program; it's instead designed to be an input to such programs, like our own [litmus](https://codeberg.org/atomdrift/litmus). cleave's detection rules ([traits](https://codeberg.org/atomdrift/cleave-traits)) roughly align with the [MBC (Malware Behavior Catalog)](https://github.com/MBCProject/mbc-markdown) hierarchy:

- **[micro-behaviors](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/micro-behaviors)**: neutral capabilities, such as `mmap` or `gethostbyname`
- **[objectives](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/objectives)**: composite traits that may the sign of a malicious behavior in service of an objective
- **[well-known](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/well-known)**: specific well-known malware family detection - not a priority, but nice to have
- **[meta](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/meta)**: structural traits
- **[third-party](https://codeberg.org/atomdrift/cleave-traits/src/branch/main/third-party)**: third-party YARA rules

## Related Tools

- [malcontent](https://github.com/chainguard-dev/malcontent) was our previous attempt at addressing this problem. cleave replaces malcontent, with roughly 2X more accuracy and coverage through AST and smart reverse-engineering abilities.
- [capa](https://github.com/mandiant/capa) was our original inspiration. cleave is significantly faster, with 15× rule coverage and much broader file format support (machO, Python, Shell, and more).

## License

Apache-2.0
