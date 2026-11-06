<p align="center"><img src="media/logo.svg" alt="" width="96"></p>

# cleave

[![Latest release](https://img.shields.io/github/v/release/atomdrift-project/cleave)](https://github.com/atomdrift-project/cleave/releases/latest)
[![License](https://img.shields.io/github/license/atomdrift-project/cleave)](LICENSE)

cleave is a static analysis engine that reveals what a programs capabilities are.

Using a database of [165,000+ heuristic rules](https://github.com/atomdrift-project/traits)), cleave rapidly (<250ms) determines
all of the operations a program is capable of, and highlights the security sensitive
operations. cleave was specifically designed for malware and differential supply-chain analysis, so
all inputs are assumed to be hostile.

There are three primary output modes, annotate, index, and JSON (for automation):

<p align="center">
  <img src="media/annotate.png" alt="cleave annotate a sample" width="760">
  <img src="media/toc.png" alt="cleave analyzing a sample (toc)" width="760">
</p>

## Install

To jam cleave into any macOS, Linux, FreeBSD, or whatever box:

```bash
curl -fsSL https://install.atomdrift.org/cleave.sh | sh
```

If you want to homebrew it yourself:

```bash
brew install atomdrift-project/tap/cleave
```

To build via source (Rust 1.97 required):

```bash
git clone https://github.com/atomdrift-project/cleave.git
cd cleave
make install
```

## What it analyzes

Representative coverage includes:

| Category | Examples |
| --- | --- |
| **Binaries and bytecode** | Mach-O, ELF, PE, NE, DOS COM, static libraries, shellcode, WebAssembly, Android DEX, Java `.class`, Python `.pyc`, BEAM, Ren'Py `.rpyc` |
| **Source and scripts** | Python, JavaScript, TypeScript, Go, Rust, C/C++, Java, Kotlin, C#, Swift, Objective-C, Ruby, PHP, Perl, Lua, Shell, PowerShell, Batch, VBScript, Scala, Groovy, Zig, Elixir, Clojure, JSP, ASP, ColdFusion, AppleScript |
| **Archives and packages** | ZIP, TAR, CPIO, 7-Zip, RAR, CAB, MSI, CHM, ASAR, JAR, APK, IPA, CRX, XPI, VSIX, npm, wheel, sdist, egg, conda, gem, crate, NuGet, Composer, Go modules, deb, rpm, Alpine, Arch, FreeBSD, Void, Gentoo, Snap, macOS `.pkg`, OCI images |
| **Disk images** | ISO 9660/UDF, DMG, VHD, SquashFS |
| **Documents and data** | PDF, RTF, Office/OLE2, OOXML, HTML/HTA, PostScript, TeX, LNK, plist, nib, XML, JSON, YAML, `.reg`, pickle, .NET BinaryFormatter |
| **Images, media, and fonts** | PNG, JPEG, GIF, BMP, WebP, TIFF, AVIF, ICO/CUR/ANI, SVG, WAV, AIFF, MP3, MP4, TrueType/OpenType/WOFF |
| **Build and deployment files** | package manifests and lockfiles, node-gyp, GitHub Actions, Dockerfile, Makefile, CMake, Xcode projects, systemd units, XDG desktop files |
| **Signatures** | OpenPGP detached signatures, X.509 signature sidecars, Apple trust caches |

See [FILE_FORMATS.md](FILE_FORMATS.md) for the maintained coverage reference.

## License

cleave is available under the [Apache License 2.0](LICENSE).
