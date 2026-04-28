# Supported File Formats

cleave identifies files by magic bytes, extension, filename, and content heuristics, then dispatches to a format-specific analyzer. The table below lists everything currently recognized.

## Binaries

| Format | Extensions | Description |
|---|---|---|
| Mach-O | (none), `.dylib`, `.bundle` | macOS/iOS executable, library, or fat universal binary |
| ELF | (none), `.so`, `.o` | Unix/Linux executable or shared library |
| PE | `.exe`, `.dll`, `.sys`, `.scr` | Windows executable, DLL, or driver |
| MSI | `.msi`, `.msp` | Windows Installer (with embedded PE extraction) |
| Java class | `.class` | Compiled Java bytecode |
| Python bytecode | `.pyc` | CPython compiled bytecode |
| Python pickle | `.pkl`, `.pickle`, `.joblib`, `.pt`, `.pth` | Serialized Python object |
| AppleScript (compiled) | `.scpt`, `.applescript` | Compiled AppleScript binary |

## Source Code

Parsed with tree-sitter where available; otherwise extension or shebang.

| Language | Extensions |
|---|---|
| Python | `.py` |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` |
| Go | `.go` |
| Rust | `.rs` |
| C / C++ / Asm | `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cxx`, `.hxx`, `.hh`, `.asm`, `.s`, `.nasm` |
| Java | `.java` |
| Kotlin | `.kt`, `.kts` |
| C# | `.cs` |
| Swift | `.swift` |
| Objective-C | `.m`, `.mm` |
| Ruby | `.rb`, `.rbs` |
| PHP | `.php` |
| Perl | `.pl`, `.pm`, `.t` |
| Lua | `.lua` |
| Shell | `.sh`, `.bash`, `.ksh`, `.zsh`, `.csh`, `.tcsh`, `.dash` |
| PowerShell | `.ps1`, `.psm1`, `.psd1` |
| Groovy / Gradle | `.groovy`, `.gradle` |
| Scala | `.scala`, `.sc` |
| Zig | `.zig` |
| Elixir | `.ex`, `.exs` |
| Batch | `.bat`, `.cmd` |
| VBScript | `.vbs`, `.vbe`, `.wsf`, `.wsc` |
| Makefile | `Makefile`, `GNUmakefile`, `.mk`, `.mak` |

## Archives

Extracted recursively. Path-traversal and zip-bomb guards apply.

| Format | Extensions | Description |
|---|---|---|
| ZIP | `.zip` | Generic ZIP archive |
| JAR / WAR / EAR | `.jar`, `.war`, `.ear` | Java archives |
| Android / iOS / Chrome / Firefox / VSCode / EPUB | `.apk`, `.ipa`, `.crx`, `.xpi`, `.vsix`, `.epub` | ZIP-based application packages |
| Python wheel / egg | `.whl`, `.egg` | Python distribution archives |
| .NET / PHP | `.nupkg`, `.phar` | NuGet / PHP archives |
| Android library | `.aar` | Android archive |
| TAR | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst` | TAR with optional gzip/bzip2/xz/zstd compression |
| Ruby / Rust | `.gem`, `.crate` | Ruby gem / Rust crate (TAR-based) |
| 7-Zip | `.7z` | 7-Zip archive |
| RAR | `.rar` | RAR archive |
| Debian | `.deb` | Debian package (`ar`-based) |
| RPM | `.rpm` | Red Hat package |
| macOS package | `.pkg` | macOS installer (XAR-based) |
| Cabinet | `.cab` | Microsoft Cabinet archive |
| Single-file compression | `.gz`, `.bz2`, `.xz`, `.zst` | Standalone compressed files |
| Void Linux / Arch | `.xbps`, `.pkg.tar.zst` | Distro packages (TAR + zstd) |

## Documents

| Format | Extensions | Description |
|---|---|---|
| PDF | `.pdf` | Portable Document Format |
| RTF | `.rtf` | Rich Text Format (with embedded object scanning) |
| Legacy Office (OLE2) | `.doc`, `.xls`, `.ppt`, `.msg`, `.dot` | Legacy Microsoft Office; VBA macro extraction |
| Modern Office (OOXML) | `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm`, `.dotx`, `.dotm`, `.xltx`, `.xltm` | Modern Microsoft Office (2007+) |
| OpenDocument | `.odt`, `.ods`, `.odp`, `.odg`, `.odf`, `.ott`, `.ots`, `.otp` | LibreOffice / OpenOffice |
| Windows shortcut | `.lnk` | Windows Shell Link |
| Property list | `.plist` | macOS/iOS preferences (binary or XML) |
| HTML | `.html`, `.htm` | HTML document |
| Markdown | `.md`, `.markdown` | Markdown document |
| XML | `.xml`, `.xaml`, `.svg`, `.config`, `.csproj`, `.vbproj`, `.fsproj`, `.vcxproj`, `.props`, `.targets`, `.settings` | Generic XML, MSBuild project files, SVG |
| Plain text | `.txt`, `LICENSE`, `COPYING` | Fallback text handling |
| Opaque binary | `.dat`, `.bin`, `.payload`, `.raw`, `.b64`, `.base64` | Likely-encoded payloads (XOR, base64, AES) |

## Manifests & Configuration

| Format | Filename / Extension | Description |
|---|---|---|
| npm | `package.json` | Node.js package manifest (supply-chain analysis) |
| Cargo | `Cargo.toml` | Rust package manifest |
| Python | `pyproject.toml`, `PKG-INFO`, `METADATA` | Python distribution metadata |
| Composer | `composer.json` | PHP Composer manifest |
| Chrome extension | `manifest.json` | Chrome extension manifest (permission analysis) |
| VSCode extension | `extension.vsixmanifest` | VSIX manifest |
| GitHub Actions | `.github/workflows/*.yml`, `action.yml` | CI/CD workflow or action definition |
| systemd | `.service`, `.service.d/*.conf` | systemd service unit |
| XDG desktop entry | `.desktop` | freedesktop.org launcher / autostart entry |

## Images

| Format | Extensions | Description |
|---|---|---|
| PNG | `.png` | PNG image (IDAT steganography analysis) |
| JPEG | `.jpg`, `.jpeg` | JPEG image (EXIF and metadata extraction) |
