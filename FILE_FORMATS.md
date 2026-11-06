# Supported File Formats

cleave identifies files by magic bytes, extension, filename, and content heuristics, then dispatches to a format-specific analyzer. The tables below list everything currently recognized.

## Binaries and Machine Code

| Format | Extensions | Description |
|---|---|---|
| Mach-O | (none), `.dylib`, `.bundle`, `.macho` | macOS/iOS executable, library, or fat universal binary |
| ELF | (none), `.so`, `.ko`, `.elf` | Unix/Linux executable, shared library, or kernel module |
| PE | `.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, `.ocx`, `.drv`, `.efi`, `.pyd` | Windows executable, DLL, driver, or EFI image |
| NE | (none) | 16-bit Windows New Executable |
| DOS COM | `.com` | Headerless DOS executable |
| Static library | `.a`, `.lib` | `ar` archive of relocatable objects |
| Shellcode | (none) | Headerless x86/x86-64 position-independent code, recognized by its GetPC idiom |
| FAT boot sector | (none) | FAT12/16/32 volume boot record and its boot code |

## Bytecode

| Format | Extensions | Description |
|---|---|---|
| Java class | `.class` | Compiled Java bytecode |
| Python bytecode | `.pyc`, `.pyo` | CPython compiled bytecode |
| WebAssembly | `.wasm` | WebAssembly module (Go/TinyGo/Rust/Emscripten target) |
| DEX | `.dex` | Dalvik/ART executable bytecode |
| Erlang/Elixir BEAM | `.beam` | Compiled BEAM VM bytecode |
| Ren'Py script | `.rpyc`, `.rpymc` | Compiled Ren'Py script (pickled AST) |
| AppleScript | `.scpt`, `.applescript` | Compiled or source AppleScript |

## Source Code and Scripts

Parsed with tree-sitter where available; otherwise identified by extension, filename, or shebang.

| Language | Extensions |
|---|---|
| Python | `.py`, `.pyw`, `.pyi`, `.pth` |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.jse` |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` |
| Go | `.go` |
| Rust | `.rs` |
| C / C++ / Asm / Pascal | `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cxx`, `.hxx`, `.hh`, `.idl`, `.asm`, `.s`, `.nasm`, `.pas`, `.dpr` |
| Java | `.java` |
| Kotlin | `.kt`, `.kts` |
| C# | `.cs` |
| Swift | `.swift` |
| Objective-C | `.m`, `.mm` |
| Ruby | `.rb`, `.rbs`, `.gemspec` |
| PHP | `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.phtml` |
| Perl | `.pl`, `.pm`, `.t` |
| Lua | `.lua` |
| Shell | `.sh`, `.bash`, `.zsh`, `.ksh`, `.csh`, `.tcsh`, `.dash`, `.fish`, `.command`, `.ebuild`, `.eclass` |
| PowerShell | `.ps1`, `.psm1`, `.psd1` |
| Groovy / Gradle | `.groovy`, `.gradle` |
| Scala | `.scala`, `.sc` |
| Zig | `.zig` |
| Elixir | `.ex`, `.exs` |
| Clojure | `.clj`, `.cljs`, `.cljc`, `.cljr`, `.edn`, `.bb` |
| Batch | `.bat`, `.cmd` |
| VBScript / WSH | `.vbs`, `.vbe`, `.wsf`, `.wsc`, `.wsh` |
| JCL | `.jcl` |
| JSP | `.jsp`, `.jspx` |
| ASP / ASP.NET | `.asp`, `.aspx`, `.asa`, `.asax`, `.ascx`, `.ashx`, `.asmx` |
| ColdFusion | `.cfm`, `.cfc`, `.cfml` |
| mIRC / ircII | `.mrc`, `.ircii` |

## Archives and Packages

Extracted recursively. Path-traversal and decompression-bomb guards apply.

| Format | Extensions | Description |
|---|---|---|
| ZIP | `.zip`, `.cbz`, `.pyz`, `.appx`, `.appxbundle`, `.msix`, `.msixbundle`, `.epub` | Generic ZIP and ZIP-based containers |
| JAR / WAR / EAR | `.jar`, `.war`, `.ear` | Java archives |
| Android | `.apk`, `.aab`, `.aar`, `.apks`, `.xapk` | Android application packages and libraries |
| iOS | `.ipa` | iOS application archive |
| Browser extensions | `.crx`, `.xpi` | Chrome and Firefox extensions |
| VS Code extension | `.vsix` | VS Code / Open VSX extension |
| Python | `.whl`, `.egg`, `.tar.gz` (sdist) | Wheels, eggs, and source distributions |
| npm | `.tgz` | npm package tarball (`package/` layout) |
| RubyGems | `.gem` | Ruby gem |
| Rust | `.crate` | Rust crate |
| NuGet | `.nupkg` | .NET package |
| PHP | `.phar`, Composer `.zip` | PHP archives and Composer distributions |
| Go module | `.zip` | Go module distribution (`module@version/` layout) |
| conda | `.conda` | conda package |
| Other registries | `.tar.gz`, `.tar` | Hex, pub.dev, CRAN, CPAN, and Hackage source packages |
| TAR | `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst` | TAR with optional gzip/bzip2/xz/zstd compression |
| CPIO | `.cpio` | ASCII CPIO archive |
| 7-Zip | `.7z`, `.cb7` | 7-Zip archive |
| RAR | `.rar`, `.cbr` | RAR archive |
| Cabinet | `.cab`, `.msu` | Microsoft Cabinet archive |
| Windows Installer | `.msi`, `.msp`, `.mst`, `.msm` | Windows Installer package or patch, with embedded PE extraction |
| Compiled HTML Help | `.chm` | Microsoft CHM container |
| Electron | `.asar` | Electron application archive |
| Ren'Py | `.rpa` | Ren'Py archive |
| Debian | `.deb`, `.udeb` | Debian package |
| RPM | `.rpm`, `.srpm` | Red Hat package |
| Alpine | `.apk` | Alpine Linux package (told apart from Android by its content) |
| Arch Linux | `.pkg.tar`, `.pkg.tar.zst`, `.pkg.tar.xz`, `.pkg.tar.gz` | Arch Linux package |
| FreeBSD | `.pkg` | FreeBSD package (told apart from macOS by its content) |
| macOS installer | `.pkg` | macOS installer package (XAR) |
| Void Linux | `.xbps` | Void Linux package |
| Gentoo | `.gpkg.tar` | Gentoo binary package |
| Snap | `.snap` | Ubuntu Snap package (SquashFS) |
| Flatpak | `.flatpak` | Flatpak bundle (recognized; its contents are not unpacked yet) |
| OCI / Docker image | `.tar` | `docker save` or OCI image layout |
| Single-file compression | `.gz`, `.bz2`, `.xz`, `.lzma`, `.zst` | Standalone compressed files |

## Disk Images

| Format | Extensions | Description |
|---|---|---|
| ISO 9660 / UDF | `.iso` | Optical disc image |
| Apple Disk Image | `.dmg` | UDIF disk image |
| Virtual Hard Disk | `.vhd` | Fixed or sparse VHD |
| SquashFS | `.squashfs`, `.sqsh` | Read-only filesystem image |

## Documents

| Format | Extensions | Description |
|---|---|---|
| PDF | `.pdf` | Portable Document Format |
| RTF | `.rtf` | Rich Text Format, with embedded object scanning |
| Legacy Office (OLE2) | `.doc`, `.dot`, `.xls`, `.xlt`, `.xla`, `.ppt`, `.pps`, `.pot`, `.ppa`, `.msg` | Legacy Microsoft Office, with VBA macro extraction |
| Modern Office (OOXML) | `.docx`, `.docm`, `.dotx`, `.dotm`, `.xlsx`, `.xlsm`, `.xltx`, `.xltm`, `.xlam`, `.pptx`, `.pptm`, `.potx`, `.potm`, `.ppsx`, `.ppsm`, `.ppam`, `.sldx`, `.sldm` | Microsoft Office 2007+ |
| HTML | `.html`, `.htm`, `.hta` | HTML document and HTML Application |
| PostScript | `.ps`, `.eps`, `.epsf` | PostScript or EPS |
| TeX / LaTeX | `.tex`, `.sty`, `.ltx`, `.dtx` | TeX source |
| Windows shortcut | `.lnk` | Windows Shell Link |
| Plain text | `.txt`, `.text`, `.log`, `.csv`, `.tsv`, `.rst`, `.adoc`, `LICENSE`, `COPYING` | Fallback text handling |
| Opaque data | `.dat`, `.bin`, `.db`, `.payload`, `.raw`, `.ser`, `.map` | Likely-encoded payloads (XOR, base64, AES) and source maps |

Markdown (`.md`, `.markdown`, `.qmd`, `.rmd`) is analyzed when named directly but skipped in directory walks. OpenDocument (`.odt`, `.ods`, `.odp`, `.odg`, and their templates) is recognized but not analyzed yet.

## Manifests, Lockfiles, and Configuration

| Format | Filename / Extension | Description |
|---|---|---|
| npm | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Node.js manifest and lockfiles |
| node-gyp | `binding.gyp`, `.gyp`, `.gypi` | Build manifest whose command expansions run at install |
| Cargo | `Cargo.toml`, `Cargo.lock` | Rust manifest and lockfile |
| Python | `pyproject.toml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `PKG-INFO`, `METADATA` | Python manifests, lockfiles, and distribution metadata |
| Ruby | `Gemfile.lock` | Bundler lockfile |
| Composer | `composer.json`, `composer.lock` | PHP manifest and lockfile |
| Go | `go.mod`, `go.sum` | Go module manifest and checksums |
| Arch | `.SRCINFO` | Arch/AUR package metadata |
| Chrome extension | `manifest.json` | Chrome extension manifest (permission analysis) |
| VS Code extension | `extension.vsixmanifest` | VSIX manifest |
| GitHub Actions | `.github/workflows/*.yml`, `action.yml` | CI/CD workflow or action definition |
| systemd | `.service`, `.service.d/*.conf` | systemd service unit |
| XDG desktop entry | `.desktop` | freedesktop.org launcher or autostart entry |
| Windows registry | `.reg` | `regedit` export |
| Property list | `.plist`, `.resx` | macOS/iOS property list (binary, XML, or OpenStep) |
| Interface Builder nib | `.nib` | Compiled AppKit/UIKit object graph |
| JSON | `.json`, `.code-workspace` | Generic JSON |
| YAML | `.yaml`, `.yml` | Generic YAML |
| XML | `.xml`, `.xaml`, `.xsd`, `.xsl`, `.xslt`, `.wsdl`, `.config`, `.settings`, `.nuspec`, `.csproj`, `.vbproj`, `.fsproj`, `.vcxproj`, `.proj`, `.props`, `.targets`, `.xib`, `.storyboard` | Generic XML, MSBuild projects, and Interface Builder sources |
| YARA rules | `.yar`, `.yara` | YARA rule source |
| Registry metadata | `*.registry.json` | Package-registry account of a release |

## Build Files

| Format | Filename / Extension | Description |
|---|---|---|
| Makefile | `Makefile`, `GNUmakefile`, `.mk`, `.mak` | GNU Make build file |
| Dockerfile | `Dockerfile`, `Containerfile` | Container image build definition |
| CMake | `CMakeLists.txt`, `.cmake` | CMake build script |
| Xcode project | `project.pbxproj` | Xcode targets, build phases, and build scripts |

## Images, Media, and Fonts

| Format | Extensions |
|---|---|
| PNG | `.png` |
| JPEG | `.jpg`, `.jpeg`, `.jpe`, `.jfif` |
| GIF | `.gif` |
| BMP | `.bmp`, `.dib` |
| WebP | `.webp` |
| TIFF | `.tif`, `.tiff` |
| AVIF | `.avif`, `.avifs` |
| Icons and cursors | `.ico`, `.cur`, `.ani` |
| SVG | `.svg` (scanned as XML; can carry script) |
| WAV / AIFF / MP3 | `.wav`, `.wave`, `.aif`, `.aiff`, `.aifc`, `.mp3` |
| MP4 / QuickTime | `.mp4`, `.m4a`, `.m4v`, `.mov` |
| Fonts | `.ttf`, `.otf`, `.ttc`, `.otc`, `.woff`, `.woff2`, `.eot` |

## Serialized Data and Signatures

| Format | Extensions | Description |
|---|---|---|
| Python pickle | `.pkl`, `.pickle`, `.joblib` | Serialized Python objects, with deserialization-attack detection |
| .NET BinaryFormatter | (none) | MS-NRBF serialized stream |
| OpenPGP signature | `.sig`, `.asc`, `.sign` | Detached release signature |
| Certificate signature | (none) | Detached X.509 signature sidecar |
| Apple trust cache | `.im4p`, `.trustcache` | Image4 trust cache of code-directory hashes |
