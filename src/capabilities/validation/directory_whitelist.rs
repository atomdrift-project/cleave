// Directory whitelist validation
//
// Validates that only known subdirectories exist in top-level taxonomy tiers.
// This prevents taxonomy drift and ensures consistency with TAXONOMY.md.

use std::path::Path;

/// Allowed top-level subdirectories in objectives/
///
/// These correspond to MBC objectives and cleave-specific extensions.
/// Update this list when adding new objectives to TAXONOMY.md.
const ALLOWED_OBJECTIVES: &[&str] = &[
    "anti-analysis",        // MBC: Anti-Behavioral Analysis
    "anti-static",          // MBC: Anti-Static Analysis
    "evasion",              // MBC: Defense Evasion (extended)
    "command-and-control",  // MBC: Command and Control
    "collection",           // MBC: Collection
    "credential-access",    // MBC: Credential Access
    "discovery",            // MBC: Discovery
    "execution",            // MBC: Execution
    "exfiltration",         // MBC: Exfiltration
    "impact",               // MBC: Impact
    "lateral-movement",     // MBC: Lateral Movement
    "persistence",          // MBC: Persistence
    "privilege-escalation", // MBC: Privilege Escalation
    "supply-chain",         // MBC: Supply Chain (package ecosystem attacks)
];

/// Allowed subdirectories in objectives/anti-static/
///
/// These represent behaviors that hinder static analysis (disassembly, decompilation,
/// string extraction). Organized by technique, not by file type — a string encryption
/// rule works the same whether the target is a Python script or a PE binary.
///
/// Update this list AND TAXONOMY.md when adding new anti-static categories.
const ALLOWED_ANTI_STATIC: &[&str] = &[
    "obfuscation", // E1027 + B0032 Obfuscated Files/Code
    "pack",        // F0001 Software Packing
    "polyglot",    // Polyglot file format abuse
];

/// Allowed subdirectories in objectives/privilege-escalation/
///
/// These represent privilege escalation behaviors — obtaining higher permissions.
///
/// Update this list AND TAXONOMY.md when adding new privilege-escalation categories.
const ALLOWED_PRIVILEGE_ESCALATION: &[&str] = &[
    "elevation-control",     // Abuse elevation control (T1548)
    "exploit",               // Local exploitation (T1068)
    "hijack-execution-flow", // Execution flow hijacking (F0015)
    "install-certificate",   // Root cert installation (F0016)
    "kernel-modules",        // Kernel modules & extensions (F0010)
    "modify-service",        // Modify existing service (F0011)
    "process-injection",     // Injection into privileged procs (E1055)
    "token-manipulation",    // Token/privilege manipulation (T1134)
];

/// Allowed subdirectories in objectives/evasion/
///
/// Defense evasion — hiding from users, admins, and security products in production.
/// "Enable malware to evade detection." (OB0006)
///
/// NOT evasion (common misplacements):
/// - Fooling sandboxes/debuggers → anti-analysis/
/// - Defeating disassembly/decompilation → anti-static/
/// - Killing AV processes → impact/degrade/edr/ (aggression, not stealth)
const ALLOWED_EVASION: &[&str] = &[
    "anti-av",               // AV/EDR bypass (stealth, not termination)   F0004
    "decoy",                 // Deceptive content (documents, fake errors, cloaking)
    "file-hiding",           // Hidden files/directories                   E1564, F0005
    "file-unlock",           // Force-close file locks                     T1562
    "fileless",              // Avoid disk artifacts (memory-only staging)
    "hijack-execution-flow", // Execution flow hijacking                   F0015
    "hosts-file",            // Hosts file manipulation                    F0004
    "indicator-removal",     // Remove evidence of activity                T1070
    "kernel-hide",           // Kernel-level hiding (rootkit)              E1014
    "masquerade",            // File/process masquerading                  T1036
    "process",               // Process-level evasion (injection, hiding)  E1055
    "quarantine-removal",    // macOS Gatekeeper bypass                    B0047
    "security-bypass",       // Security restriction bypass
    "self-delete",           // Self-deletion after execution              F0007
    "tcc-manipulation",      // macOS TCC database manipulation
];

/// Allowed subdirectories in objectives/collection/
///
/// Information gathering — identifying and collecting data from the system.
/// "Identify and gather information, such as sensitive files." (OB0003)
///
/// NOT collection (common misplacements):
/// - Targeting specific credential stores → credential-access/
/// - Data transport to attacker → exfiltration/
/// - Neutral file reading → micro-behaviors/fs/read/
const ALLOWED_COLLECTION: &[&str] = &[
    "activity",       // User activity tracking
    "app-data",       // Application-specific data (Notes, Stickies, macOS metadata)
    "archive",        // Archive collected data                           T1560
    "clipboard",      // Clipboard capture                                T1115
    "database",       // Database enumeration/access                      T1005
    "email-harvest",  // Email address harvesting                         T1114
    "file-copy",      // File copying mechanisms                          T1005
    "file-targeting", // File enumeration for targeting                   T1083
    "keylog",         // Keystroke logging                                T1056.001
    "messaging",      // Messaging app data collection                    T1005
    "monitor",        // Monitoring/telemetry capture
    "network",        // Network packet/traffic capture                   T1040
    "screenshot",     // Screen capture                                   T1113
    "stealer",        // Multi-step stealer behavior composites           T1119
];

/// Allowed subdirectories in objectives/credential-access/
///
/// Credential theft — targeting specific credential stores and secrets.
/// "Obtain credential access." (OB0005)
///
/// NOT credential-access (common misplacements):
/// - Generic keystroke/clipboard capture → collection/
/// - Neutral env access (os.environ) → micro-behaviors/os/env/
/// - Credential + transport chains → exfiltration/stealer/
/// - Remote service brute-forcing → lateral-movement/brute-force/
const ALLOWED_CREDENTIAL_ACCESS: &[&str] = &[
    "api-harvest",        // API key/token harvesting                      T1528
    "browser",            // Browser credential stores                     T1555.003
    "capture",            // Password prompt/input capture                 T1056
    "clipboard",          // Clipboard credential targeting (crypto hijack)
    "cloud",              // Cloud service tokens
    "cracking",           // Password cracking                             T1110
    "credential-manager", // Windows Credential Manager                      T1555.004
    "dev-tools",          // Developer tool credentials (JFrog, etc.)
    "discord",            // Discord token theft                           T1528
    "dump",               // OS credential dumping                         T1003
    "email",              // Email client credentials
    "env",                // Environment secrets                           T1552.001
    "files",              // Config file credentials                       T1552.001
    "financial",          // Financial data (credit cards)
    "ftp",                // FTP client credentials
    "gaming",             // Gaming platform credentials (Steam)
    "keychain",           // macOS Keychain                                T1555.001
    "messaging",          // Messaging app credentials (Telegram)
    "pam",                // PAM interception                              T1556.003
    "phishing",           // Credential phishing                           T1566
    "shell",              // Shell history                                 T1552.003
    "ssh",                // SSH key theft                                 T1552.004
    "theft",              // Credential theft composites
    "validation",         // Credential validation
    "vpn",                // VPN config credentials
    "wallet",             // Crypto wallet access                          B0028
    "windows-registry",   // Registry credential extraction
];

/// Allowed subdirectories in objectives/discovery/
///
/// Environment reconnaissance — gaining knowledge about the system and network.
/// "Gain knowledge about the system and network." (OB0007)
///
/// NOT discovery (common misplacements):
/// - Single neutral system call (os.platform) → micro-behaviors/os/sysinfo/
/// - Port scanning for lateral movement → discovery/network/scan/ (stays here)
const ALLOWED_DISCOVERY: &[&str] = &[
    "account", // Account/user discovery                              T1087, T1033
    "cloud",   // Cloud instance metadata                             T1552.005
    "host",    // Host-specific discovery (apps, browser, geo, security)
    "network", // Network information (connections, scan, interfaces) T1016
    "process", // Process enumeration                                 T1057
    "system",  // System information                                  E1082
];

/// Allowed subdirectories in objectives/exfiltration/
///
/// Data theft — transporting stolen data out of the system.
/// "Steal data from a system." (OB0010)
/// Focuses on TRANSPORT. Source + transport = exfiltration.
///
/// NOT exfiltration (common misplacements):
/// - Reading credential stores → credential-access/
/// - Gathering/archiving data → collection/
/// - Transport mechanism alone (HTTP POST) → micro-behaviors/communications/
const ALLOWED_EXFILTRATION: &[&str] = &[
    "cloud",          // Cloud storage exfil (S3, GCS, Colab)           T1567
    "dns",            // DNS-based exfil (subdomain encoding)           T1048
    "ftp",            // FTP-based exfil
    "http",           // HTTP/HTTPS exfil (POST, upload, paste)         T1041
    "messaging",      // Messaging platform abuse (Discord, Slack, Telegram)
    "oob",            // Out-of-band data collection (interactsh, pipedream)
    "sensitive-data", // Sensitive file targeting before transport
    "serialization",  // Data serialization for transport
    "side-channel",   // Covert channels (DNS tunneling, stego)
    "stealer",        // Complete steal-and-send chains                 E1020
];

/// Allowed subdirectories in objectives/persistence/
///
/// Persistence is organized by trigger event:
/// - firmware: survives OS reinstall (MBR, UEFI, component firmware)
/// - system: runs at OS boot, no user login needed
/// - login: runs at user login / session start
///
/// NOTE: Hiding/concealment belongs in evasion/, not persistence/.
/// Persistence is about *restarting after reboot*, not *hiding from detection*.
const ALLOWED_PERSISTENCE: &[&str] = &[
    "firmware", // Survives OS reinstall (bootkit, UEFI, component firmware)
    "system",   // Runs at OS boot (services, daemons, init scripts, cron)
    "login",    // Runs at user login (registry run keys, shell RC, startup folder)
];

/// Allowed top-level subdirectories in micro-behaviors/
///
/// These represent capability categories (what code can do).
/// Must not use objective names (no c2, persist, evasion, etc.).
///
/// Note: Some directories like anti-analysis/, anti-static/, execution/
/// These represent capability categories (what code can do).
/// Must not use objective names (no c2, persist, evasion, etc.).
const ALLOWED_MICRO_BEHAVIORS: &[&str] = &[
    "communications", // Network protocols and transport
    "crypto",         // Cryptographic operations
    "data",           // Data transformation, encoding, serialization
    "dylib",          // Dynamic library operations
    "fs",             // Filesystem access
    "hardware",       // Hardware interaction
    "mem",            // Memory operations
    "os",             // OS integration
    "process",        // Process control
    "time",           // Timing operations
    "ui",             // User interface operations
];

/// Allowed subdirectories in micro-behaviors/communications/
const ALLOWED_MB_COMMUNICATIONS: &[&str] = &[
    "async-io",
    "benchmark",
    "capture",
    "dns",
    "email",
    "ftp",
    "http",
    "icmp",
    "ip",
    "ipc",
    "proxy",
    "socket",
    "ssh",
    "url",
    "websocket",
];

/// Allowed subdirectories in micro-behaviors/crypto/
const ALLOWED_MB_CRYPTO: &[&str] = &[
    "asymmetric",
    "certificate",
    "hash",
    "kdf",
    "library",
    "symmetric",
];

/// Allowed subdirectories in micro-behaviors/data/
const ALLOWED_MB_DATA: &[&str] = &[
    "archive",
    "buffer",
    "compress",
    "control-flow",
    "db",
    "decode",
    "embedded",
    "encode",
    "format",
    "serialize",
    "source",
    "string",
    "text",
];

/// Allowed subdirectories in micro-behaviors/dylib/
const ALLOWED_MB_DYLIB: &[&str] = &["enumerate", "library", "load", "lookup"];

/// Allowed subdirectories in micro-behaviors/fs/
const ALLOWED_MB_FS: &[&str] = &[
    "attributes",
    "chmod",
    "config",
    "delete",
    "device",
    "directory",
    "disk",
    "enumerate",
    "file",
    "link",
    "lock",
    "memory",
    "path",
    "pipe",
    "proc",
    "quota",
    "read",
    "shell-ops",
    "swap",
    "sync",
    "temp",
    "traversal",
    "volume",
    "watch",
    "write",
];

/// Allowed subdirectories in micro-behaviors/hardware/
const ALLOWED_MB_HARDWARE: &[&str] = &[
    "block",
    "display",
    "flash",
    "input",
    "iokit",
    "smartcard",
    "wireless",
];

/// Allowed subdirectories in micro-behaviors/mem/
const ALLOWED_MB_MEM: &[&str] = &[
    "advise",
    "alloc",
    "anonymous",
    "c-runtime",
    "create",
    "decompress",
    "gc",
    "inline-asm",
    "lock",
    "protect",
    "query",
    "read",
    "sync",
];

/// Allowed subdirectories in micro-behaviors/os/
const ALLOWED_MB_OS: &[&str] = &[
    "api-resolution",
    "autorun",
    "bpf",
    "callback",
    "clipboard",
    "com",
    "compat",
    "console",
    "container",
    "env",
    "event",
    "exception",
    "firewall",
    "group",
    "kernel",
    "linker",
    "message",
    "module",
    "msdos",
    "network",
    "package-manager",
    "pam",
    "privilege",
    "random",
    "registry",
    "security",
    "service",
    "signal",
    "stdio",
    "syscall",
    "sysinfo",
    "telemetry",
    "user",
    "wmi",
    "wsh",
];

/// Allowed subdirectories in micro-behaviors/process/
const ALLOWED_MB_PROCESS: &[&str] = &[
    "argument",
    "attach",
    "control",
    "create",
    "daemonize",
    "debug",
    "enumerate",
    "exit",
    "fd",
    "fork",
    "hook",
    "identity",
    "info",
    "inject",
    "interpreter",
    "io",
    "lifecycle",
    "pid",
    "resources",
    "script",
    "sync",
    "terminate",
    "thread",
    "threading",
    "tls",
    "tty",
    "user",
];

/// Allowed subdirectories in micro-behaviors/time/
const ALLOWED_MB_TIME: &[&str] = &["query", "schedule", "sleep", "timing"];

/// Allowed subdirectories in micro-behaviors/ui/
const ALLOWED_MB_UI: &[&str] = &[
    "controls",
    "dialog",
    "framework",
    "graphics",
    "menu",
    "terminal",
    "wallpaper",
    "window",
];

/// Allowed subdirectories in objectives/anti-analysis/
///
/// These represent behaviors that prevent, obstruct, or evade behavioral analysis
/// (sandboxes, debuggers, VMs, emulators). NOT for general defense evasion — that
/// belongs in objectives/evasion/. NOT for static analysis evasion — that belongs
/// in objectives/anti-static/.
///
/// Update this list AND TAXONOMY.md when adding new anti-analysis categories.
const ALLOWED_ANTI_ANALYSIS: &[&str] = &[
    "debugger-detect",    // B0001 Debugger Detection
    "sandbox-detect",     // B0007 Sandbox Detection
    "vm-detect",          // B0009 Virtual Machine Detection
    "emulator-detect",    // B0004 Emulator Detection
    "environment-detect", // Analysis environment detection
    "timing",             // B0025 Conditional Execution (delays, dormancy)
    "tool-detect",        // Detect analyst tools (IDA, procmon, x64dbg)
    "geofencing",         // B0025 Geographic/locale conditional execution
    "anti-tampering",     // Detect analyst code patches
    "self-modify",        // Runtime self-modification (B0008)
    "self-terminate",     // Crash/exit when analysis detected
    "process-tree",       // Break process lineage for sandbox evasion
    "fingerprinting",     // CPU/instruction-level environment detection
    "browser-detect",     // Browser sandbox detection
];

/// Allowed subdirectories in objectives/command-and-control/
///
/// C2 is about communicating with compromised systems to control them (MBC OB0004).
/// MBC behaviors: B0030 C2 Communication, B0031 DGA, E1105 Ingress Tool Transfer.
///
/// NOT C2 (common misplacements):
/// - DDoS attacks → impact/dos/
/// - Data exfiltration → exfiltration/
/// - Credential phishing → credential-access/phishing/
/// - Steganography for hiding → anti-static/obfuscation/steganography/
/// - Competing malware kill → impact/degrade/rival-bot/
///
/// Update this list AND TAXONOMY.md when adding new C2 categories.
const ALLOWED_C2: &[&str] = &[
    "backdoor",       // Persistent remote access (all types)          B0030
    "beacon",         // Periodic check-in / heartbeat                 B0030
    "botnet",         // Bot network coordination                      B0030
    "channel",        // Communication channels (HTTP, IRC, Tor, etc.) B0030
    "dns",            // DNS-based C2 + DGA + tunneling                B0031
    "dropper",        // Payload delivery & execution                  E1105
    "infrastructure", // C2 infrastructure (domains, IPs, cloud)       B0030
    "remote-command", // Command dispatch                              B0011
    "reverse-shell",  // Reverse shell patterns                        B0030
    "trigger",        // Activation triggers
];

/// Allowed subdirectories in objectives/lateral-movement/
///
/// Lateral movement is about propagation — spreading to new systems.
/// Everything here must involve moving through an environment, either
/// actively (direct machine access) or passively (malicious email).
///
/// NOT lateral movement (common misplacements):
/// - Scanning/recon → discovery/network/scan/
/// - Local password cracking → credential-access/
/// - Process injection → evasion/process/injection/
/// - Masquerading → evasion/masquerade/
/// - Killing rival malware → impact/degrade/rival-bot/
/// - WMI execution → execution/ (lateral only when combined with network evidence)
///
/// Update this list AND TAXONOMY.md when adding new lateral-movement categories.
const ALLOWED_LATERAL_MOVEMENT: &[&str] = &[
    "brute-force",        // Remote service credential spraying (SSH, IoT)  T1110
    "delivery",           // Payload delivery to new targets                E1105
    "exploit",            // Remote exploitation for access
    "infection",          // File infection / virus propagation             T1554
    "pass-the-hash",      // Credential reuse for remote access             T1550.002
    "smb",                // SMB share propagation                          T1021.002
    "social-engineering", // Lures, spam (passive lateral)                 B0020, B0021
    "ssh",                // SSH lateral (connect, backdoor, deploy)        T1021.004
    "trojanize",          // Software trojanization
    "usb-worm",           // USB drive propagation
    "worm",               // Self-propagating (email, SMB, IRC, P2P)
];

/// Allowed subdirectories in objectives/execution/
///
/// Execution is about executing code on a system (MBC OB0009).
/// "Behaviors that enable malware to execute code on a system to achieve a variety of goals."
///
/// NOT execution (common misplacements):
/// - Neutral capabilities (openpty, fork+setsid, GetModuleHandle, Math.random) → micro-behaviors/
/// - Evasive execution (reflective loading, fileless, shellcode) → evasion/
/// - Privilege escalation (sudo, GTFOBins) → privilege-escalation/
/// - Remote commands (attacker-controlled) → command-and-control/
/// - Install hooks (setup.py cmdclass) → micro-behaviors/build/setup/;
///   composites live in lateral-movement/supply-chain/
///
/// Update this list AND TAXONOMY.md when adding new execution categories.
const ALLOWED_EXECUTION: &[&str] = &[
    "activex",     // COM/ActiveX execution                        E1569
    "autoinstall", // Automatic dependency installation
    "automation",  // Compiled automation (AppleScript)             E1059
    "compile",     // Compile after delivery
    "condition",   // Conditional execution / guardrails            B0025
    "exploit",     // Exploitation for client execution             E1203
    "interpreter", // Script/code interpreters                      E1059
    "lnk",         // LNK-based execution                           E1204
    "lolbin",      // Living-off-the-land binaries                  T1218
    "lure",        // User execution via social engineering          E1204
    "trigger",     // Document exploitation triggers                 E1203
    "wmi",         // WMI execution                                  E1569
];

/// Allowed subdirectories in objectives/impact/
///
/// Impact is about destructive, disruptive, or resource-hijacking operations.
/// "Manipulate, interrupt, or destroy systems and data."
///
/// NOT impact (common misplacements):
/// - Exploits/CVEs → privilege-escalation/exploit/
/// - Info stealers → credential-access/ or collection/
/// - AV/EDR bypass (AMSI, indirect syscalls) → evasion/anti-av/
/// - File hiding → evasion/file-hiding/
/// - Specific malware families → well-known/malware/
///
/// NOTE on evasion vs impact boundary:
/// - evasion/ = stealth ("don't see me") — bypass, exclusions, hiding
/// - impact/degrade/ = aggression ("I'll stop you") — kill processes, disable firewalls
///
/// Update this list AND TAXONOMY.md when adding new impact categories.
const ALLOWED_IMPACT: &[&str] = &[
    "crypto-manipulation", // Cryptocurrency manipulation (clipboard hijack) T1565.001
    "cryptojacking",       // Resource hijacking / cryptomining              B0018
    "deface",              // Defacement                                     T1491
    "degrade",             // System capability degradation (EDR kill, firewall disable)
    "destroy",             // Data destruction                               T1485
    "dos",                 // Denial of service                              B0033
    "infect",              // File infection (virus propagation)
    "ransom",              // Ransomware encryption + extortion              T1486
    "services",            // Service stopping                               T1489
    "system",              // System impact (crash, shutdown, reboot)
    "ui",                  // Screen locker / UI lockout
    "wipe",                // Disk wiping                                    T1561
];

/// Allowed subdirectories in objectives/supply-chain/
///
/// Supply chain attacks — compromising package ecosystems, extensions, and updates.
/// These target the software distribution pipeline itself.
///
/// NOT supply-chain (common misplacements):
/// - Lateral movement via supply chain → lateral-movement/ (spreading, not compromising packages)
/// - Package metadata analysis → metadata/package/
///
/// Update this list AND TAXONOMY.md when adding new supply-chain categories.
const ALLOWED_SUPPLY_CHAIN: &[&str] = &[
    "credential-theft", // Stealing credentials from CI/package infra
    "hidden-payload",   // Concealed malicious payloads in packages
    "impersonation",    // Typosquatting, name confusion
    "install-hook",     // Malicious install/build hooks (setup.py, postinstall)
    "metadata-anomaly", // Suspicious package metadata patterns
    "recon-exfil",      // Reconnaissance and data exfiltration from build env
    "trojanized",       // Trojanized legitimate packages
];

/// Allowed top-level subdirectories in well-known/
///
/// These represent specific malware families and tools.
const ALLOWED_WELL_KNOWN: &[&str] = &["malware", "tools"];

/// Allowed subdirectories in well-known/malware/
///
/// Categories align with MBC/STIX 2.1 malware types. Each describes what the
/// malware DOES, not who made it or how it arrives.
///
/// Rules:
/// - Each malware family appears in exactly ONE category
/// - Pick the primary behavior when a family has multiple capabilities
/// - Actor attribution (APT group) belongs in trait descriptions, not dirs
/// - trojan/ is catch-all — use only when no more specific type fits
///
/// Update this list AND TAXONOMY.md when adding new malware categories.
const ALLOWED_MALWARE: &[&str] = &[
    "backdoor",     // Passive remote access (shell, tunnel, implant)
    "botnet",       // Bot network member (C2-controlled fleet)
    "downloader",   // Fetches payload from remote URL
    "dropper",      // Contains/stages another payload (disk or memory)
    "exploit",      // Exploits specific vulnerabilities (CVE, PoC)
    "keylogger",    // Primary function is keystroke capture
    "miner",        // Cryptomining / resource hijacking
    "ransomware",   // File encryption for ransom
    "rat",          // Full remote administration toolkit
    "rootkit",      // Kernel/userspace hiding + privilege escalation
    "stealer",      // Information stealer (credentials, tokens, wallets)
    "supply-chain", // Malicious package, extension, or update
    "trojan",       // Disguised as legitimate (catch-all)
    "virus",        // Self-replicating file infector
    "webshell",     // Web-based backdoor (PHP/JSP/ASP)
    "worm",         // Self-propagating across networks
];

/// Allowed subdirectories in well-known/tools/
///
/// Categories of tools detected by signature or behavioral pattern.
/// Each describes the tool's PURPOSE, not its legality.
///
/// Update this list AND TAXONOMY.md when adding new tool categories.
const ALLOWED_TOOLS: &[&str] = &[
    "browser",             // Browser-based tools and extensions
    "detection",           // Detection and scanning tools
    "dual-use",            // Legitimate tools commonly abused (LOLBins, netcat, etc.)
    "offensive",           // Offensive security / red team tools
    "reverse-engineering", // RE tools (disassemblers, debuggers, decompilers)
    "sysadmin",            // System administration tools
];

/// Allowed top-level subdirectories in metadata/
///
/// These represent neutral file-structure metadata with no behavioral implication.
/// Behavioral detection (supply-chain indicators, masquerade detection, etc.)
/// belongs in objectives/, not here.
///
/// Update this list AND TAXONOMY.md when adding new metadata categories.
const ALLOWED_METADATA: &[&str] = &[
    "arch",      // CPU architecture detection (x86, ARM, MIPS, IoT)
    "binary",    // Binary internals (sections, debug, framework, installer, metrics)
    "build",     // Build system detection (cmake, cargo, docker, CI/CD)
    "document",  // Document format internals (office, PDF, RTF, OLE, HTML)
    "file",      // File-level observables (magic bytes, extension, encoded content)
    "hardening", // Security hardening features (sandbox, seccomp, pledge)
    "import",    // Dependencies/imports (auto-generated)
    "lang",      // Language, compiler, encoding detection
    "library",   // Library/framework detection (react, vue, jquery, etc.)
    "package",   // Package ecosystem metadata & project quality
    "signed",    // Code signatures, certificates, entitlements
    "vendor",    // Vendor identification (Apple, Microsoft, FSF, etc.)
];

/// Allowed subdirectories in metadata/binary/
///
/// Binary internals — traits that require parsing binary headers (PE, ELF, Mach-O).
/// File-level observables (magic bytes, extension) belong in file/, not here.
/// Document parsing (OLE, OOXML, PDF) belongs in document/, not here.
///
/// Prefer technology-neutral subdirectory names. Technology names belong in filenames.
const ALLOWED_METADATA_BINARY: &[&str] = &[
    "anomaly",     // Structural violations and anomalies
    "debug",       // Debug symbols (PDB, DWARF)
    "framework",   // Runtime/framework detection (.NET, Java, VB6, MFC)
    "installer",   // Installer framework detection
    "instruction", // Instruction-level patterns (indirect calls, CPUID)
    "layout",      // File-level structure (overlay, embedded, bundles)
    "linking",     // Runtime linking and dynamic resolution
    "metrics",     // Structural measurements (counts, entropy, ratios, size)
    "resource",    // Embedded resource analysis
    "section",     // Section analysis
    "symbols",     // Import/export symbol analysis
];

/// Allowed subdirectories in metadata/document/
///
/// Document internals — traits that require document parsing (OLE, OOXML, PDF objects).
/// Binary parsing belongs in binary/, file identification in file/.
const ALLOWED_METADATA_DOCUMENT: &[&str] = &[
    "html",   // HTML structure
    "office", // Office documents (VBA, OOXML, ActiveMime)
    "ole",    // OLE compound documents
    "pdf",    // PDF structure
    "rtf",    // RTF analysis
];

/// Allowed subdirectories in metadata/file/
///
/// File-level observables — properties visible without deep parsing.
/// These are primarily component traits used as building blocks in composite rules.
const ALLOWED_METADATA_FILE: &[&str] = &[
    "encoded",   // Encoded content presence (base64)
    "extension", // File extension classification
    "magic",     // Magic byte signatures
    "text",      // Text/data format identification (JSON, makefile)
];

/// Allowed subdirectories in metadata/lang/
///
/// Language, compiler, and encoding detection.
/// Build orchestration (cmake, docker, CI/CD) belongs in build/, not here.
const ALLOWED_METADATA_LANG: &[&str] = &[
    "compiled",            // Compiled language detection
    "compiler",            // Compiler identification
    "encoded",             // Encoded strings (unicode, wide)
    "go-build",            // Go build specifics
    "javascript-features", // JavaScript language features
    "linking",             // Linker properties
    "optimization",        // Optimization flags
    "scripted",            // Scripted language detection
    "security",            // Language security features
    "shebang",             // Shebang detection
    "source",              // Source language identification
    "version",             // Language version detection
];

/// Allowed subdirectories in metadata/package/
///
/// Package ecosystem metadata and project quality indicators.
/// Behavioral supply-chain detection belongs in objectives/supply-chain/, not here.
const ALLOWED_METADATA_PACKAGE: &[&str] = &[
    "chrome-extension", // Extension manifest analysis
    "config",           // Configuration file detection
    "contributors",     // Contributor metadata
    "dependencies",     // Dependency analysis
    "documentation",    // Documentation presence
    "error-handling",   // Error handling patterns
    "fields",           // Package field analysis
    "files",            // File counts and types
    "help",             // Help/usage interface
    "keywords",         // Package keywords
    "license",          // License detection
    "logging",          // Logging patterns
    "maintainers",      // Maintainer counts
    "metrics",          // Code metrics
    "quality",          // Quality signals
    "scripts",          // Package scripts
    "testing",          // Testing detection
    "tooling",          // Package tooling
    "versioning",       // Version detection
];

/// Allowed subdirectories in metadata/signed/
///
/// Code signatures, certificates, and entitlements.
/// Vendor identification by non-signature means belongs in vendor/, not here.
const ALLOWED_METADATA_SIGNED: &[&str] = &[
    "certificate",  // Certificate chain string patterns
    "entitlements", // Code entitlements (macOS/iOS, Android)
    "platform",     // Platform-signed binary composites (auto-generated)
    "trust-level",  // Signing trust level (ad-hoc, developer, platform, app store)
];

/// Validates that only known subdirectories exist in taxonomy tiers.
///
/// Returns Ok(()) if all directories are whitelisted, or Err with a list
/// of unknown directories that should be reviewed.
pub(crate) fn validate_directory_structure(traits_path: &Path) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Check objectives/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_OBJECTIVES.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/ subdirectory: '{}'\n  \
                         If this is a valid MBC objective, add it to ALLOWED_OBJECTIVES in \
                         src/capabilities/validation/directory_whitelist.rs",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/anti-analysis/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/anti-analysis")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_ANTI_ANALYSIS.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/anti-analysis/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         anti-analysis/ is for behavioral analysis evasion (sandboxes, debuggers, VMs).\n  \
                         Defense evasion belongs in evasion/, static analysis evasion in anti-static/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/anti-static/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/anti-static")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_ANTI_STATIC.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/anti-static/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         anti-static/ is for static analysis evasion (obfuscation, packing).\n  \
                         Behavioral analysis evasion belongs in anti-analysis/, defense evasion in evasion/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/collection/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/collection")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_COLLECTION.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/collection/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         collection/ is for gathering information (capture, archive, enumerate).\n  \
                         Credential-specific stores → credential-access/. Financial → credential-access/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/privilege-escalation/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/privilege-escalation")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_PRIVILEGE_ESCALATION.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/privilege-escalation/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         privilege-escalation/ is for obtaining higher permissions.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/discovery/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/discovery")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_DISCOVERY.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/discovery/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         discovery/ is for reconnaissance (gaining knowledge about system/network).\n  \
                         Neutral capabilities → micro-behaviors/. Taking action → lateral-movement/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/credential-access/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/credential-access")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_CREDENTIAL_ACCESS.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/credential-access/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         credential-access/ targets specific credential stores.\n  \
                         Generic capture → collection/. Neutral env access → micro-behaviors/.\n  \
                         Neutral keywords → micro-behaviors/data/text/keywords/.\n  \
                         Credential access + transport → exfiltration/stealer/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/evasion/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/evasion")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_EVASION.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/evasion/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         evasion/ is for stealth — hiding from users, admins, and security tools.\n  \
                         Killing AV → impact/degrade/edr/. Obfuscation → anti-static/.\n  \
                         Analyst tool detection → anti-analysis/tool-detect/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/persistence/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/persistence")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_PERSISTENCE.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/persistence/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         persistence/ must use firmware/, system/, or login/ to indicate trigger event.\n  \
                         Hiding/concealment belongs in evasion/, not persistence/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/command-and-control/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/command-and-control")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_C2.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/command-and-control/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         command-and-control/ is for C2 communication (MBC OB0004).\n  \
                         DDoS → impact/dos/. Exfiltration → exfiltration/. Phishing → credential-access/.\n  \
                         Steganography → anti-static/obfuscation/. Rival malware kill → impact/degrade/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/execution/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/execution")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_EXECUTION.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/execution/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         execution/ is for code execution on a system (MBC OB0009).\n  \
                         Neutral capabilities → micro-behaviors/. Evasive execution → evasion/.\n  \
                         Privilege escalation → privilege-escalation/. Remote commands → command-and-control/.\n  \
                         Install hooks → micro-behaviors/build/setup/ (composites in supply-chain/).\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/lateral-movement/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/lateral-movement")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_LATERAL_MOVEMENT.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/lateral-movement/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         lateral-movement/ is for propagation — spreading to new systems.\n  \
                         Scanning → discovery/. Process injection → evasion/. Masquerading → evasion/masquerade/.\n  \
                         Local password cracking → credential-access/. Rival malware killing → impact/degrade/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/impact/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/impact")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_IMPACT.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/impact/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         impact/ is for destructive, disruptive, or resource-hijacking operations.\n  \
                         Exploits/CVEs → privilege-escalation/. AV bypass → evasion/anti-av/.\n  \
                         AV/EDR termination (aggressive) → impact/degrade/edr/.\n  \
                         File hiding → evasion/file-hiding/. Malware signatures → well-known/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/exfiltration/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/exfiltration")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_EXFILTRATION.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/exfiltration/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         exfiltration/ focuses on transport — how data leaves the system.\n  \
                         Reading credentials → credential-access/. Gathering data → collection/.\n  \
                         Transport alone (HTTP POST) → micro-behaviors/communications/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check objectives/supply-chain/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives/supply-chain")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_SUPPLY_CHAIN.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/supply-chain/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         supply-chain/ is for package ecosystem attacks (install hooks, typosquatting).\n  \
                         Lateral movement via supply chain → lateral-movement/.\n  \
                         Package metadata → metadata/package/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check micro-behaviors/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("micro-behaviors")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_MICRO_BEHAVIORS.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown micro-behaviors/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         Micro-behaviors must describe capabilities, not objectives.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check micro-behaviors/ subdirectory whitelists
    let mb_checks: &[(&str, &[&str])] = &[
        ("communications", ALLOWED_MB_COMMUNICATIONS),
        ("crypto", ALLOWED_MB_CRYPTO),
        ("data", ALLOWED_MB_DATA),
        ("dylib", ALLOWED_MB_DYLIB),
        ("fs", ALLOWED_MB_FS),
        ("hardware", ALLOWED_MB_HARDWARE),
        ("mem", ALLOWED_MB_MEM),
        ("os", ALLOWED_MB_OS),
        ("process", ALLOWED_MB_PROCESS),
        ("time", ALLOWED_MB_TIME),
        ("ui", ALLOWED_MB_UI),
    ];
    for (category, allowed) in mb_checks {
        let cat_path = traits_path.join(format!("micro-behaviors/{}", category));
        if let Ok(entries) = std::fs::read_dir(&cat_path) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    let dir_name = entry.file_name().to_string_lossy().to_string();
                    if !allowed.contains(&dir_name.as_str()) {
                        errors.push(format!(
                            "Unknown micro-behaviors/{}/{}\n  \
                             This rule is misplaced according to TAXONOMY.md.\n  \
                             There is almost certainly a better existing directory for this trait.",
                            category, dir_name
                        ));
                    }
                }
            }
        }
    }

    // Check well-known/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("well-known")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_WELL_KNOWN.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown well-known/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         well-known/ should only contain 'malware' and 'tools'.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check well-known/malware/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("well-known/malware")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_MALWARE.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown well-known/malware/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         malware/ categories must describe what the malware DOES (MBC/STIX 2.1 types).\n  \
                         Actor attribution (APT) belongs in trait descriptions, not directory names.\n  \
                         Each family appears in exactly one category.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check well-known/tools/ subdirectories
    if let Ok(entries) = std::fs::read_dir(traits_path.join("well-known/tools")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_TOOLS.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown well-known/tools/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         tools/ categories describe a tool's purpose, not its legality.\n  \
                         Malware families → well-known/malware/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check metadata/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("metadata")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_METADATA.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown metadata/ subdirectory: '{}'\n  \
                         This rule is misplaced according to TAXONOMY.md.\n  \
                         metadata/ must contain only neutral file-structure properties.\n  \
                         Behavioral detection belongs in objectives/, tool signatures in well-known/.\n  \
                         There is almost certainly a better existing directory for this trait.",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check metadata/ subdirectory whitelists
    let metadata_checks: &[(&str, &[&str])] = &[
        ("binary", ALLOWED_METADATA_BINARY),
        ("document", ALLOWED_METADATA_DOCUMENT),
        ("file", ALLOWED_METADATA_FILE),
        ("lang", ALLOWED_METADATA_LANG),
        ("package", ALLOWED_METADATA_PACKAGE),
        ("signed", ALLOWED_METADATA_SIGNED),
    ];
    for (category, allowed) in metadata_checks {
        let cat_path = traits_path.join(format!("metadata/{}", category));
        if let Ok(entries) = std::fs::read_dir(&cat_path) {
            for entry in entries.flatten() {
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    let dir_name = entry.file_name().to_string_lossy().to_string();
                    if !allowed.contains(&dir_name.as_str()) {
                        errors.push(format!(
                            "Unknown metadata/{}/{}\n  \
                             This rule is misplaced according to TAXONOMY.md.\n  \
                             See the metadata boundary rubric in TAXONOMY.md for placement guidance.\n  \
                             There is almost certainly a better existing directory for this trait.",
                            category, dir_name
                        ));
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_validate_actual_traits_directory() {
        // Test against actual traits directory
        let traits_path = PathBuf::from("traits");
        if traits_path.exists() {
            let result = validate_directory_structure(&traits_path);
            assert!(
                result.is_ok(),
                "Directory validation failed:\n{}",
                result.unwrap_err().join("\n")
            );
        }
    }

    #[test]
    fn test_allowed_objectives_constants() {
        // Verify all MBC objectives are present
        assert!(ALLOWED_OBJECTIVES.contains(&"anti-analysis"));
        assert!(ALLOWED_OBJECTIVES.contains(&"anti-static"));
        assert!(ALLOWED_OBJECTIVES.contains(&"evasion"));
        assert!(ALLOWED_OBJECTIVES.contains(&"execution"));
        assert!(ALLOWED_OBJECTIVES.contains(&"persistence"));
        assert!(ALLOWED_OBJECTIVES.contains(&"privilege-escalation"));
    }

    #[test]
    fn test_no_objective_abbreviations_allowed() {
        // Ensure abbreviated/aliased names aren't in the whitelist
        // c2 should be command-and-control, collect should be collection
        assert!(!ALLOWED_OBJECTIVES.contains(&"c2"));
        assert!(!ALLOWED_OBJECTIVES.contains(&"collect"));
        assert!(!ALLOWED_OBJECTIVES.contains(&"cred"));
        assert!(!ALLOWED_OBJECTIVES.contains(&"privesc"));
        assert!(!ALLOWED_OBJECTIVES.contains(&"lat-move"));
    }

    #[test]
    fn test_catches_invalid_objectives_subdirectory() {
        // Create temp directory with invalid structure
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Create objectives/ with valid and invalid subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/c2")).unwrap(); // Invalid!
        std::fs::create_dir_all(traits_path.join("objectives/collect")).unwrap(); // Invalid!

        let result = validate_directory_structure(traits_path);
        assert!(result.is_err(), "Should catch invalid directories");

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'c2'")),
            "Should flag 'c2' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'collect'")),
            "Should flag 'collect' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_micro_behaviors_subdirectory() {
        // Create temp directory with invalid structure
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Create micro-behaviors/ with valid and invalid subdirectories
        std::fs::create_dir_all(traits_path.join("micro-behaviors/communications")).unwrap();
        std::fs::create_dir_all(traits_path.join("micro-behaviors/c2")).unwrap(); // Invalid!
        std::fs::create_dir_all(traits_path.join("micro-behaviors/persist")).unwrap(); // Invalid!

        let result = validate_directory_structure(traits_path);
        assert!(result.is_err(), "Should catch invalid directories");

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'c2'")),
            "Should flag 'c2' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'persist'")),
            "Should flag 'persist' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_valid_structure_passes() {
        // Create temp directory with valid structure
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Create valid directories
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/collection")).unwrap();
        std::fs::create_dir_all(traits_path.join("micro-behaviors/communications")).unwrap();
        std::fs::create_dir_all(traits_path.join("micro-behaviors/process")).unwrap();
        std::fs::create_dir_all(traits_path.join("well-known/malware")).unwrap();
        std::fs::create_dir_all(traits_path.join("metadata/binary")).unwrap();
        std::fs::create_dir_all(traits_path.join("metadata/vendor")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(result.is_ok(), "Valid structure should pass: {:?}", result);
    }

    #[test]
    fn test_catches_invalid_metadata_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        std::fs::create_dir_all(traits_path.join("metadata/binary")).unwrap();
        std::fs::create_dir_all(traits_path.join("metadata/purpose")).unwrap(); // Invalid!
        std::fs::create_dir_all(traits_path.join("metadata/intent")).unwrap(); // Invalid!

        let result = validate_directory_structure(traits_path);
        assert!(result.is_err(), "Should catch invalid metadata directories");

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'purpose'")),
            "Should flag 'purpose' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'intent'")),
            "Should flag 'intent' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_anti_analysis_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Create valid and invalid anti-analysis subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/debugger-detect"))
            .unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/vm-detect")).unwrap();
        // Invalid - these belong elsewhere
        std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/obfuscation")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/kernel-hide")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid anti-analysis directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'obfuscation'")),
            "Should flag 'obfuscation' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'kernel-hide'")),
            "Should flag 'kernel-hide' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_persistence_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Valid persistence subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/persistence/firmware")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/persistence/system")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/persistence/login")).unwrap();
        // Invalid - hiding belongs in evasion, not persistence
        std::fs::create_dir_all(traits_path.join("objectives/persistence/hidden-files")).unwrap();
        // Invalid - flat structure without trigger event
        std::fs::create_dir_all(traits_path.join("objectives/persistence/registry")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid persistence directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'hidden-files'")),
            "Should flag 'hidden-files' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'registry'")),
            "Should flag flat 'registry' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_impact_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Valid impact subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/impact/ransom")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/impact/degrade")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/impact/dos")).unwrap();
        // Invalid - exploits belong in privilege-escalation
        std::fs::create_dir_all(traits_path.join("objectives/impact/exploit")).unwrap();
        // Invalid - stealer belongs in credential-access
        std::fs::create_dir_all(traits_path.join("objectives/impact/stealer")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(result.is_err(), "Should catch invalid impact directories");

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'exploit'")),
            "Should flag 'exploit' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'stealer'")),
            "Should flag 'stealer' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_anti_static_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        std::fs::create_dir_all(traits_path.join("objectives/anti-static/obfuscation")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/anti-static/pack")).unwrap();
        // Invalid - these don't belong in anti-static
        std::fs::create_dir_all(traits_path.join("objectives/anti-static/hardening")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/anti-static/masquerade")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid anti-static directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'hardening'")),
            "Should flag 'hardening' as invalid: {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'masquerade'")),
            "Should flag 'masquerade' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_execution_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Valid execution subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/execution/interpreter")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/execution/wmi")).unwrap();
        // Invalid - these were historically misplaced
        std::fs::create_dir_all(traits_path.join("objectives/execution/setup")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/execution/tty")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/execution/reflective-load")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid execution directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'setup'")),
            "Should flag 'setup' as invalid (hooks → micro-behaviors/build/setup/): {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'tty'")),
            "Should flag 'tty' as invalid (neutral capability → micro-behaviors/): {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'reflective-load'")),
            "Should flag 'reflective-load' as invalid (evasive → evasion/ or c2/implant/): {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_c2_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Valid C2 subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control/backdoor"))
            .unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control/dropper"))
            .unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control/beacon")).unwrap();
        // Invalid - these were historically misplaced
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control/ddos")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control/exfil")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/command-and-control/phishing"))
            .unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(result.is_err(), "Should catch invalid C2 directories");

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'ddos'")),
            "Should flag 'ddos' as invalid (belongs in impact/dos/): {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'exfil'")),
            "Should flag 'exfil' as invalid (belongs in exfiltration/): {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'phishing'")),
            "Should flag 'phishing' as invalid (belongs in credential-access/): {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_lateral_movement_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Valid lateral-movement subdirectories
        std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/worm")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/ssh")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/brute-force"))
            .unwrap();
        // Invalid - these were historically misplaced and moved elsewhere
        std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/scan")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/evasion")).unwrap();
        std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/phishing")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid lateral-movement directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'scan'")),
            "Should flag 'scan' as invalid (belongs in discovery/): {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'evasion'")),
            "Should flag 'evasion' as invalid (belongs in objectives/evasion/): {:?}",
            errors
        );
        assert!(
            errors.iter().any(|e| e.contains("'phishing'")),
            "Should flag 'phishing' as invalid (belongs in credential-access/): {:?}",
            errors
        );
    }

    #[test]
    fn test_metadata_no_vendor_specific_toplevel() {
        // Vendor-specific directories belong under metadata/vendor/, not at top level
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        std::fs::create_dir_all(traits_path.join("metadata/apple")).unwrap(); // Invalid!
        std::fs::create_dir_all(traits_path.join("metadata/microsoft")).unwrap(); // Invalid!

        let result = validate_directory_structure(traits_path);
        assert!(result.is_err(), "Vendor dirs at top level should fail");

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("'apple'")),
            "Should flag 'apple' as invalid: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_metadata_level2_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        // Valid level-2 subdirectories
        std::fs::create_dir_all(traits_path.join("metadata/binary/metrics")).unwrap();
        std::fs::create_dir_all(traits_path.join("metadata/binary/anomaly")).unwrap();
        // Invalid level-2 subdirectory
        std::fs::create_dir_all(traits_path.join("metadata/binary/pe")).unwrap();

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid metadata level-2 directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("metadata/binary/pe")),
            "Should flag 'pe' as invalid under binary/: {:?}",
            errors
        );
    }

    #[test]
    fn test_catches_invalid_metadata_package_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let traits_path = temp_dir.path();

        std::fs::create_dir_all(traits_path.join("metadata/package/testing")).unwrap();
        std::fs::create_dir_all(traits_path.join("metadata/package/npm")).unwrap(); // Invalid!

        let result = validate_directory_structure(traits_path);
        assert!(
            result.is_err(),
            "Should catch invalid metadata/package/ directories"
        );

        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("metadata/package/npm")),
            "Should flag 'npm' as invalid under package/: {:?}",
            errors
        );
    }
}
