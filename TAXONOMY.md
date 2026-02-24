# cleave Taxonomy

A three-tier taxonomy following [MBC (Malware Behavior Catalog)](https://github.com/MBCProject/mbc-markdown) principles.

## Overview

| Tier | Purpose | Criticality Range | MBC Equivalent |
|------|---------|-------------------|----------------|
| **Capabilities** (`micro-behaviors/`) | Observable mechanics (what code *can do*) | component → baseline → notable → suspicious | [Micro-objectives](https://github.com/MBCProject/mbc-markdown/tree/master/micro-behaviors) |
| **Objectives** (`objectives/`) | Attacker goals (why code *likely wants* to do something) | component → baseline → notable → suspicious → hostile | [Objectives](https://github.com/MBCProject/mbc-markdown#malware-objective-descriptions) |
| **Known Entities** (`well-known/`) | Specific signatures | component → baseline → suspicious → hostile | (MBC corpus) |
| **Meta** (`metadata/`) | File-level properties (informational only) | baseline | — |

**Criticality levels:**
- **component** - Building block for composites that makes no sense individually (e.g., string fragments like `&cc=`). Filtered from terminal output unless a composite that references it fires. Always included in JSON output for ML signal.
- **baseline** - Common functionality that doesn't describe program purpose (e.g., `mmap`, `stdio`, `read`). Always included in output for ML signal.
- **notable** - Defines program purpose (`socket`, `exec`, `eval`)
- **suspicious** - Rarely legitimate, indicates possible malicious intent
- **hostile** - Clear attack pattern, no legitimate use (requires precision >= 3.5)

Both `component` and `baseline` are allowed in any tier.

## Tier Dependencies

Rules must follow a strict dependency hierarchy to maintain taxonomy clarity:

| Tier | Can Reference | Rationale |
|------|--------------|-----------|
| **`micro-behaviors/`** | `micro-behaviors/`, `metadata/` | Capabilities are atomic micro-behaviors and must not depend on objectives |
| **`objectives/`** | `micro-behaviors/`, `objectives/`, `metadata/` | Objectives build on capabilities and other objectives |
| **`well-known/`** | `micro-behaviors/`, `objectives/`, `well-known/`, `metadata/` | Specific signatures can reference any trait type |
| **`metadata/`** | `metadata/` | Informational properties typically reference only other meta traits |

**Key Principle:** `micro-behaviors/` traits must NOT reference `objectives/` traits. Capabilities represent atomic, observable mechanics (micro-behaviors), while objectives represent inferred attacker intent. Mixing these layers violates the taxonomy's separation of concerns.

**Hostile Criticality:** `micro-behaviors/` traits must NEVER use `crit: hostile`. Hostile criticality requires intent inference and must be in `objectives/` where rules are properly categorized by attacker objective (C2, exfil, impact, etc.). Cap's maximum criticality is `suspicious` for rarely legitimate but still observable capabilities.

**Examples:**
- ✅ `objectives/command-and-control/reverse-shell` references `micro-behaviors/communications/socket/create` (objective uses capability)
- ✅ `micro-behaviors/process/create/shell` references `micro-behaviors/fs/file/read` (capability uses capability)
- ✅ `micro-behaviors/process/hollow` with `crit: suspicious` (rarely legitimate capability)
- ❌ `micro-behaviors/process/create/dropper` references `objectives/anti-static/obfuscation` (capability cannot depend on objective)
- ❌ `micro-behaviors/anything` with `crit: hostile` (hostile requires intent, belongs in objectives/)

If a `micro-behaviors/` rule needs functionality from an `objectives/` trait, either:
1. Move the `objectives/` trait to `micro-behaviors/` if it's actually a capability
2. Refactor the `micro-behaviors/` rule to not depend on the objective-level detection
3. Move the entire `micro-behaviors/` rule to `objectives/` if it's actually inferring intent

## Tier 1: Capabilities (`micro-behaviors/`)

Value-neutral observations about what code can do. High confidence from static analysis. Maps to MBC's [Micro-objectives](https://github.com/MBCProject/mbc-markdown/tree/master/micro-behaviors).

**Criticality guidance:**
- **baseline** - Universal baseline (`open`, `read`, `malloc`) or building blocks for composites
- **notable** - Defines program purpose (`socket`, `exec`, `eval`)
- **suspicious** - Rarely legitimate (`shellcode-inject`, `process-hollow`)
- **Never hostile** - Hostile requires objective-level evidence (belongs in `objectives/`)

**Validation:** Cap rules with hostile criticality will fail validation. Hostile implies intent inference, which requires combining multiple capabilities into an objective.

### Directory Structure

Within objectives/ - rules should be organized in the following directory structure: objectives/OBJECTIVE/BEHAVIOR/METHOD/ - with invididual YAML files per platform or ecosystem within that directory. In some cases, you may need to add a sub-method subdirectory for methods with many options, for instance string obfuscation.

Within micro-behaviors/ - rules should be organized by micro-behaviors/CATEGORY/BEHAVIOR/METHOD/ - and if necessary, an additional level for  sub-methods. So for example, use micro-behaviors/crypto/symmetric/aes/ruby.yaml rather than micro-behaviors/crypto/symmetric/aes.yaml. Another example: micro-behaviors/data/encode/base64/ - if you can't think of a specific method, consider what could bring multiple traits together, like a common syscall, protocol, or other logical grouping. This directory name may be referenced in composite traits in order to match similar rules, so think about that when grouping them.

```
micro-behaviors/
├── communications/               # Network communication
│   ├── socket/         # Raw socket operations          → MBC: Communication
│   │   ├── netcat/     # nc/netcat tools
│   │   └── telnet/     # Telnet connections
│   ├── http/           # HTTP client/server
│   ├── dns/            # DNS operations
│   │   ├── lookup/     # DNS lookups (platform-based: unix, node)
│   │   │   ├── txt/    # TXT record lookups (C2 common)
│   │   │   └── reverse/ # Reverse DNS lookups
│   │   ├── doh/        # DNS over HTTPS
│   │   └── tools/      # DNS CLI tools (dig, nslookup, host)
│   ├── icmp/           # ICMP operations
│   │   ├── ping/       # Host reachability (ping, fping)
│   │   └── trace/      # Route tracing (traceroute, mtr)
│   ├── capture/        # Packet capture
│   │   ├── tcpdump/    # tcpdump
│   │   └── wireshark/  # Wireshark/tshark
│   ├── benchmark/      # Network performance testing
│   │   ├── iperf/      # Bandwidth testing
│   │   ├── http/       # HTTP benchmarking (ab, wrk)
│   │   └── speedtest/  # Internet speed testing
│   ├── ipc/            # Inter-process communication
│   └── proxy/          # Proxy protocols (SOCKS, etc.)
│
├── crypto/             # Cryptographic operations       → MBC: Cryptography
│   ├── symmetric/      # AES, DES, etc.
│   ├── asymmetric/     # RSA, ECC, etc.
│   ├── hash/           # SHA, MD5, etc.
│   └── xor/            # XOR operations
│
├── data/               # Data transformation            → MBC: Data
│   ├── encode/         # Encoding operations
│   │   ├── base64/
│   │   ├── hex/
│   │   └── custom/
│   ├── compress/       # Zip, gzip, etc.
│   └── serialize/      # JSON, protobuf, pickle, etc.
│
├── fs/                 # Filesystem access              → MBC: File System
│   ├── read/           # File reading
│   ├── write/          # File writing
│   ├── delete/         # File deletion
│   ├── enumerate/      # Directory listing
│   ├── hide/           # Hidden file manipulation (suspicious)
│   └── path/           # Path-related traits
│       ├── config/     # Configuration file paths
│       │   ├── accounts/  # User accounts (/etc/passwd, /etc/shadow)
│       │   ├── groups/    # Group membership (/etc/group, /etc/gshadow)
│       │   └── privilege-escalation/   # Privilege config (/etc/sudoers)
│       └── device/     # Device paths (/dev/*)
│           ├── storage/  # Block storage (/dev/sda, /dev/nvme) - wiper relevant
│           └── terminal/ # TTY/PTY devices (/dev/tty, /dev/pts)
│
├── hardware/                 # Hardware interaction           → MBC: Hardware
│   ├── input/          # Keyboard, mouse
│   ├── display/        # Screenshot, screen access
│   ├── audio/          # Microphone, speakers
│   └── usb/            # USB devices
│
├── mem/                # Memory operations              → MBC: Memory
│   ├── alloc/          # Memory allocation
│   ├── protect/        # Memory protection changes
│   ├── map/            # Memory mapping
│   └── inject/         # Shellcode/code cave injection (same-process)
│
├── os/                 # OS integration                 → MBC: Operating System
│   ├── registry/       # Windows registry
│   ├── env/            # Environment variables
│   ├── service/        # System services
│   ├── user/           # User management
│   ├── syscall/        # Direct syscall invocation
│   ├── bpf/            # BPF/eBPF operations
│   ├── info/           # Basic system queries (baseline)
│   ├── network/        # Network configuration
│   │   ├── interface/  # Interface listing (ifconfig, ip addr)
│   │   └── status/     # Connection status (netstat, ss, lsof)
│   └── firewall/       # Firewall management (by implementation)
│       ├── iptables/   # iptables/ip6tables
│       ├── nftables/   # nft/nftables
│       ├── ufw/        # Uncomplicated Firewall
│       └── firewalld/  # firewalld/firewall-cmd
│
├── process/            # Process control                → MBC: Process
│   ├── create/         # Process creation
│   ├── inject/         # Cross-process injection
│   │   ├── dll/        # DLL injection
│   │   ├── thread/     # Thread injection
│   │   ├── apc/        # APC injection
│   │   └── atom-bombing/ # Atom bombing
│   ├── terminate/      # Process termination
│   ├── enumerate/      # Process listing
│   ├── hollow/         # Process hollowing
│   ├── hook/           # API/function hooking
│   └── fd/             # File descriptor manipulation (dup2, etc.)
│
└── time/               # Timing operations
    ├── sleep/          # Delays
    ├── schedule/       # Scheduled execution
    └── timer/          # Timers
```

## Tier 2: Objectives (`objectives/`)

Attacker goals inferred from capability combinations. Implies *likely* intent - we can't be 100% certain from static analysis alone. Maps to MBC's [Objectives](https://github.com/MBCProject/mbc-markdown#malware-objective-descriptions).

**Criticality guidance:**
- **baseline** - Building block for composites, no direct analytical signal on its own
- **notable** - Objective pattern present but has common legitimate uses (anti-debug in games, discovery in installers)
- **suspicious** - Pattern suggests malicious intent, edge-case legitimate uses
- **hostile** - Clear attack pattern, no legitimate use (requires precision >= 3.5)

### Directory Structure

```
objectives/
├── anti-analysis/      # Evade dynamic analysis         → MBC: Anti-Behavioral Analysis
│   ├── vm-detect/      # Virtual machine detection        B0009
│   ├── sandbox-detect/ # Sandbox detection                B0007
│   ├── debugger-detect/# Debugger detection               B0001
│   ├── timing/         # Timing-based evasion             B0025
│   └── kernel-hide/    # Kernel-level hiding (rootkit techniques)
│
├── anti-static/        # Evade static analysis          → MBC: Anti-Static Analysis
│   ├── obfuscate/      # Code obfuscation                 B0032
│   │   ├── string-encrypt/
│   │   ├── control-flow/
│   │   ├── dead-code/
│   │   └── virtualize/   # Code virtualization            B0008
│   └── pack/           # Packing/compression
│
├── evasion/            # General evasion techniques     → MBC: Defense Evasion (extended)
│   ├── anti-av/        # AV/EDR bypass (not termination)
│   │   ├── amsi/       # AMSI bypass techniques
│   │   ├── defender/   # Windows Defender bypass
│   │   ├── heuristic/  # Static heuristic evasion (TBAV)
│   │   └── platform/   # Platform-specific bypasses
│   ├── log-clear/      # Clear logs                       T1070
│   ├── timestomp/      # Modify timestamps                T1070.006
│   ├── self-delete/    # Remove self after execution      F0007
│   ├── evidence-removal/ # Clean up artifacts
│   ├── masquerade/     # File/process masquerading        T1036
│   ├── decoy/          # Decoy documents/files
│   ├── process/        # Process manipulation
│   │   └── injection/  # Process injection                E1055
│   └── hijack-execution-flow/ # Execution flow hijacking  F0015
│   # Note: evasion/ = stealth ("don't see me")
│   # vs impact/degrade/edr/ = aggression ("I'll stop you")
│   # evasion/anti-av/ = bypass, exclusions, heuristic avoidance
│   # impact/degrade/edr/ = kill processes, stop services
│
├── command-and-control/                 # Command & control              → MBC: Command and Control
│   ├── beacon/         # Check-in patterns                B0030
│   ├── channel/        # Communication channels
│   │   └── covert/     # Covert channels (ICMP, DNS, etc.)
│   ├── reverse-shell/  # Reverse shell patterns
│   ├── backdoor/       # Backdoor patterns
│   ├── dropper/        # Payload delivery (hostile patterns)
│   │   ├── encrypted/  # Encrypted payload droppers
│   │   ├── http/       # HTTP-based droppers
│   │   ├── loader/     # Loader patterns
│   │   ├── method/     # Dropper methods/techniques
│   │   ├── payload/    # Payload execution
│   │   ├── script/     # Script-based droppers
│   │   ├── fileless/   # Fileless droppers
│   │   ├── install-time/ # Install-time droppers
│   │   ├── silent-install/ # Silent installer patterns
│   │   └── stager/     # Multi-stage droppers
│   ├── implant/        # Implant execution patterns
│   │   ├── eval/       # Remote code execution via eval
│   │   ├── activex/    # ActiveX-based implants
│   │   └── reflective-load/ # Reflective loading
│   └── infrastructure/ # C2 infrastructure
│       └── spoofing/   # Infrastructure spoofing
│
├── collection/            # Information gathering          → MBC: Collection
│   ├── keylog/         # Keystroke logging                T1056.001
│   ├── clipboard/      # Clipboard capture                T1115
│   ├── screenshot/     # Screen capture                   T1113
│   └── audio/          # Audio capture                    T1123
│
├── credential-access/              # Credential theft               → MBC: Credential Access
│   ├── browser/        # Browser credentials              T1555.003
│   ├── system/         # OS credentials                   T1003
│   ├── network/        # Network credentials
│   └── cloud/          # Cloud service credentials
│
├── discovery/          # Environment reconnaissance     → MBC: Discovery
│   ├── system/         # System information               T1082
│   ├── network/        # Network information              T1016
│   ├── user/           # User information                 T1033
│   └── software/       # Installed software               T1518
│
├── execution/          # Code execution                 → MBC: Execution
│   ├── interpreter/    # Script/code interpreters         E1059
│   ├── dropper/        # Payload droppers
│   ├── background/     # Background execution
│   └── compile/        # Runtime compilation
│
├── exfiltration/       # Data exfiltration              → MBC: Exfiltration
│   ├── http/           # HTTP-based exfil                 T1041
│   ├── dns/            # DNS-based exfil                  T1048
│   ├── email/          # SMTP-based exfil                 T1048
│   ├── cloud/          # Cloud storage exfil
│   └── staged/         # Staged exfiltration              T1074
│
├── impact/             # Destructive operations         → MBC: Impact
│   ├── destroy/        # Data destruction                 T1485
│   ├── encrypt/        # Ransomware encryption            T1486
│   ├── dos/            # Denial of service                B0033
│   ├── deface/         # Defacement                       T1491
│   └── degrade/        # Degrade system capabilities
│       ├── edr/        # EDR/AV termination (aggressive)  T1562.001
│       └── firewall/   # Firewall manipulation/abuse
│
├── lateral-movement/            # Lateral movement               → MBC: Lateral Movement
│   ├── remote-execution/    # Remote execution                 T1021
│   ├── exploit/        # Exploitation
│   ├── pass-the-hash/  # Credential reuse                 T1550.002
│   ├── code-injection/ # Code injection attacks
│   ├── trojanize/      # Software trojanization
│   └── supply-chain/   # Supply chain attacks
│       └── dropper/    # Supply chain dropper patterns
│
├── persistence/        # Persistence mechanisms         → MBC: Persistence
│   ├── startup/        # Startup entries                  T1547
│   ├── service/        # Service installation             T1543
│   ├── cron/           # Scheduled tasks (cron)           T1053
│   ├── systemd/        # Systemd service persistence
│   ├── launchd/        # macOS LaunchDaemons/Agents
│   ├── registry/       # Windows registry persistence
│   ├── shell/          # Shell configuration files
│   ├── implant/        # Code implants
│   ├── backdoor/       # Backdoor persistence
│   └── boot/           # Boot-level persistence           T1542
│
├── privilege-escalation/            # Privilege escalation           → MBC: Privilege Escalation
│   ├── exploit/        # Local exploitation               T1068
│   ├── uac-bypass/     # Windows UAC bypass               T1548.002
│   └── abuse/          # Privilege abuse
│
└── false-positives/    # Meta: Downgrade rules to reduce false positives
    └── downgrades/     # Criticality downgrades for common patterns
```

## Tier 3: Known Entities (`well-known/`)

Specific identification of malware families and tools. Similar to MBC's [malware corpus](https://github.com/MBCProject/mbc-markdown/tree/master/xample-malware) but structured as detection rules.

### Directory Structure

```
well-known/malware/          # Malware family signatures
├── apt/                # APT/nation-state groups
├── backdoor/
├── botnet/
├── dropper/
├── exploit/
├── loader/
├── miner/              # Cryptominers
├── ransomware/
├── rat/                # Remote access trojans
├── rootkit/
├── stealer/
├── trojan/
├── virus/
└── worm/

well-known/tools/            # Legitimate tools often abused
├── offensive/          # Pentesting tools (Cobalt Strike, Metasploit)
├── sysadmin/           # Admin tools (PsExec, WMI)
└── dual-use/           # Dual-use utilities
```

## Meta Properties (`metadata/`)

File-level traits that are purely informational (no behavioral implication).

```
metadata/
├── format/             # File format (elf, pe, macho, script)
├── lang/               # Language/compiler detection
├── library/            # Library/framework detection (vue, jquery, react)
├── import/             # Dependencies/imports used by the file (auto-generated)
│   ├── python/         # Python imports (socket, requests, os.system)
│   ├── npm/            # NPM packages (axios, lodash)
│   ├── ruby/           # Ruby gems (net/http, rest-client)
│   ├── java/           # Java imports (java.net.Socket)
│   ├── go/             # Go imports
│   ├── rust/           # Rust crate imports
│   ├── c/              # C library imports
│   ├── macho/          # Mach-O dylib imports (libSystem.B.dylib)
│   ├── elf/            # ELF shared object imports (libcrypto.so)
│   └── pe/             # PE DLL imports (kernel32.dll)
├── signed/             # Code signature traits (auto-generated from binary analysis)
│   ├── platform::apple # Apple platform binary
│   ├── developer::*    # Developer ID signed (TEAM_ID as suffix)
│   ├── app-store::*    # Mac App Store signed
│   └── adhoc::unsigned # Ad-hoc signature (no identity)
├── arch/               # Architecture (x86, x64, arm, arm64)
├── sign/               # Code signing certificate detection (YAML-defined)
│   ├── certificate/    # Certificate string patterns
│   └── signature/      # Signature type patterns
├── quality/            # Code quality (logging, error handling, docs, tests)
└── hardening/          # Security hardening (sandbox, seccomp, pledge)
```

**Note:** `metadata/import/` traits are auto-generated from discovered imports - no YAML definition needed. They enable composite rules to reference specific dependencies.

**Note:** `metadata/signed/` traits are auto-generated from code signature analysis. Use `metadata/signed/platform` to match any platform-signed binary, or `metadata/signed/developer::TEAMID` for a specific developer.

**Note:** `metadata/hardening/` traits can be used in `downgrade:` rules to reduce criticality for security-conscious code.

## Trait ID Format

Trait IDs use `::` to separate directory path from trait name:

```
directory/path::trait-name
└─────┬──────┘  └────┬────┘
  directory      local ID
```

**Reference patterns:**
- `trait-name` - Matches trait in same directory (local reference)
- `micro-behaviors/communications/http` - Matches any trait in that directory (directory reference)
- `micro-behaviors/communications/http::curl-download` - Matches specific trait (exact match)

## Decision Framework

```
Is it a specific malware/tool signature?
  └─→ well-known/malware/ or well-known/tools/

Can you infer attacker intent from capability combinations?
  └─→ objectives/ (use composite rules)

Is it a single observable capability?
  └─→ micro-behaviors/
      ├── Rarely legitimate? → suspicious
      ├── Defines purpose? → notable
      └── Universal baseline? → baseline
```

## Composite Rules

Capabilities combine into objectives via composite rules:

```yaml
# objectives/command-and-control/reverse-shell/combos.yaml
composite_rules:
  - id: reverse-shell
    desc: "Reverse shell pattern"
    crit: hostile
    all:
      - id: micro-behaviors/communications/socket/create
      - id: micro-behaviors/process/fd/dup
      - id: micro-behaviors/process/create/shell
```

## Example Classifications

| Code Pattern | Tier | Path | Criticality |
|--------------|------|------|-------------|
| `socket()` call | Capability | `micro-behaviors/communications/socket/create` | notable |
| `eval()` call | Capability | `micro-behaviors/process/create/eval/dynamic` | notable |
| Process hollowing | Capability | `micro-behaviors/process/hollow` | suspicious |
| Screenshot API | Capability | `micro-behaviors/hardware/display/screenshot` | notable |
| Screenshot + timer + upload | Objective | `objectives/collection/screenshot` | suspicious |
| Reverse shell pattern | Objective | `objectives/command-and-control/reverse-shell` | hostile |
| Cobalt Strike beacon | Known | `well-known/malware/rat/cobalt-strike` | hostile |

## MBC Identifier Reference

When adding ATT&CK or MBC identifiers to traits, use these formats:
- **ATT&CK Techniques**: `T1234` or `T1234.001` (sub-technique)
- **MBC Behaviors**: `B0001` (behavior), `C0015` (micro-behavior)
- **MBC Enhanced**: `E1234` (ATT&CK technique with MBC enhancements)

See [MBC Identifiers](https://github.com/MBCProject/mbc-markdown#identifiers) for the full specification.
