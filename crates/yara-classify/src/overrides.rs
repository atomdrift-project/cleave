//! File types for rules whose names and metadata say nothing about them.

/// Curated rule-name → filetype overrides for known malware families/tools whose
/// rules carry no detectable filetype signal (no magic check, module reference,
/// naming convention, or metadata) but whose target platform is known. Matched
/// case-insensitively as a substring of the rule name. Keep entries
/// high-confidence; this is the manual escape hatch for the "impossible to infer"
/// tail. Extend as new signal-less families are audited into a filetype.
pub(super) const RULE_FILETYPE_OVERRIDES: &[(&str, &[&str])] = &[
    ("mimikatz", &["pe"]),
    ("poisonivy", &["pe"]),
    ("danabot", &["pe"]),
    ("purplefox", &["pe"]),
    ("qakbot", &["pe"]),
    ("emotet", &["pe"]),
    ("trickbot", &["pe"]),
    ("cobaltstrike", &["pe"]),
    ("icedid", &["pe"]),
    ("rhysida", &["pe"]),
    // --- audited from fallback, batch 1 (JPCERT) ---
    // exceptions first (substring first-match wins):
    ("gobratloader", &["sh"]), // GobRAT loader is a shell-script dropper
    ("stealthworker", &["pe", "elf"]), // Go brute-forcer, Windows + Linux
    ("kaos_golang", &["pe", "elf", "macho"]), // Lazarus Go, cross-compiled
    ("3proxy", &["pe", "elf"]), // cross-platform proxy tool
    // groups + Windows PE families:
    ("apt10", &["pe"]),
    ("blacktech", &["pe"]),
    ("remcos", &["pe"]),
    ("tokyox", &["pe"]),
    ("agenttesla", &["pe"]),
    ("asyncrat", &["pe"]),
    ("azorult", &["pe"]),
    ("bebloh", &["pe"]),
    ("ottercookie", &["pe"]),
    ("dragonok", &["pe"]),
    ("formbook", &["pe"]),
    ("hawkeye", &["pe"]),
    ("comebacker", &["pe"]),
    ("torisma", &["pe"]),
    ("lokibot", &["pe"]),
    ("nanocore", &["pe"]),
    ("netwire", &["pe"]),
    ("njrat", &["pe"]),
    ("phantomstealer", &["pe"]),
    ("plugx", &["pe"]),
    ("quasar", &["pe"]),
    ("snakekeylogger", &["pe"]),
    ("redleaves", &["pe"]),
    ("powerharbor", &["pe"]),
    ("donut", &["pe"]),
    // --- audited from fallback, batch 2 (YARAForge) ---
    // non-PE / cross-platform (specific):
    ("darkradiation", &["sh"]),           // Bash ransomware (Linux/ESXi)
    ("envyscout", &["html", "js"]),       // HTML-smuggling dropper
    ("manjusaka", &["pe", "elf"]),        // Go/Rust C2, cross-platform
    ("liblzma", &["elf"]),                // XZ/liblzma backdoor (Linux .so)
    ("lambda_malware", &["elf"]),         // AWS Lambda malware (Linux)
    ("babuk", &["pe", "elf"]),            // ransomware, Windows + ESXi/Linux
    ("blackcat", &["pe", "elf"]),         // ALPHV, Windows + Linux ESXi
    ("blackberry_snake", &["pe", "elf"]), // Turla Snake, cross-platform
    ("ssh_mitm", &["py"]),                // jtesta ssh-mitm (Python)
    ("abptts", &["php", "aspx", "jsp"]),  // NCC ABPTTS webshell
    ("masscan", &["pe", "elf"]),          // C scanner, Windows + Linux
    ("pupy", &["pe", "elf", "py"]),       // Pupy RAT, cross-platform
    // Windows PE families:
    ("adaptixbeacon", &["pe"]),
    ("aurastealer", &["pe"]),
    ("bruteratel", &["pe"]),
    ("bumblebee", &["pe"]),
    ("dcrat", &["pe"]),
    ("koiloader", &["pe"]),
    ("latrodectus", &["pe"]),
    ("oyster", &["pe"]),
    ("rcsession", &["pe"]),
    ("rhadamanthys", &["pe"]),
    ("smokeloader", &["pe"]),
    ("xenorat", &["pe"]),
    ("xworm", &["pe"]),
    ("kingrat", &["pe"]),
    ("rozena", &["pe"]),
    ("headertip", &["pe"]),
    ("underminer", &["pe"]),
    ("kwampirs", &["pe"]),
    ("orangeworm", &["pe"]),
    ("nazar", &["pe"]),
    ("alkhal", &["pe"]),
    ("alumnilocker", &["pe"]),
    // --- audited from fallback, batch 3 (YARAForge) ---
    // non-PE / cross-platform:
    ("kobalos", &["elf"]),                       // Linux/Unix HPC malware
    ("mozi_", &["elf"]),                         // Mozi IoT botnet (Linux)
    ("sliver", &["pe", "elf", "macho"]),         // Sliver Go C2, cross-platform
    ("masepie", &["py"]),                        // APT28 Python backdoor
    ("gadgettojscript", &["js"]),                // generates JScript droppers
    ("javadispcash", &["jar", "class", "java"]), // Java ATM malware
    ("fenixbotnet", &["js"]),                    // JScript-encoded (.jse)
    ("mintsloader", &["js", "ps1"]),             // JS -> PowerShell loader
    // Windows PE families:
    ("potao", &["pe"]),
    ("prikormka", &["pe"]),
    ("sparklinggoblin", &["pe"]),
    ("stantinko", &["pe"]),
    ("redflare", &["pe"]),
    ("allasenha", &["pe"]),
    ("ateraagent", &["pe"]),
    ("muddywater", &["pe"]),
    ("ursnif", &["pe"]),
    ("xxmm", &["pe"]),
    ("armadill", &["pe"]),
    ("lavender", &["pe"]),
    ("tsc_loader", &["pe"]),
    ("zark20rk", &["pe"]),
    ("aurorastealer", &["pe"]),
    ("ducktail", &["pe"]),
    ("meduzastealer", &["pe"]),
    ("pswstealer", &["pe"]),
    ("purecrypter", &["pe"]),
    // --- audited from fallback, batch 4 (YARAForge: RussianPanda / SEKOIA APT) ---
    // non-PE / cross-platform (specific names to avoid clobbering PE siblings):
    ("buhtrap_maldocx", &["doc", "docx"]),
    ("uac0063_malicious_doc", &["doc", "docx"]),
    ("gamaredon_lnks", &["lnk"]),
    ("redhotel_maliciouslnk", &["lnk"]),
    ("sharpext", &["js"]),
    ("scanbox", &["js"]),
    ("tortoiseshell_wateringhole", &["js"]),
    ("powerexchange", &["ps1"]),
    ("powergap", &["ps1"]),
    ("sload", &["ps1"]),
    ("awfulshred", &["sh"]), // Sandworm Bash wiper
    ("orcshred", &["sh"]),   // Sandworm Bash wiper
    ("upstyle", &["py"]),    // GlobalProtect backdoor (Python)
    ("pondrat", &["pe", "elf", "macho"]),
    ("blueshell", &["pe", "elf", "macho"]),
    ("sparkrat", &["pe", "elf", "macho"]),
    ("stripedfly", &["pe", "elf"]),
    // Windows PE families:
    ("solardropper", &["pe"]),
    ("supperbackdoor", &["pe"]),
    ("whitesnakestealer", &["pe"]),
    ("adsync_creddump", &["pe"]),
    ("quarterrig", &["pe"]),
    ("cloudatlas", &["pe"]),
    ("kamikakabot", &["pe"]),
    ("konni", &["pe"]),
    ("blindingcan", &["pe"]),
    ("micdown", &["pe"]),
    ("mustangpanda", &["pe"]),
    ("toneshell", &["pe"]),
    ("tortoiseshell_imaploader", &["pe"]),
    ("dangerous_password", &["pe"]),
    ("hrserv", &["pe"]),
    ("darkriver", &["pe"]),
    // --- audited from fallback, batch 5 (YARAForge: SEKOIA + SIGNATURE_BASE APT) ---
    // non-PE / cross-platform:
    ("sharpshooter", &["js", "vbs", "hta"]), // scriptlet generator (13 rules)
    ("empire_onedrive", &["ps1"]),           // PowerShell Empire stager
    ("guerrilla_lemongroup", &["apk", "dex"]),
    ("strongpity_mobile", &["apk", "dex"]),
    ("drovorub", &["elf"]), // APT28 Linux rootkit
    ("ipmipwner", &["py"]),
    ("pivotnacci", &["py"]),
    ("enum4linux", &["pl", "py"]),
    ("bypassgodzilla", &["jsp", "php", "aspx"]),
    ("sharepoint_cve_2025_53770", &["aspx"]),
    ("luckymouse_sysupdate", &["pe", "elf"]),
    ("xiebroc2", &["pe", "elf"]),
    ("water_sigbin", &["pe", "elf"]),
    ("apt28_generic_poco", &["pe", "elf"]),
    ("softether", &["pe", "elf", "macho"]),
    // Windows PE families:
    ("evilnum", &["pe"]),
    ("guloader", &["pe"]),
    ("tarrask", &["pe"]),
    ("venom_admin", &["pe"]),
    ("storm_1811", &["pe"]),
    ("ladon", &["pe"]),
    ("nobelium", &["pe"]),
    ("cn_group_loader", &["pe"]),
    ("crywiper", &["pe"]),
    // --- audited from fallback, batch 6 (YARAForge: SIGNATURE_BASE APT) ---
    // non-PE / cross-platform:
    ("3cx_malicious", &["pe", "macho"]), // 3CX supply chain (Win + macOS)
    ("lockbit", &["pe", "elf"]),         // ransomware, Windows + ESXi/Linux
    ("moonlightmaze", &["elf"]),         // vintage Unix toolkit
    ("armitage", &["jar", "class", "java"]),
    ("cactustorch", &["js", "vbs", "hta"]),
    // Windows PE families:
    ("whispergate", &["pe"]),
    ("wmrat", &["pe"]),
    ("ke3chang", &["pe"]),
    ("hoplight", &["pe"]),
    ("veiledsignal", &["pe"]),
    ("putterpanda", &["pe"]),
    ("project_sauron", &["pe"]),
    ("projectsauron", &["pe"]),
    ("proxy_malware_packed", &["pe"]),
    ("thrip", &["pe"]),
    ("hermetic_wiper", &["pe"]),
    ("bemstour", &["pe"]),
    ("equation", &["pe"]),
    ("beastdoor", &["pe"]),
    ("bernhardpos", &["pe"]),
    ("bypassuacdll", &["pe"]),
    // --- audited from fallback, batch 7 (YARAForge: SIGNATURE_BASE C-E) ---
    // non-PE / cross-platform:
    ("chinachopper", &["aspx", "php", "jsp"]), // China Chopper webshell
    ("mafix", &["elf"]),                       // Linux rootkit
    ("mempodipper", &["elf"]),                 // Linux LPE
    ("coinminer", &["pe", "elf"]),
    // Windows PE families/tools:
    ("cn_gui_scanner", &["pe"]),
    ("milkt_scanner", &["pe"]),
    ("scanport_portscanner", &["pe"]),
    ("ssport_portscanner", &["pe"]),
    ("cn_honker_portrecall", &["pe"]),
    ("cn_packed_scanner", &["pe"]),
    ("cn_tools_temp", &["pe"]),
    ("chinese_hacktool", &["pe"]),
    ("codoso", &["pe"]),
    ("deeppanda", &["pe"]),
    ("dexter_malware", &["pe"]),
    ("deploysmalwareviasideloading", &["pe"]),
    ("duqu", &["pe"]),
    // --- audited from fallback, batch 8 (YARAForge: EQGRP / Shadow Brokers Unix tooling) ---
    ("fvey_shadowbroker_user_tool", &["elf"]), // Unix/Solaris implants
    ("nopen", &["elf"]),                       // NOPEN Unix backdoor
    ("strifeworld", &["elf"]),                 // passive collection tool
    ("eqgrp_networkprofiler", &["elf"]),
    ("eqgrp_sniffer", &["elf"]),
    ("eqgrp_tunnel_state", &["elf"]),
    ("eqgrp_userscript", &["sh"]),
    ("opscript", &["sh"]), // operator scripts
    // --- audited from fallback, batch 9 (YARAForge: SIGNATURE_BASE F-I, HKTL block) ---
    // non-PE / cross-platform (sqlmap_backdoor before sqlmap):
    ("hktl_dsniff", &["elf"]),
    ("hktl_frp", &["pe", "elf", "macho"]),
    ("pnscan", &["elf"]),
    ("hktl_nfs", &["elf"]),
    ("lazagne", &["py", "pe"]),
    ("natbypass", &["pe", "elf"]),
    ("fscan_portscanner", &["pe", "elf"]),
    ("powerkatz", &["pe", "ps1"]),
    ("powersploit", &["ps1"]),
    ("shellpop", &["sh"]),
    ("sqlmap_backdoor", &["php", "asp", "jsp"]),
    ("sqlmap", &["py"]),
    // Windows PE families:
    ("fourelementsword", &["pe"]),
    ("ghostdragon", &["pe"]),
    ("glassrat", &["pe"]),
    ("golddragon", &["pe"]),
    ("greenbug", &["pe"]),
    ("meterpreter_inmemory", &["pe"]),
    ("edge_saved_passwords_dumper", &["pe"]),
    ("redmimicry", &["pe"]),
    ("panda_tesksd", &["pe"]),
    ("hiddencobra", &["pe"]),
    ("hyperbro", &["pe"]),
    // --- audited from fallback, batch 10 (YARAForge: SIGNATURE_BASE Invoke/MAL) ---
    ("invoke_smbexec", &["ps1"]),
    ("invoke_wmiexec", &["ps1"]),
    ("aspxspy", &["aspx"]),
    ("loki2crypto", &["elf"]),    // Loki2 Unix ICMP backdoor
    ("andariel", &["pe", "elf"]), // NK Andariel (Go, Win + Linux)
    ("jrat", &["jar", "class", "java"]),
    ("mobileiron_mi_war", &["jar"]), // Ivanti EPMM WAR
    ("litellm", &["py"]),            // LiteLLM supply-chain
    ("lazarus_dec_17", &["pe"]),
    ("nk_win_dtrack", &["pe"]),
    ("tiger_rat", &["pe"]),
    ("burningumbrella", &["pe"]),
    ("chrysalis", &["pe"]),
    ("bricksteal", &["pe"]),
    ("grace_dec22", &["pe"]),
    ("katz_stealer", &["pe"]),
    ("conticrypter", &["pe"]),
    ("sednit_delphidownloader", &["pe"]),
    ("thinspool", &["pe"]),
    ("apt15_generic", &["pe"]),
    ("sakula", &["pe"]),
    ("shellcode_loader_apr23", &["pe"]),
    // --- audited from fallback, batch 11 (JPCERT leftovers + YARAForge A-D) ---
    // non-PE / cross-platform:
    ("sysrvbot", &["pe", "elf"]),          // Linux miner botnet (Go)
    ("gokcpdoor", &["pe", "elf"]),         // Tick Go backdoor
    ("kittipongk_cryptominer", &["elf"]),  // Unix XMRig/xmr-stak
    ("waterpamola", &["js", "php"]),       // web-skimming (EC-CUBE)
    ("tool_frp", &["pe", "elf", "macho"]), // fast reverse proxy
    ("cve_2021_40444", &["doc", "docx", "rtf"]), // MSHTML in Office docs
    // Windows PE families:
    ("lazarus_vsingle", &["pe"]),
    ("lazarus_httpbot", &["pe"]),
    ("lazarus_loader_thumbsdb", &["pe"]),
    ("lazarus_packer_code", &["pe"]),
    ("lazarus_simplecurl", &["pe"]),
    ("lazarus_tool_smbscan", &["pe"]),
    ("stonemite", &["pe"]),
    ("daserf", &["pe"]),
    ("datper", &["pe"]),
    ("gofarer", &["pe"]),
    ("dalbot", &["pe"]),
    ("tick_skysea", &["pe"]),
    ("veletrix", &["pe"]),
    ("trishul_rat", &["pe"]),
    ("bookworm", &["pe"]),
    ("chimera_sept", &["pe"]),
    ("apt_c_61", &["pe"]),
    ("heinote", &["pe"]),
    ("vault7_sig", &["pe"]),
    ("unk_dev_0322", &["pe"]),
    ("direct_syscall_shellcode", &["pe"]),
    ("indicator_kb_id_ransomware", &["pe"]), // DITEKSHEN ransomware family
    // --- audited from fallback, batch 12 (elastic/bartblaze family clusters) ---
    ("linpeas", &["sh", "bash"]), // Linux privesc audit script (18 rules)
    ("mythic", &["pe", "elf", "macho"]), // Mythic C2, multi-language agents
    ("gosar", &["pe", "elf"]),    // Go Quasar
    ("finaldraft", &["pe", "elf"]), // REF7707, Windows + Linux
    ("hacktool_nps", &["pe", "elf"]), // nps Go proxy
    // --- audited from fallback, batch 13 (SIGNATURE_BASE M-R) ---
    ("mimipenguin", &["elf", "sh", "py"]), // Linux cred dumper
    ("msfpayloads", &["pe", "elf", "macho"]),
    ("ncrack", &["pe", "elf"]),
    ("pscan_portscan", &["pe", "elf"]),
    ("p0wned", &["pe", "ps1"]), // .NET + PowerShell toolkit
    ("pua_crypto_mining", &["pe", "elf"]),
    ("pua_cryptominer", &["pe", "elf"]),
    ("exe2hex", &["bat", "ps1"]),
    ("nautilus_forensic", &["pe"]),
    ("octowave", &["pe"]),
    ("oilrig", &["pe"]),
    ("apt_zerot", &["pe"]),
    ("malumpos", &["pe"]),
    ("powershdll", &["pe"]),
    ("pwdump", &["pe"]),
    ("blackshades", &["pe"]),
    // --- audited from fallback, batch 14 (SIGNATURE_BASE R-S) ---
    ("gobfuscate", &["pe", "elf"]),       // Go obfuscator output
    ("lnx_base64", &["sh"]),              // Linux base64 download/exec
    ("poolrat", &["pe", "elf", "macho"]), // Lazarus, multi-platform
    ("rat_clientmesh", &["pe"]),
    ("regin", &["pe"]),
    ("remcom_remote", &["pe"]),
    ("remsec", &["pe"]),
    ("stuxshop", &["pe"]),
    ("win32dll_string", &["pe"]),
    ("shimrat", &["pe"]),
    ("sig_238", &["pe"]),
    ("skeleton_key", &["pe"]),
    // --- audited from fallback, batch 15 (SIGNATURE_BASE S-Z + TRELLIX) ---
    ("ysoserial", &["jar", "class", "java"]), // Java deserialization payloads
    ("ms16_032", &["ps1"]),                   // PowerShell exploit PoC
    ("stegokatz", &["pe"]),
    ("streamex", &["pe"]),
    ("ta17_293a_malware", &["pe"]),
    ("ta459", &["pe"]),
    ("threatgroup3390", &["pe"]),
    ("tzddos", &["pe"]),
    ("waterbear", &["pe"]),
    ("waterbug", &["pe"]),
    ("_wce", &["pe"]),
    ("winnti_dropper", &["pe"]),
    ("woolengoldfish", &["pe"]),
    ("zxshell", &["pe"]),
    ("acidbox", &["pe"]),
    ("backdoorfckg", &["pe"]),
    ("cryptolocker", &["pe"]),
    ("cyaxsharp", &["pe"]),
    ("masslogger", &["pe"]),
    // --- audited from fallback, batch 16 (TRELLIX/ESET/Telekom) ---
    ("ebury", &["elf"]),                 // Linux OpenSSH backdoor
    ("ransom_darkside", &["pe", "elf"]), // Windows + ESXi/Linux
    ("eset_dino", &["pe"]),
    ("vatet", &["pe"]),
    ("ransom_makop", &["pe"]),
    ("ransom_suncrypt", &["pe"]),
    // --- audited from fallback, batch 17 (VOLEXITY/WITHSECURELABS/bartblaze families) ---
    // non-PE / cross-platform:
    ("sodinokobi", &["pe", "elf"]), // REvil/Sodinokibi (Win + ESXi)
    ("brickstorm", &["pe", "elf"]), // Go backdoor
    ("reversessh", &["pe", "elf"]), // Go reverse SSH
    ("discordc2", &["pe", "elf"]),  // Go Discord C2
    ("pantegana", &["pe", "elf", "macho"]), // Go RAT
    ("adaptix_beacon", &["pe", "elf"]),
    ("lookvaljs", &["js"]),
    ("lookvalps", &["ps1"]),
    ("grimresource", &["xml"]), // MSC (XML) technique
    // Windows PE families:
    ("shellcode_mykins", &["pe"]),
    ("shifu", &["pe"]),
    ("ico_uta0040", &["pe"]),
    ("reloadext", &["pe"]),
    ("daylight", &["pe"]),
    ("phantomrelay", &["pe"]),
    ("legionrelay", &["pe"]),
    ("greyvibe", &["pe"]),
    ("teasoup", &["pe"]),
    ("autumn_backdoor", &["pe"]),
    ("confucius_b", &["pe"]),
    ("stormdns", &["pe"]),
    ("andromeda", &["pe"]),
    ("arechclient", &["pe"]),
    ("avemaria", &["pe"]),
    ("bazarbackdoor", &["pe"]),
    ("bazarloader", &["pe"]),
    ("ganelp", &["pe"]),
    ("parallax", &["pe"]),
    ("redline", &["pe"]),
    ("saintbot", &["pe"]),
    ("shinnyshield", &["pe"]),
    ("systembc", &["pe"]),
    ("unk_br_banker", &["pe"]),
    ("unk_crime_downloader", &["pe"]),
    ("zloader", &["pe"]),
    ("costura", &["pe"]),
    ("enigmastub", &["pe"]),
    ("minitor", &["pe"]),
    ("vmprotectstub", &["pe"]),
    ("adfind", &["pe"]),
    ("createminidump", &["pe"]),
];
