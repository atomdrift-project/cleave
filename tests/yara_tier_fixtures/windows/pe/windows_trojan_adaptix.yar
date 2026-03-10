rule Windows_Trojan_Adaptix_2779784c {
    meta:
        author = "Elastic Security"
        id = "2779784c-10c6-4404-9b9d-bc6bed56b493"
        fingerprint = "d7b01850f18d6aefefada16d8a80db392fa3d68b9d64a5fbdca9ebe094fe8a4e"
        creation_date = "2025-06-23"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Adaptix"
        reference_sample = "9bbc6a711cd5ba3a1e7d8303e8c72166479a1a189ad382e2b837b1bf64c51a9d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 81 EC A8 01 00 00 48 8B 84 24 C0 01 00 00 48 C7 00 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 08 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 10 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 }
        $a2 = { 48 83 EC 58 48 8B 4C 24 70 E8 ?? ?? ?? ?? 89 44 24 38 C7 44 24 34 00 00 00 00 48 8D 54 24 34 48 8B 4C 24 70 E8 ?? ?? ?? ?? 48 89 44 24 40 48 8B 4C 24 70 E8 ?? ?? ?? ?? 66 89 44 24 30 }
    condition:
        any of them
}
