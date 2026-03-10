rule IcedID_init_loader
{
    meta:
        id = "1GXBmGKG0zu5DhEKiZK0Kx"
        fingerprint = "b86460e97101c23cf11ff9fb43f6fcdce444fcfa301b1308c2f4d6aa2f01986a"
        version = "1.0"
        creation_date = "2021-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID (stage 1 and 2, initial loaders)."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"

    strings:
        $s1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" ascii wide
        $s2 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii wide
        $s3 = "/image/?id=%0.2X%0.8X%0.8X%s" ascii wide
        $x1 = "; _gat=" ascii wide
        $x2 = "; _ga=" ascii wide
        $x3 = "; _u=" ascii wide
        $x4 = "; __io=" ascii wide
        $x5 = "; _gid=" ascii wide
        $x6 = "Cookie: __gads=" ascii wide

    condition:
        int16(0) == 0x5a4d
        and 2 of ($s*) or 3 of ($x*)
}
