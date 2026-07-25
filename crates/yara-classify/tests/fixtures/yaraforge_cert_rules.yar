// Verbatim excerpts from the YARAForge third-party bundle
// (third-party/YARAForge/yara-rules-full.yar in the traits repo), kept here so
// `test_exact_third_party_cert_examples_classify_as_pe` asserts against real
// upstream text instead of a hand-typed paraphrase. Both rules carry their
// PE signal only in `pe.signatures[...]` — no `uint16(0) == 0x4D5A` string
// literal and no `filetype` metadata — which is exactly the shape that used to
// fall through to YaraTier::Unknown. Upstream attribution and license URLs are
// preserved in each rule's metadata block; copy rules in verbatim rather than
// reformatting them, since the point is to pin the real-world formatting.
rule REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b1c650bb-b53f-5cca-8cc2-4d3498285d31"
		date = "2020-08-05"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84/yara/certificate/blocklist.yara#L10444-L10460"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84/LICENSE"
		logic_hash = "726ac44dd8109fcd0a9120f6c0673b8ecf7d5b3a4bb81976f48402e21502201a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16( 0 ) == 0x5A4D and for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . subject contains "JAWRO SP Z O O" and pe.signatures [ i ] . serial == "03:32:d5:c9:42:86:9b:dc:ab:f5:a8:26:61:97:cd:14" and 1622160000 <= pe.signatures [ i ] . not_after )
}

rule DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "32b8e28b-361f-53e5-b06c-504dd9e86ae9"
		date = "2020-11-19"
		modified = "2024-10-04"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_knownbad_certs.yar#L6405-L6416"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		hash = "dee5ca4be94a8737c85bbee27bd9d81b235fb700"
		logic_hash = "2a554105ae99de388621adefb2f53d2d0873ac3175ca2ccf00fc6a498ea2fd29"
		score = 75
		quality = 75
		tags = "FILE"
		importance = 20

	condition:
		uint16( 0 ) == 0x5a4d and for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . subject contains "IQ Trade ApS" and pe.signatures [ i ] . serial == "06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e" )
}

