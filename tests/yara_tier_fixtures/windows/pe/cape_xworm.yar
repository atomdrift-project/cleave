rule CAPE_Xworm
{
	meta:
		description = "XWorm Config Extractor"
		author = "kevoreilly"
		id = "0f55dbfb-c239-53f2-a1e0-bfa494558d6e"
		date = "2023-11-07"
		modified = "2023-11-07"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/analyzer/windows/data/yara/XWorm.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/LICENSE"
		logic_hash = "d8e103f3470e83d71cd4992b74698c0721b8a69d764fdb7a4543997b2853014a"
		score = 75
		quality = 70
		tags = ""
		cape_options = "bp0=$decrypt+11,action0=string:r10,count=1,typestring=XWorm Config"

	strings:
		$decrypt = {45 33 C0 39 09 FF 15 [4] 48 8B F0 E8 [4] 48 8B C8 48 8B D6 48 8B 00 48 8B 40 68 FF 50 ?? 90}

	condition:
		any of them
}
