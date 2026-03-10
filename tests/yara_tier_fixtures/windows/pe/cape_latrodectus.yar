rule CAPE_Latrodectus : FILE
{
	meta:
		description = "Latrodectus export selection"
		author = "kevoreilly"
		id = "7c6f167a-6b76-5509-b164-306d1cd19b0f"
		date = "2024-02-26"
		modified = "2024-02-26"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/analyzer/windows/data/yara/Latrodectus.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/LICENSE"
		hash = "378d220bc863a527c2bca204daba36f10358e058df49ef088f8b1045604d9d05"
		logic_hash = "c2c9f23e287253d766425c05eb774f6e07bdcbabc259e04b723a1a87c8b91fbd"
		score = 75
		quality = 70
		tags = "FILE"
		cape_options = "export=$export"

	strings:
		$export = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 30 4C 8B 05 [4] 33 D2 C7 40 [5] 88 50 ?? 49 63 40 3C 42 8B 8C 00 88 00 00 00 85 C9 0F 84}

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}
