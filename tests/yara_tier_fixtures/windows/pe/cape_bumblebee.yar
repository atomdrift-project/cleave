rule CAPE_Bumblebee : FILE
{
	meta:
		description = "BumbleBee Anti-VM Bypass"
		author = "enzo & kevoreilly"
		id = "85e2c9fd-86de-57c8-99ec-de2cc3996876"
		date = "2022-04-21"
		modified = "2023-02-08"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/analyzer/windows/data/yara/BumbleBee.yar#L34-L46"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/LICENSE"
		logic_hash = "0a632a0b30b28d544880eb1cfdd85e95f455c343d60f8d6922d4196ef7415961"
		score = 75
		quality = 70
		tags = "FILE"
		cape_options = "bp0=$antivm1+2,bp1=$antivm2+2,bp1=$antivm3+38,action0=jmp,action1=skip,count=0,force-sleepskip=1"

	strings:
		$antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
		$antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
		$antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15 [4] E8 [4] 84 c0}

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}
