rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Regkeycomb_Iexecutecommandcom : FILE
{
	meta:
		description = "Detects executables embedding command execution via IExecuteCommand COM object"
		author = "ditekSHen"
		id = "4bc7e6aa-1771-5c33-bc62-71072dec04cb"
		date = "2020-11-06"
		modified = "2024-06-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_suspicious.yar#L1472-L1486"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "269109f96f3fca5eacc19664b7b0c7f970131db29c47bfe1e9e67e56604bf1c1"
		score = 40
		quality = 43
		tags = "FILE"
		importance = 20

	strings:
		$r1 = "Classes\\Folder\\shell\\open\\command" ascii wide nocase
		$k1 = "DelegateExecute" ascii wide
		$s1 = "/EXEFilename \"{0}" ascii wide
		$s2 = "/WindowState \"\"" ascii wide
		$s3 = "/PriorityClass \"\"32\"\" /CommandLine \"" ascii wide
		$s4 = "/StartDirectory \"" ascii wide
		$s5 = "/RunAs" ascii wide

	condition:
		uint16( 0 ) == 0x5a4d and ( ( 1 of ( $r* ) and 1 of ( $k* ) ) or ( all of ( $s* ) ) )
}
