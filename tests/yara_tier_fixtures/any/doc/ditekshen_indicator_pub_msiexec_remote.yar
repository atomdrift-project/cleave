rule DITEKSHEN_INDICATOR_PUB_MSIEXEC_Remote : FILE
{
	meta:
		description = "detects VB-enable Microsoft Publisher files utilizing Microsoft Installer to retrieve remote files and execute them"
		author = "ditekSHen"
		id = "518db2bb-174b-54c4-b330-1e8a8e36265d"
		date = "2020-11-06"
		modified = "2024-09-06"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_office.yar#L535-L549"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "be5407e6e6e21e77f6de1d3a378996bfc6ce4326986aa03eb152e772bb495184"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Microsoft Publisher" ascii
		$s2 = "msiexec.exe" ascii
		$s3 = "Document_Open" ascii
		$s4 = "/norestart" ascii
		$s5 = "/i http" ascii
		$s6 = "Wscript.Shell" fullword ascii
		$s7 = "\\VBE6.DLL#" wide

	condition:
		uint16( 0 ) == 0xcfd0 and 6 of them
}
