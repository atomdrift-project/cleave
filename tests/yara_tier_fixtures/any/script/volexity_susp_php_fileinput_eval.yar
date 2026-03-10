rule VOLEXITY_Susp_Php_Fileinput_Eval : FILE
{
	meta:
		description = "Rule designed to detect PHP files which use file_get_contents() and then shortly afterwards use an eval statement."
		author = "threatintel@volexity.com"
		id = "3e311677-22ea-5e5f-bdc6-dd67033d25a6"
		date = "2021-06-16"
		modified = "2024-12-12"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L159-L182"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "de376bfdfa5b6244c414454cb5d43d29e3dd75e049389f0c430c160f9d198965"
		score = 65
		quality = 80
		tags = "FILE"
		hash1 = "1a34c43611ee310c16acc383c10a7b8b41578c19ee85716b14ac5adbf0a13bd5"
		hash2 = "6e8874c756c009c63f715a44ca72d0cb31dc25d87d7df6ca2830fe8330580342"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5581
		version = 5

	strings:
		$s1 = "file_get_contents(\"php://input\")"
		$s2 = "eval("

	condition:
		$s2 in ( @s1 [ 1 ] .. ( @s1 [ 1 ] + 512 ) )
}
