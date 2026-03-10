rule TRELLIX_ARC_Apt_Turla_Pdb : BACKDOOR FILE
{
	meta:
		description = "Rule to detect a component of the APT Turla"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b39ac7fc-16dd-559e-8ab0-76da5cbbc719"
		date = "2017-05-31"
		modified = "2020-08-14"
		reference = "https://attack.mitre.org/groups/G0010/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_turla_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "3b8bd0a0c6069f2d27d759340721b78fd289f92e0a13965262fea4e8907af122"
		logic_hash = "d519317c936a38f189bf0de908902ec4e3e079c8c7463c8881ceb332c0a82a26"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Turla"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Workshop\\Projects\\cobra\\carbon_system\\x64\\Release\\carbon_system.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 650KB and any of them
}
