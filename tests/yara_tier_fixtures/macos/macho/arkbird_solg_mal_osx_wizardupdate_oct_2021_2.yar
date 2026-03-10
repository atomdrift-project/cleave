rule ARKBIRD_SOLG_MAL_OSX_Wizardupdate_Oct_2021_2 : FILE
{
	meta:
		description = "Detect a structure like the bash of WizardUpdate installer on OSX system"
		author = "Arkbird_SOLG"
		id = "3e48c2fa-10f4-5152-90e6-f5f8cc507103"
		date = "2021-10-22"
		modified = "2021-10-23"
		reference = "https://twitter.com/MsftSecIntel/status/1451279679059488773"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-10-23/WizardUpdate/MAL_OSX_WizardUpdate_Oct_2021_2.yara#L1-L20"
		license_url = "N/A"
		logic_hash = "99d3323e3c155be040fef3beea0a55aec9bd3178df822d5fd6530864186446ed"
		score = 75
		quality = 67
		tags = "FILE"
		hash1 = "eafacc44666901a5ea3c81a128e5dd88d0968a400d74ef1da5c2c05dc6dd7a39"
		tlp = "White"
		adversary = "-"

	strings:
		$s1 = { 24 28 65 76 61 6c 20 65 63 68 6f 20 7e 24 28 65 63 68 6f 20 24 55 53 45 52 29 29 }
		$s2 = { 69 66 20 5b 20 21 20 2d 66 20 22 24 [5-15] 22 20 5d 3b 20 74 68 65 6e }
		$s3 = { 63 75 72 6c 20 2d 2d 72 65 74 72 79 20 [2-3] 2d 66 20 22 }
		$s4 = { 78 61 74 74 72 20 2d 72 20 2d 64 20 63 6f 6d 2e 61 70 70 6c 65 2e 71 75 61 72 61 6e 74 69 6e 65 }
		$s5 = { 6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 20 2d 77 }
		$s6 = { 63 68 6f 77 6e 20 2d 52 20 24 55 53 45 52 }
		$s7 = { 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 5c 22 31 2e 30 5c 22 20 65 6e 63 6f 64 69 6e 67 3d 5c 22 55 54 46 2d 38 5c 22 3f 3e 0a 09 3c 21 44 4f 43 54 59 50 45 20 70 6c 69 73 74 20 50 55 42 4c 49 43 20 5c 22 2d 2f 2f 41 70 70 6c 65 2f 2f 44 54 44 20 50 4c 49 53 54 20 31 2e 30 2f 2f 45 4e 5c 22 20 5c 22 68 74 74 70 3a 2f 2f 77 77 77 2e 61 70 70 6c 65 2e 63 6f 6d 2f 44 54 44 73 2f 50 72 6f 70 65 72 74 79 4c 69 73 74 2d 31 2e 30 2e 64 74 64 5c 22 3e 0a 09 3c 70 6c 69 73 74 20 76 65 72 73 69 6f 6e 3d 5c 22 31 2e 30 5c 22 3e }

	condition:
		filesize > 2KB and 6 of ( $s* )
}
