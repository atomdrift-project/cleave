rule GCTI_Sliver_Implant_32Bit
{
	meta:
		description = "Sliver 32-bit implant (with and without --debug flag at compile)"
		author = "gssincla@google.com"
		id = "6bc4d7d1-64cf-5920-8f07-54a8a7a94f26"
		date = "2022-11-18"
		modified = "2022-11-19"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		source_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/YARA/Sliver/Sliver__Implant_32bit.yara#L17-L81"
		license_url = "https://github.com/chronicle/GCTI/blob/1c5fd42b1895098527fde00c2d9757edf6b303bb/LICENSE"
		hash = "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
		logic_hash = "5b394a198f691b6777438a69d20a423798525daa84a09a0ce346eca5bb66f850"
		score = 60
		quality = 35
		tags = ""

	strings:
		$s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }
		$s_wg = { 66 81 ?? 77 67 }
		$s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
		$s_http = { 81 ?? 68 74 74 70 }
		$s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }
		$s_mtls = { 81 ?? 6D 74 6C 73 }
		$fp1 = "cloudfoundry" ascii fullword

	condition:
		4 of ( $s* ) and not 1 of ( $fp* )
}
