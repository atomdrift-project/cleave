rule SECUINFRA_HUNT_RTF_CVE_2023_21716_Mar23 : CVE_2023_21716
{
	meta:
		description = "Detects RTF documents with an inflated fonttable. Hunting for CVE-2023-21716"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "1b76f428-f2a8-5d1d-a78c-b4a70ac4f5db"
		date = "2023-03-07"
		modified = "2023-03-07"
		reference = "https://www.bleepingcomputer.com/news/security/proof-of-concept-released-for-critical-microsoft-word-rce-bug/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Hunting/HUNT_RTF_CVE_2023_21716.yar#L3-L20"
		license_url = "N/A"
		logic_hash = "456008db725b8348f9f3851bb9aae9990e7613e1b9056846b121605c3e080297"
		score = 50
		quality = 45
		tags = "CVE-2023-21716"
		tlp = "CLEAR"

	strings:
		$fonttbl_len = /\\fonttbl\{.{1,10}\;\}(\s.{1,10}\}){10,}/

	condition:
		uint32be( 0x0 ) == 0x7B5C7274 and !fonttbl_len [ 1 ] > 256 and console.log ( "[!] Inflated fonttable with length: " , !fonttbl_len [ 1 ] )
}
