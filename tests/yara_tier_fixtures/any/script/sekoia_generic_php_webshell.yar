rule SEKOIA_Generic_Php_Webshell : FILE
{
	meta:
		description = "Detects generic webshell"
		author = "Sekoia.io"
		id = "415a96bd-11a4-40e7-8335-ac1f1a99d17c"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/eb4a01ac59073178c241b45b6def27c8873569e3/yara_rules/generic_php_webshell.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/eb4a01ac59073178c241b45b6def27c8873569e3/LICENSE.md"
		logic_hash = "617264a785b8e9e87a39e12d7b72963d94e0686a174716347369fe71ab7a78af"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "system($_POST['a']);"

	condition:
		all of them and filesize < 500
}
