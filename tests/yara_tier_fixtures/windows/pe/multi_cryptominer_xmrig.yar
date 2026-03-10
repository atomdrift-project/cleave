rule SEKOIA_Miner_Win_Xmrig_Strings : FILE
{
	meta:
		description = "Detects XMRig EXE"
		author = "Sekoia.io"
		id = "35f203aa-20cd-4235-9ead-b34be14255d5"
		date = "2024-01-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/eb4a01ac59073178c241b45b6def27c8873569e3/yara_rules/miner_win_xmrig_strings.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/eb4a01ac59073178c241b45b6def27c8873569e3/LICENSE.md"
		logic_hash = "34aa0da9d3bb277927c87a3745ec9e35881682319c91141da6ff1cff7e0610d9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "XMRig "
		$ = "pool_wallet"
		$ = "IP Address currently banned"
		$ = "rigid"
		$ = "diff_current"
		$ = "shares_good"
		$ = "shares_total"
		$ = "avg_time"
		$ = "avg_time_ms"
		$ = "hashes_total"
		$ = "pool address"
		$ = "ping time"
		$ = "connection time"
		$ = "daemon+wss://"
		$ = "daemon+https://"
		$ = "daemon+http://"
		$ = "socks5://"
		$ = "stratum+ssl://"
		$ = "stratum+tcp://"

	condition:
		uint32be( 0 ) == 0x5A4D and filesize < 15MB and 7 of them
}
