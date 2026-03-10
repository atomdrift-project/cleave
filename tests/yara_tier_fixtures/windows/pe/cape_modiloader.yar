rule CAPE_Modiloader : FILE
{
	meta:
		description = "ModiLoader detonation shim"
		author = "kevoreilly"
		id = "64f9aa51-d668-5d40-9781-c26970acf781"
		date = "2023-10-19"
		modified = "2025-01-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/analyzer/windows/data/yara/ModiLoader.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/9e4ade71bcedfca09d26693498703c8ccd2d31ff/LICENSE"
		hash = "1f0cbf841a6bc18d632e0bc3c591266e77c99a7717a15fc4b84d3e936605761f"
		logic_hash = "9e64e0c40192cc832a1ffa7b3ac65a704596af82515d03706cd7aa1f4498f32f"
		score = 75
		quality = 70
		tags = "FILE"
		cape_options = "exclude-apis=NtAllocateVirtualMemory:NtProtectVirtualMemory"

	strings:
		$epilog1 = {81 C2 A1 03 00 00 87 D1 29 D3 33 C0 5A 59 59 64 89 10 68}
		$epilog2 = {6A 00 6A 01 8B 45 ?? 50 FF 55 ?? 33 C0 5A 59 59 64 89 10 68}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}
