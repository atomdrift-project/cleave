# Inno Setup installer with an overlong embedded filename

This fixture is `eSignal_setup.exe` from sample SHA-256
`53594375bb74310b56a4f38a06c655f3d0b4c94bd08b40bf97c1d1614db0a3ad`.
Its Inno payload contains a 614-byte batch script whose basename uses 175
U+205F whitespace characters. The UTF-8 component is 536 bytes, which exceeds
Linux `NAME_MAX` and made the previous external extraction fail before Cleave
could analyze the script.

The script writes an HKCU Run value that invokes `mshta` and hidden PowerShell;
the PowerShell downloads and evaluates a response. The sample is for static
analysis regression only. Do not execute it or resolve its URL.

`python3 scripts/check-inno-long-member-path.py` checks that Cleave retries the
failed extraction with a shortened output name, analyzes the embedded batch
script, and reports its persistence behavior.
