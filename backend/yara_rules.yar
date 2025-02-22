import "pe"

rule Comprehensive_Malware_Detection {
    meta:
        description = "Detects potential malware based on multiple indicators"
        author = "Kripa"
        version = "2.1"

    strings:
        // Suspicious Strings
        $malware_strings = "malware"
        $suspicious_command = "cmd.exe /c"
        $base64_encoded = /UEsDBBQ[A-Za-z0-9+\/=]{5,}/
        $suspicious_url = /http:\/\/(www\.)?malicious\.(com|net|org)/

        // PE-Specific Indicators
        $encrypted_data = { 68 ?? ?? ?? ?? 8B F0 }

        // Suspicious API Calls (Fixed: Using `nocase` instead of regex)
        $VirtualAlloc = "VirtualAlloc" nocase
        $CreateProcess = "CreateProcessA" nocase
        $CreateProcessW = "CreateProcessW" nocase
        $InternetOpen = "InternetOpenA" nocase
        $InternetOpenW = "InternetOpenW" nocase
        $ShellExecute = "ShellExecuteA" nocase
        $ShellExecuteW = "ShellExecuteW" nocase
        $RunPE = "NtUnmapViewOfSection" nocase

        // Hex Patterns
        $suspicious_hex = { E8 ?? ?? ?? ?? 5D C3 }
        $xor_encryption = { 31 ?? 31 ?? }  // XOR-based encryption
        $api_hashing = { 8B ?? ?? 53 56 57 }

    condition:
        (
            // If the file is a PE executable and contains packing indicators
            pe.is_pe and (pe.section_index(".upx") >= 0 or $encrypted_data)
        ) or
        (
            // Matches any of the suspicious strings
            any of ($malware_strings, $suspicious_command, $suspicious_url, $base64_encoded)
        ) or
        (
            // Matches at least 2 suspicious API calls
            2 of ($VirtualAlloc, $CreateProcess, $CreateProcessW, $InternetOpen, $InternetOpenW, $ShellExecute, $ShellExecuteW, $RunPE)
        ) or
        (
            // Matches known hex patterns
            any of ($suspicious_hex, $xor_encryption, $api_hashing)
        )
}
