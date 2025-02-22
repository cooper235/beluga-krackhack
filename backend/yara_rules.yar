import "pe"

rule Comprehensive_Malware_Detection
{
    meta:
        description = "Detects potential malware based on multiple indicators"
        author = "Kripa"
        version = "2.1"

    strings:
        // Suspicious Strings
        $malware_strings = "malware"
        $suspicious_command = "cmd.exe /c"
        $base64_encoded = /UEsDBBQ[A-Za-z0-9+/=]{5,}/  // More generic base64 pattern
        $suspicious_url = /http:\/\/(www\.)?malicious\.(com|net|org)/

        // PE-Specific Indicators
        $pe_signature = { 4D 5A } // 'MZ' header (PE file)
        $packed_section = ".upx"
        $encrypted_data = { 68 ?? ?? ?? ?? 8B F0 }

        // Suspicious API Calls
        $VirtualAlloc = /(?i)VirtualAlloc/
        $CreateProcess = /(?i)CreateProcess(A|W)?/
        $InternetOpen = /(?i)InternetOpen(A|W)?/
        $ShellExecute = /(?i)ShellExecute(A|W)?/
        $RunPE = /(?i)NtUnmapViewOfSection/

        // Hex Patterns
        $suspicious_hex = { E8 ?? ?? ?? ?? 5D C3 }
        $xor_encryption = { 31 ?? 31 ?? }  // XOR-based encryption
        $api_hashing = { 8B ?? ?? 53 56 57 }

    condition:
        (
            // If the file is a PE executable
            pe.is_pe and ( $packed_section or $encrypted_data )
        ) or
        (
            // Matches any of the suspicious strings
            any of ($malware_strings, $suspicious_command, $base64_encoded, $suspicious_url)
        ) or
        (
            // Matches at least 2 suspicious API calls
            2 of ($VirtualAlloc, $CreateProcess, $InternetOpen, $ShellExecute, $RunPE)
        ) or
        (
            // Matches known hex patterns
            any of ($suspicious_hex, $xor_encryption, $api_hashing)
        )
}
