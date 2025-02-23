import "pe"
import "math"

rule Comprehensive_Malware_Detection {
    meta:
        description = "Detects potential malware based on multiple indicators"
        author = "Kripa"
        version = "2.2"

    strings:
        // Suspicious Strings
        $malware_strings = "malware" nocase
        $suspicious_command = "cmd.exe /c" nocase
        $powershell_command = "powershell.exe -nop -exec bypass" nocase
        $base64_encoded = /UEsDBBQ[A-Za-z0-9+\/=]{5,}/
        $suspicious_url = /http:\/\/(www\.)?malicious\.(com|net|org)/
        $obfuscated_code = /eval\(.*\)/
        $malware_family = "Emotet" nocase

        // PE-Specific Indicators
        $encrypted_data = { 68 ?? ?? ?? ?? 8B F0 }
        $code_injection = { 8B 45 FC 8B 40 04 89 45 F8 }
        $process_hollowing = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 }
        $anti_debugging = { 0F 31 C3 }

        // Suspicious API Calls
        $VirtualAlloc = "VirtualAlloc" nocase
        $CreateProcess = "CreateProcessA" nocase
        $CreateProcessW = "CreateProcessW" nocase
        $InternetOpen = "InternetOpenA" nocase
        $InternetOpenW = "InternetOpenW" nocase
        $ShellExecute = "ShellExecuteA" nocase
        $ShellExecuteW = "ShellExecuteW" nocase
        $RunPE = "NtUnmapViewOfSection" nocase
        $LoadLibrary = "LoadLibraryA" nocase
        $GetProcAddress = "GetProcAddress" nocase
        $WriteProcessMemory = "WriteProcessMemory" nocase
        $RegSetValue = "RegSetValueExA" nocase

        // Hex Patterns
        $suspicious_hex = { E8 ?? ?? ?? ?? 5D C3 }
        $xor_encryption = { 31 ?? 31 ?? }
        $api_hashing = { 8B ?? ?? 53 56 57 }

    condition:
        (
            // If the file is a PE executable and contains packing indicators
            pe.is_pe and (pe.section_index(".upx") >= 0 or $encrypted_data)
        ) or
        (
            // Matches any of the suspicious strings
            any of ($malware_strings, $suspicious_command, $powershell_command, $suspicious_url, $base64_encoded, $obfuscated_code, $malware_family)
        ) or
        (
            // Matches at least 2 suspicious API calls
            2 of ($VirtualAlloc, $CreateProcess, $CreateProcessW, $InternetOpen, $InternetOpenW, $ShellExecute, $ShellExecuteW, $RunPE, $LoadLibrary, $GetProcAddress, $WriteProcessMemory, $RegSetValue)
        ) or
        (
            // Matches known hex patterns
            any of ($suspicious_hex, $xor_encryption, $api_hashing, $code_injection, $process_hollowing, $anti_debugging)
        )
}

rule PDF_Malware_Detection {
    meta:
        description = "Detects malicious PDF files"
        author = "Kripa"
        version = "1.0"

    strings:
        $pdf_javascript = "/JavaScript"
        $pdf_launch_action = "/Launch"
        $pdf_embedded_file = "/EmbeddedFile"
        $pdf_malicious_url = /http:\/\/(www\.)?malicious\.(com|net|org)/

    condition:
        any of them
}

rule DOCX_Malware_Detection {
    meta:
        description = "Detects malicious DOCX files"
        author = "Kripa"
        version = "1.0"

    strings:
        $macro_string = "Macros"
        $vba_code = "Sub AutoOpen()"
        $suspicious_ole = "OLE2Link"

    condition:
        any of them
}

rule High_Entropy_Section {
    meta:
        description = "Detects high-entropy sections in PE files"
        author = "Kripa"
        version = "1.0"

    condition:
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0
        )
}

rule Emotet_Malware {
    meta:
        description = "Detects Emotet malware"
        author = "Kripa"
        version = "1.0"

    strings:
        $emotet_string1 = "Emotet" nocase
        $emotet_string2 = "C2_Server" nocase
        $emotet_hex = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 }

    condition:
        any of them
}
