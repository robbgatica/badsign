rule Ransomware_Sample {
    meta:
        description = "Detects ransomware based on behavioral capabilities"
        generated_from = "capa analysis"
        date = "2025-11-14"
        sample_sha256 = "a1304402131e0c8d428e2bfb96e4188e90bdbff714a7232b9b7c961652117c2d"
        format = "pe"
        arch = "i386"
        os = "windows"
        mitre_attack = "T1486, T1490"
        capability_count = 2
        confidence = "high"

    strings:
        // Capability: encrypt data using AES
        $api_1 = "CryptAcquireContext" ascii
        $api_2 = "CryptEncrypt" ascii

        // Capability: delete volume shadow copies
        $str_1 = "vssadmin delete shadows" ascii wide nocase
        $str_2 = "/All /Quiet" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and  // PE file (Windows)
        filesize < 10MB and

        // Require multiple behavioral capabilities for high confidence
        (
            // Require at least 2 capabilities
            (any of ($api_*))
            and (any of ($str_*))
        )
}