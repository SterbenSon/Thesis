rule EnhancedMalwareDetection {
    meta:
        description = "Enhanced rule to detect various forms of malware and steganographic techniques, including EICAR test file"
        author = "CS2"
        date = "2024-07-18"
    strings:
        // Detects malware signatures
        $malware_sig1 = {6A 40 68 00 30 00 00 6A 14 8D 91 D0 00 00 6A 01 8B C8 FF 91 14 01 00 00}
        $malware_sig2 = {E8 ?? ?? ?? ?? 5D 83 C4 10 B8 00 00 00 00 59}

        // detects common error message string in infected files
        $dos_mode_error = "This program cannot be run in DOS mode"

        // detects presence of Win32 executable
        $win32_string = "PE\x00\x00\x4C\x01\x14\x00\x00\x00"
        
        // Detects malware hidden in image files
        $image_malware1 = {FF D8 FF E0 ?? ?? 4A 46 49 46 00 01}  // JPEG header
        $image_malware2 = {89 50 4E 47 0D 0A 1A 0A}              // PNG header
        
        // detects steganographic payloads in exif data
        $exif_payload = "Exif\x00\x00"

        // detects multimedia file headers
        $mp4_header = {00 00 00 18 66 74 79 70 69 73 6F 6D}
        $avi_header = {52 49 46 46 ?? ?? ?? ?? 41 56 49 20}
        $mp3_header = {49 44 33}
        $wav_header = {52 49 46 46 ?? ?? ?? ?? 57 41 56 45}

        // Detects EICAR test file(used for testing)
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        // Trigger if any known malware signatures, DOS mode error string, or EICAR test file string is found
        any of ($malware_sig*, $dos_mode_error, $eicar_string) or
        // Trigger if Win32 executable is found
        $win32_string or
        // Trigger if steganographic payloads in EXIF data are found in image files
        (any of ($image_malware*) and $exif_payload) or
        // Trigger if multimedia file headers are found with any malware signature or EXIF payload
        (any of ($mp4_header, $avi_header, $mp3_header, $wav_header) and (any of ($malware_sig*, $exif_payload)))
}
