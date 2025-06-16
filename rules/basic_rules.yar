/*────────────────────────────────────────────────────────────
 Mal-Protocol | Comprehensive YARA Ruleset
 Author: ig.masio / ig.darmik
 Use: General malware detection in scripts, executables, and archives
────────────────────────────────────────────────────────────*/

rule Base64_Encoded_Payload
{
    meta:
        description = "Detects long base64 strings (may indicate encoded payloads)"
        severity = "low"
    strings:
        $b64 = /[A-Za-z0-9\/+]{80,}={0,2}/
    condition:
        $b64
}

rule Powershell_Obfuscation
{
    meta:
        description = "Detects obfuscated or suspicious PowerShell commands"
        severity = "high"
    strings:
        $s1 = "Invoke-Expression"
        $s2 = "FromBase64String"
        $s3 = "IEX"
        $s4 = "New-Object System.Net.WebClient"
        $s5 = "DownloadString"
        $s6 = "Invoke-WebRequest"
    condition:
        any of ($s*)
}

rule Python_Malware_Snippets
{
    meta:
        description = "Common patterns in Python-based malware"
        severity = "medium"
    strings:
        $p1 = "os.system('rm -rf /')"
        $p2 = "subprocess.Popen"
        $p3 = "socket.connect"
        $p4 = "requests.get"
        $p5 = "key = Fernet.generate_key()"
    condition:
        any of ($p*)
}

rule Suspicious_URL_Hosts
{
    meta:
        description = "Detects known malware delivery or C2 services"
        severity = "high"
    strings:
        $u1 = "pastebin.com"
        $u2 = "bit.ly"
        $u3 = "tinyurl.com"
        $u4 = "discordapp.com/api/webhooks"
        $u5 = "raw.githubusercontent.com"
        $u6 = "cdn.discordapp.com"
    condition:
        any of them
}

rule Windows_Persistence_Registry
{
    meta:
        description = "Common Windows persistence via registry Run keys"
        severity = "medium"
    strings:
        $r1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $r2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        $r1 or $r2
}

rule Malicious_File_Extensions_Embedded
{
    meta:
        description = "Detects references to suspicious file extensions"
        severity = "medium"
    strings:
        $e1 = ".exe"
        $e2 = ".scr"
        $e3 = ".bat"
        $e4 = ".ps1"
        $e5 = ".vbs"
        $e6 = ".dll"
    condition:
        3 of ($e*)
}

rule Encoded_JavaScript_Attack
{
    meta:
        description = "Detects hex-encoded or escaped JavaScript attack payloads"
        severity = "high"
    strings:
        $js1 = /\\x[0-9a-fA-F]{2}/
        $js2 = /%u[0-9a-fA-F]{4}/
        $js3 = "eval(unescape("
    condition:
        2 of ($js*)
}

rule Office_Macro_Indicators
{
    meta:
        description = "Detects potential malicious macros in Office documents"
        severity = "high"
    strings:
        $m1 = "AutoOpen"
        $m2 = "Document_Open"
        $m3 = "Shell"
        $m4 = "WScript.Shell"
        $m5 = "CreateObject"
    condition:
        2 of ($m*)
}

rule Keylogger_Terms
{
    meta:
        description = "Detects known keylogger-related keywords"
        severity = "high"
    strings:
        $k1 = "GetAsyncKeyState"
        $k2 = "keylog"
        $k3 = "keystroke"
        $k4 = "keyboard_hook"
    condition:
        any of ($k*)
}

rule RAT_Control_Strings
{
    meta:
        description = "Detects known remote access trojan (RAT) commands or functions"
        severity = "high"
    strings:
        $rat1 = "connect_back"
        $rat2 = "cmd.exe /c"
        $rat3 = "reverse_shell"
        $rat4 = "upload_file"
        $rat5 = "download_file"
    condition:
        2 of ($rat*)
}

rule Suspicious_Packer_Presence
{
    meta:
        description = "Detects presence of packers (UPX, ASPack, etc.)"
        severity = "medium"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $a1 = "ASPack"
    condition:
        any of them
}
