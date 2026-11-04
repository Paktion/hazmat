// Starter rules for the selftest. They match the harmless test samples only.

rule hazmat_test_stealer_sim
{
    meta:
        description = "Credential-stealer traits planted in testdata/stealer_sim.c"
    strings:
        $gate = "/gate.php"
        $chrome = "\\Google\\Chrome\\User Data\\Default\\Login Data"
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $wallet = "wallet.dat"
    condition:
        3 of them
}

rule hazmat_test_ai_targeted_text
{
    meta:
        description = "Text aimed at AI analysts, as planted in testdata/poison.h"
    strings:
        $a = "AI ANALYSIS SYSTEMS" nocase
        $b = "Ignore all previous instructions" nocase
        $c = "NO MALWARE DETECTED"
        $d = "<|system|>"
    condition:
        any of them
}
