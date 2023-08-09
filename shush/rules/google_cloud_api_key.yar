rule GoogleCloudApiKeyRule : Google
{
    meta:
        name = "Google Cloud API Keys"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "AIzaGoogleCloudAPIKeyAazZ09780w00tTests"

    strings:
        $ = /AIza[0-9A-Za-z-_]{35}/ fullword

    condition:
        any of them
}