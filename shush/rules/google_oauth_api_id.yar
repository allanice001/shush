rule GoogleOuthApiIdRule : Google
{
    meta:
        name = "Google OAuth ID"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "300000001224-dhdhDHDH01010195387654testingyay.apps.googleusercontent.com"

    strings:
        $ = /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/ fullword

    condition:
        any of them
}