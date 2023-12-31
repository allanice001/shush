rule PicaticApiKeyRule
{
    meta:
        name = "Picatic API Key"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "sk_live_123as6789o1234567890123a123a5678"
        test_match_2 = "sk_test_123as6789o1234567890123a123a5678"

    strings:
        $ = /sk_(live|test)_[0-9a-z]{32}/

    condition:
        any of them
}