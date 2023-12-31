rule TwitterApiKeyRule
{
    meta:
        name = "Twitter API Key"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "101-811111111114efffffffff1111111fff11ffff1b"

    strings:
        $ = /[1-9][0-9]+\-[0-9a-zA-Z]{40}/

    condition:
        any of them
}