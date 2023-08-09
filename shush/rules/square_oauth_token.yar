rule SquareOauthTokenRule : Square
{
    meta:
        name = "Square OAuth Token"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "sq0csp-551234567890Square-Token_5512345678901Square"

    strings:
        $ = /sq0csp-[0-9A-Za-z-_]{43}/

    condition:
        any of them
}