rule SquareAccessTokenRule : Square
{
    meta:
        name = "Square Access Token"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "sqOatp-5512345678901SquareToken"

    strings:
        $ = /sqOatp-[0-9A-Za-z-_]{22}/

    condition:
        any of them
}