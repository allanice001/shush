rule FacebookAccessTokenRule
{
    meta:
        name = "Facebook Access Token"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "EAACEdEose0cBATestAccessCodeForFaceb00k"

    strings:
        $ = /EAACEdEose0cBA[0-9A-Za-z]+/ fullword

    condition:
        any of them
}