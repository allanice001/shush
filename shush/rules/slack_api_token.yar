rule SlackTokenRule : Slack
{
    meta:
        name = "Slack Token"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "xoxp-333333333578-11111111191-811111111114-efffffffffffff1111111fff11ffff1b"

    strings:
        $ = /(xox[pboa]\-[0-9]{12}\-[0-9]{11}\-[0-9]{12}\-[a-z0-9]{32})/ nocase

    condition:
        any of them
}