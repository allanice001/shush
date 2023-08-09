rule AmazonMwsRule : AWS
{
    meta:
        name = "AWS MWS"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "amzn.mws.123a5678-d34d-b33f-f00d-f00df00df00d"

    strings:
        $ = /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ fullword nocase

    condition:
        any of them
}