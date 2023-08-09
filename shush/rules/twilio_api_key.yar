rule TwilioApiKeyRule
{
    meta:
        name = "Twilio API Key"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "55123456789012345678901234F00Df00d"
        test_no_match_1 = "551234567ZZ012345678901234FzzDf00d"

    strings:
        $ = /55[0-9a-fA-F]{32}/

    condition:
        any of them
}