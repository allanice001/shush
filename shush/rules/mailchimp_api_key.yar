rule MailchimpApiKeyRule
{
    meta:
        name = "MailChimp API Key"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "deadbeefdeadb33fdeadbeefdeadb33f-us90"

    strings:
        $ = /[0-9a-f]{32}-us[0-9]{1,2}/ fullword

    condition:
        any of them
}