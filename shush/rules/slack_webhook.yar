rule SlackWebhookRule : Slack
{
    meta:
        name = "Slack Webhook"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

    strings:
        $ = /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/ nocase

    condition:
        any of them
}