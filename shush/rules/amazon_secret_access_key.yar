rule AwsSecretAccessKeyRule : AWS
{
    meta:
        name = "AWS Secret Access Key"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "aws_secret_access_key: aZAa+Amaz0nS3cr3tAcc3ssk3yTestCase=Match"
        test_match_2 = "'aws_secret_access_key' = 'aZAa+Amaz0nS3cr3tAcc3ssk3yTestCase=Match'"

    strings:
        $ = /("|')?(aws)?_?(secret)?_?(access)?_?(key)(("|')?\s*(:|=>|=)\s*("|')?)?[A-Za-z0-9\/\+=]{40}("|')?/ fullword nocase

    condition:
        any of them
}