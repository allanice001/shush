rule ShodanApiKeyRule
{
    meta:
        name = "Shodan API Key"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "shodan: deadbeefdeadb33fdeadbeefdeadb33f"
        test_match_2 = "shodan = 'deadbeefdeadb33fdeadbeefdeadb33f'"

    strings:
        $quoted = /("|')?shodan(.*)(("|')?\s*(:|=>|=)\s*("|'))[0-9a-zA-Z]{32}("|')/ nocase
        $unquoted = /shodan(.*)(\s*(:|=>|=)\s*)[0-9a-zA-Z]{32}/ nocase

    condition:
        $quoted or $unquoted
}