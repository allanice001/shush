rule GitLabPatApiTokenRule : GitLab
{
    meta:
        name = "GitLab PAT API-style"
        author = "security dragon"
        date = "2023-04-25"
        test_match_1 = "private-token:ab123mr980pas453201s"

    strings:
        $ = /private.token\s*(:|=>|=)\s*[a-z0-9_]{20}/ fullword ascii

    condition:
        any of them
}