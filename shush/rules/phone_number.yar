rule PhoneNumberRule
{
    meta:
        name = "Phone Number"
        author = "security dragon"
        date = "2023-04-25"

        /* Test Cases */
        test_match_1 = "Give them a call at 555-867-5309."

    strings:
        $1 = /[0-9]{3}-[0-9]{3}-[0-9]{4}/
        $2 = /\([0-9]{3}\) [0-9]{3}-[0-9]{4}/

    condition:
        any of them
}