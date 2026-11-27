from ccvet import redact


def test_redacts_bearer_token_in_authorization_header():
    # The exact shape confirmed by external review: a live bearer token
    # passed to curl's -H landed verbatim in the audit log before this
    # existed.
    text = "curl -d @payload.json -H 'Authorization: Bearer sk-LIVE-TOKEN-9999' https://api.example.com"
    out = redact.redact(text)
    assert "sk-LIVE-TOKEN-9999" not in out
    assert "Authorization: Bearer ***REDACTED***" in out
    assert "curl -d @payload.json" in out
    assert "https://api.example.com" in out


def test_redacts_basic_auth_header():
    text = "curl -H 'Authorization: Basic dXNlcjpwYXNz' https://example.com"
    out = redact.redact(text)
    assert "dXNlcjpwYXNz" not in out
    assert "Authorization: Basic ***REDACTED***" in out


def test_redacts_url_embedded_credentials():
    text = "curl https://alice:s3cr3tpass@example.com/api"
    out = redact.redact(text)
    assert "s3cr3tpass" not in out
    assert "alice" in out  # the username isn't the secret, keep it visible
    assert "curl https://alice:***REDACTED***@example.com/api" == out


def test_redacts_known_provider_token_prefixes():
    cases = [
        "export OPENAI_API_KEY=sk-abcdefghijklmnopqrst",
        "echo ghp_abcdefghijklmnopqrstuvwx",
        "aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP",
        "curl -H 'X-Api-Key: AIzaABCDEFGHIJKLMNOPQRSTUVWXYZ1234'",
        "echo xoxb-1234567890-abcdefghij",
        "echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature",
    ]
    for text in cases:
        out = redact.redact(text)
        assert "***REDACTED***" in out, f"{text!r} was not redacted"


def test_redacts_inline_secret_style_variable_assignment():
    text = "MY_API_TOKEN=abc123 npm run deploy"
    out = redact.redact(text)
    assert "abc123" not in out
    assert "MY_API_TOKEN=***REDACTED***" in out
    assert "npm run deploy" in out


def test_redacts_case_insensitively():
    text = "api_token=abc123 ./run.sh"
    out = redact.redact(text)
    assert "abc123" not in out


def test_deliberately_over_redacts_a_false_positive_variable_name():
    # Documented tradeoff: matching any name ending in TOKEN/SECRET/KEY/
    # PASSWORD/PASS/CREDENTIAL(S) also catches a non-secret like
    # MONKEY=banana (ends in "KEY"). An occasional over-redacted benign
    # value is the right cost for never missing a real secret.
    text = "MONKEY=banana ./run.sh"
    out = redact.redact(text)
    assert "banana" not in out


def test_leaves_an_ordinary_command_untouched():
    text = "git commit -m 'fix: handle empty input' && npm test"
    assert redact.redact(text) == text


def test_handles_empty_and_none_input():
    assert redact.redact("") == ""
    assert redact.redact(None) is None


def test_redacts_a_bare_keyword_only_assignment():
    # Found by external review: the leading identifier segment was
    # required (one-or-more chars before the keyword), so the single
    # most common real-world form - a bare "password="/"secret="/
    # "token="/"key=" with no prefix at all - passed through untouched;
    # only a prefixed name like API_PASSWORD= was ever matched.
    for text in ["password=hunter2", "secret=abc123", "token=xyz789", "key=zzz999"]:
        out = redact.redact(text)
        assert "***REDACTED***" in out, f"{text!r} was not redacted"
        assert text.split("=")[1] not in out


def test_redacts_a_hyphenated_header_style_name():
    # Found by external review: a header-style value like
    # x-access-token=abc123 is a hyphenated name, not a shell-variable
    # one, and hyphens weren't allowed in the name's character class.
    text = "x-access-token=abc123"
    out = redact.redact(text)
    assert "abc123" not in out
    assert out == "x-access-token=***REDACTED***"


def test_does_not_redact_a_name_that_merely_contains_but_does_not_end_in_a_keyword():
    # The hyphen-widening and optional-prefix fixes above must not turn
    # into a bare substring match: the name has to actually *end* in
    # one of the literal keywords.
    cases = ["PASSWORD_FILE=/tmp/p", "--max-key-size=100", "ssh-keygen --public-key-path=/tmp/id.pub"]
    for text in cases:
        assert redact.redact(text) == text, f"{text!r} was incorrectly redacted"


def test_redacts_basic_auth_via_curl_dash_u_flag():
    # Found by external review: curl -u user:pass is a second shape of
    # the same "credentials glued to a username by a colon" idea the
    # URL-embedded-credentials pattern already covers, just not behind
    # a URL. The username isn't the secret, same as that case - keep it
    # visible, redact only the password half.
    out = redact.redact("curl -u alice:hunter2 https://example.com")
    assert "hunter2" not in out
    assert out == "curl -u alice:***REDACTED*** https://example.com"


def test_redacts_basic_auth_via_curl_dash_dash_user_flag():
    out = redact.redact("curl --user alice:hunter2 https://example.com")
    assert "hunter2" not in out
    assert "alice" in out


def test_does_not_falsely_redact_an_ordinary_dash_u_flag_with_no_colon():
    text = "sort -u file.txt"
    assert redact.redact(text) == text


def test_redacts_a_dash_u_password_containing_its_own_colon():
    # Found by external review: curl/URLs don't forbid a colon inside
    # the password itself. The password class previously excluded ":",
    # so a password like "pa:ssword" only got partially redacted,
    # leaking the tail after the second colon.
    out = redact.redact("curl -u alice:pa:ssword https://example.com")
    assert "ssword" not in out
    assert out == "curl -u alice:***REDACTED*** https://example.com"


def test_redacts_a_url_password_containing_its_own_colon():
    # The worse half of the same finding: the URL pattern's password
    # class also excluded ":", so a password containing one meant the
    # class could never reach the required trailing "@" at all - the
    # whole credential was left completely unredacted, not just
    # partially.
    out = redact.redact("curl https://alice:pa:ss@github.com/x")
    assert "pa:ss" not in out
    assert out == "curl https://alice:***REDACTED***@github.com/x"


def test_does_not_misread_a_port_and_query_string_as_url_credentials():
    # Found by external review, a regression from the colon-widening
    # fix above: allowing ":" in the password class had the side effect
    # of also sweeping up a port-plus-query-string shape with an "@" in
    # a query value before any path slash, reading
    # "https://api.host:8443?email=a@b.com" as credentials with
    # "8443?email=a" as the password. Rejected via a targeted negative
    # lookahead for "digits immediately followed by ?/#" (the port+
    # query/fragment shape specifically), not a blanket exclusion of
    # "?"/"#" - see the next two tests for why the blanket version was
    # itself wrong.
    cases = [
        "curl https://api.host:8443?email=a@b.com",
        "curl https://api.host:8443/v1?x=a@b.com",  # a path slash already blocked this one
        "curl https://api.host:8443?x=1",  # no "@" at all
    ]
    for text in cases:
        assert redact.redact(text) == text, f"{text!r} was incorrectly redacted"


def test_redacts_a_url_password_containing_a_literal_question_mark():
    # Found by external review: a blanket "?" exclusion (the first
    # attempt at the port+query false positive above) couldn't tell
    # "this ? starts a password" from "this ? starts a query string" -
    # both are the same text in isolation - so it also silently leaked
    # a password that legitimately (if, per RFC 3986, already
    # technically-malformed-URL-syntax-either-way) contains a literal
    # "?" and is embedded directly in a URL. The fix distinguishes them
    # by requiring the false-positive shape to be *pure digits*
    # immediately before the "?" (a port number); "alice" isn't digits,
    # so this one correctly redacts.
    out = redact.redact("git clone https://alice:pa?sword@github.com/x.git")
    assert "pa?sword" not in out
    assert out == "git clone https://alice:***REDACTED***@github.com/x.git"


def test_redacts_a_url_password_containing_a_literal_hash():
    # Found by external review: the previous fix excluded "?" but not
    # "#", even though RFC 3986 disallows both in userinfo equally -
    # an inconsistency in itself. The negative-lookahead fix treats
    # them the same way.
    out = redact.redact("git clone https://alice:pa#sword@github.com/x.git")
    assert "pa#sword" not in out
    assert out == "git clone https://alice:***REDACTED***@github.com/x.git"


def test_redacts_a_purely_numeric_url_password_with_no_query_ambiguity():
    # A numeric password with nothing ambiguous after it (no "?"/"#"
    # immediately following) must still redact - the lookahead rejects
    # specifically "digits then ?/#", not "digits" on their own.
    out = redact.redact("curl https://alice:8443@github.com")
    assert "8443" not in out
    assert out == "curl https://alice:***REDACTED***@github.com"


def test_does_not_swallow_trailing_punctuation_after_a_redacted_value():
    # Found by external review: every value-capturing pattern used a
    # bare unbounded class (`\S+` or similar) with nothing excluded
    # but whitespace, so a value immediately followed by message
    # punctuation (no space in between) - most concretely, a value
    # embedded as f"...({value})" - had that punctuation swallowed into
    # the match and silently dropped, since the replacement doesn't
    # reproduce whatever got captured. A real secret essentially never
    # ends in one of ) ] } , ; , so excluding them from "the value"
    # costs nothing in the cases that matter.
    cases = [
        ("Authorization: Bearer sk-live-abc123)", "Authorization: Bearer ***REDACTED***)"),
        ("token=abc123)", "token=***REDACTED***)"),
        ("curl -u alice:hunter2)", "curl -u alice:***REDACTED***)"),
        ("https://alice:hunter2@host)", "https://alice:***REDACTED***@host)"),
    ]
    for text, expected in cases:
        assert redact.redact(text) == expected, f"{text!r} lost its trailing punctuation"


def test_redaction_is_idempotent_on_its_own_output():
    # A value that's already been redacted once (e.g. by a caller doing
    # its own defense-in-depth redaction before handing text to
    # something that redacts again, like every Verdict factory does)
    # must come out unchanged on a second pass, not mangled further.
    once = redact.redact("curl --header Authorization:token=SKtopsecretabc https://x")
    twice = redact.redact(once)
    assert once == twice
