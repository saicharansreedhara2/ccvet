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
