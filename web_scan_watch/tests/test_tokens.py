import base64
import json
from datetime import datetime, timedelta, timezone

from src import tokens


def _make_jwt(exp_dt):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload = {"exp": int(exp_dt.timestamp())}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


def test_non_jwt_value():
    info = tokens.analyze_token("Bearer not-a-jwt")
    assert info.is_jwt is False


def test_valid_jwt_future_expiry():
    future = datetime.now(tz=timezone.utc) + timedelta(hours=10)
    info = tokens.analyze_token("Bearer " + _make_jwt(future))
    assert info.is_jwt is True
    assert info.is_expired is False
    assert info.hours_until_expiry > 9


def test_expired_jwt():
    past = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    info = tokens.analyze_token(_make_jwt(past))
    assert info.is_jwt is True
    assert info.is_expired is True


def test_extract_jwt_from_cookie():
    future = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    jwt = _make_jwt(future)
    assert tokens.extract_jwt_from_value(f"session={jwt}; other=x") == jwt


def test_validate_tokens_blocks_on_expired():
    past = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    ok = tokens.validate_tokens({}, _make_jwt(past), max_runtime_hours=1.0, force=True)
    assert ok is False


def _make_jwt_payload(payload: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


def test_decode_jwt_payload_wrong_parts():
    # not 3 parts -> None
    assert tokens.decode_jwt_payload("only.two") is None


def test_decode_jwt_payload_invalid_base64_json():
    # 3 parts but the payload section is not valid base64/JSON -> None
    assert tokens.decode_jwt_payload("aaa.!!!notbase64!!!.ccc") is None


def test_analyze_token_jwt_without_exp():
    # is_jwt True but no expiration
    info = tokens.analyze_token(_make_jwt_payload({"sub": "user"}))
    assert info.is_jwt is True
    assert info.expiration is None
    assert info.is_expired is False


def test_analyze_token_jwt_non_numeric_exp():
    # exp present but not numeric -> hits except
    info = tokens.analyze_token(_make_jwt_payload({"exp": "not-a-number"}))
    assert info.is_jwt is True
    assert info.expiration is None


def test_validate_tokens_valid_non_expiring_no_warnings():
    # valid non-expiring sf_token (no exp) + empty webauth -> True, no warnings
    sf_token = _make_jwt_payload({"sub": "user"})
    assert (
        tokens.validate_tokens({}, sf_token, max_runtime_hours=1.0, force=True) is True
    )


def test_validate_tokens_sf_token_expiring_soon_with_force(capsys):
    # sf_token expires sooner than max_runtime_hours, force=True -> True + warning block
    soon = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    sf_token = _make_jwt(soon)
    assert (
        tokens.validate_tokens({}, sf_token, max_runtime_hours=24.0, force=True) is True
    )
    out = capsys.readouterr().out
    assert "WARNING" in out


def test_validate_tokens_webauth_expiring_soon_with_force(capsys):
    # webauth token expiring soon, force=True -> exercises webauth loop and True
    soon = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    long_lived = datetime.now(tz=timezone.utc) + timedelta(hours=1000)
    webauth = {"Cookie": [_make_jwt(soon)]}
    ok = tokens.validate_tokens(
        webauth, _make_jwt(long_lived), max_runtime_hours=24.0, force=True
    )
    assert ok is True
    out = capsys.readouterr().out
    assert "webauth.Cookie" in out


def test_validate_tokens_webauth_expired_blocks():
    # expired webauth token -> has_expired True -> returns False
    past = datetime.now(tz=timezone.utc) - timedelta(hours=1)
    long_lived = datetime.now(tz=timezone.utc) + timedelta(hours=1000)
    webauth = {"Cookie": [_make_jwt(past)]}
    ok = tokens.validate_tokens(
        webauth, _make_jwt(long_lived), max_runtime_hours=1.0, force=True
    )
    assert ok is False


def test_analyze_token_empty_payload_not_jwt():
    # decodes to an empty dict (falsy) -> `if not payload` returns early
    info = tokens.analyze_token(_make_jwt_payload({}))
    assert info.is_jwt is False


def test_validate_tokens_prompt_declined_returns_false(monkeypatch, capsys):
    # non-force path: user declines at the prompt -> False
    soon = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
    ok = tokens.validate_tokens(
        {}, _make_jwt(soon), max_runtime_hours=24.0, force=False
    )
    assert ok is False


def test_validate_tokens_prompt_accepted_returns_true(monkeypatch):
    # non-force path: user accepts -> True (continues past prompt)
    soon = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "y")
    ok = tokens.validate_tokens(
        {}, _make_jwt(soon), max_runtime_hours=24.0, force=False
    )
    assert ok is True


def test_validate_tokens_prompt_eof_returns_false(monkeypatch):
    # EOFError/KeyboardInterrupt at the prompt -> False
    soon = datetime.now(tz=timezone.utc) + timedelta(hours=1)

    def raise_eof(*a, **k):
        raise EOFError()

    monkeypatch.setattr("builtins.input", raise_eof)
    ok = tokens.validate_tokens(
        {}, _make_jwt(soon), max_runtime_hours=24.0, force=False
    )
    assert ok is False
