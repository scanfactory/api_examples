from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger("scan_watcher")

# <moved verbatim: TokenInfo, decode_jwt_payload, extract_jwt_from_value,
#  analyze_token, validate_tokens>


class TokenInfo(BaseModel):
    raw_value: str
    is_jwt: bool = False
    expiration: datetime | None = None
    is_expired: bool = False
    hours_until_expiry: float | None = None


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None


def extract_jwt_from_value(value: str) -> str | None:
    """
    Extract JWT token from a header value.

    Handles these formats:
    - "Bearer xxx.yyy.zzz"
    - "xxx.yyy.zzz"
    - "session=xxx.yyy.zzz; other=value"
    """
    if value.lower().startswith("bearer "):
        potential_jwt = value[7:].strip()
        if len(potential_jwt.split(".")) == 3:
            return potential_jwt

    if len(value.split(".")) == 3 and "=" not in value and ";" not in value:
        return value

    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            cookie_value = part.split("=", 1)[1]
            if len(cookie_value.split(".")) == 3:
                return cookie_value

    return None


def analyze_token(value: str) -> TokenInfo:
    """
    Analyze a token value for JWT content and expiration.

    Args:
        value: Token or header value to analyze

    Returns:
        TokenInfo with analysis results
    """
    info = TokenInfo(raw_value=value)
    jwt_token = extract_jwt_from_value(value)

    if not jwt_token:
        return info

    payload = decode_jwt_payload(jwt_token)
    if not payload:
        return info

    info.is_jwt = True

    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_timestamp = float(exp)
            info.expiration = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            delta = info.expiration - now
            info.hours_until_expiry = delta.total_seconds() / 3600
            info.is_expired = info.hours_until_expiry <= 0
        except (ValueError, OSError):
            pass

    return info


def validate_tokens(
    webauth: dict[str, list[str]],
    sf_token: str,
    max_runtime_hours: float,
    force: bool = False,
) -> bool:
    """
    Validate all tokens and check expiration against max runtime.

    Args:
        webauth: WebAuth headers configuration
        sf_token: API authentication token
        max_runtime_hours: Maximum runtime in hours
        force: Skip confirmation prompts

    Returns:
        True if validation passed and should continue, False otherwise
    """
    warnings: list[str] = []
    has_expired = False
    needs_confirmation = False

    sf_token_info = analyze_token(sf_token)
    if sf_token_info.is_jwt and sf_token_info.expiration:
        if sf_token_info.is_expired:
            logger.error("API token (SF_TOKEN) has already expired!")
            has_expired = True
        elif (
            sf_token_info.hours_until_expiry is not None
            and sf_token_info.hours_until_expiry < max_runtime_hours
        ):
            warnings.append(
                f"API token (SF_TOKEN) expires in {sf_token_info.hours_until_expiry:.1f} hours, "
                f"but max_runtime_hours is {max_runtime_hours}"
            )
            needs_confirmation = True

    # ПРОВЕРКА WEBAUTH ТОКЕНОВ, ЕСЛИ ОНИ ТАМ ЕСТЬ НА ВРЕМЯ ИХ ЖИЗНИ
    for header_name, values in webauth.items():
        for value in values:
            token_info = analyze_token(value)
            if token_info.is_jwt and token_info.expiration:
                if token_info.is_expired:
                    logger.error(f"Token in webauth.{header_name} has already expired!")
                    has_expired = True
                elif (
                    token_info.hours_until_expiry is not None
                    and token_info.hours_until_expiry < max_runtime_hours
                ):
                    warnings.append(
                        f"Token in webauth.{header_name} expires in {token_info.hours_until_expiry:.1f} hours"
                    )
                    needs_confirmation = True

    if has_expired:
        return False

    if warnings and needs_confirmation:
        print("\n" + "=" * 60)
        print("⚠️  WARNING: Token Expiration Risk")
        print("=" * 60)
        for warning in warnings:
            print(f"\n• {warning}")
        print(f"\nmax_runtime_hours is set to {max_runtime_hours} hours.")
        print("\nThis means the scanner may lose access before the scan completes.")
        print(
            "The scan will be stopped when auth check fails, but scan time will be wasted."
        )
        print("\nRecommendations:")
        print("  - Reduce max_runtime_hours to match token lifetime")
        print("  - Use longer-lived tokens")
        print("=" * 60)

        if not force:
            try:
                response = input("\nContinue anyway? [y/N]: ").strip().lower()
                if response not in ("y", "yes"):
                    logger.info("User chose not to continue due to token warnings")
                    return False
            except (EOFError, KeyboardInterrupt):
                print()
                return False

    return True
