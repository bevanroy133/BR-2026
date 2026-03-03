"""
provider_adapters.py - Pluggable provider adapters with retry/backoff support.

This module isolates third-party provider logic (VirusTotal, Google Safe
Browsing, etc.) behind adapter interfaces so provider failures do not leak
into core analysis flow.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import random
import socket
import time
from typing import Callable, Protocol
import urllib.error
import urllib.request

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_delay_s: float = 0.35
    backoff_multiplier: float = 2.0
    max_delay_s: float = 2.0
    jitter_s: float = 0.1


AUTH_MODE_PASSWORD = "password"
AUTH_MODE_OAUTH_GENERIC = "oauth"

OAUTH_PROVIDER_GOOGLE = "google"
OAUTH_PROVIDER_MICROSOFT = "microsoft"
OAUTH_PROVIDER_YAHOO = "yahoo"


@dataclass(frozen=True)
class OAuthProviderAdapter:
    provider_id: str
    display_name: str
    legacy_auth_mode: str
    auth_endpoint: str
    token_endpoint: str
    default_scope: str
    auth_params: dict[str, str]
    use_pkce: bool
    require_client_secret: bool
    use_openid_nonce: bool = False


class FileReputationAdapter(Protocol):
    name: str

    def lookup_hash(self, file_hash: str) -> int | None:
        """Return detection count, or None when unavailable."""


class UrlReputationAdapter(Protocol):
    name: str

    def is_malicious(self, url: str) -> bool:
        """Return True when the URL is provider-flagged."""


_RETRYABLE_HTTP_STATUS = {408, 425, 429, 500, 502, 503, 504}


def _sleep_backoff(policy: RetryPolicy, attempt: int):
    if attempt >= policy.max_attempts:
        return
    delay = min(
        policy.max_delay_s,
        policy.initial_delay_s * (policy.backoff_multiplier ** (attempt - 1)),
    )
    # Small jitter helps avoid synchronized retries.
    jitter = random.uniform(-policy.jitter_s, policy.jitter_s)
    time.sleep(max(0.0, delay + jitter))


def _request_json_with_retry(
    req: urllib.request.Request,
    *,
    timeout_s: float,
    policy: RetryPolicy,
    provider_name: str,
) -> dict:
    last_error: Exception | None = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in _RETRYABLE_HTTP_STATUS and attempt < policy.max_attempts:
                _sleep_backoff(policy, attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_error = exc
            if attempt < policy.max_attempts:
                _sleep_backoff(policy, attempt)
                continue
            raise
        except json.JSONDecodeError as exc:
            last_error = exc
            break
        except Exception as exc:
            last_error = exc
            break
    if last_error is None:
        raise RuntimeError(f"{provider_name}: request failed without details")
    raise last_error


@dataclass
class VirusTotalAdapter:
    api_key: str
    timeout_s: float = 10.0
    retry_policy: RetryPolicy = RetryPolicy()
    name: str = "virustotal"

    def lookup_hash(self, file_hash: str) -> int | None:
        if not self.api_key:
            return None
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self.api_key},
            )
            data = _request_json_with_retry(
                req,
                timeout_s=self.timeout_s,
                policy=self.retry_policy,
                provider_name=self.name,
            )
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        except Exception as exc:
            log.info("VirusTotal lookup failed for %s: %s", file_hash[:12], exc)
            return None


@dataclass
class GoogleSafeBrowsingAdapter:
    api_key: str
    timeout_s: float = 10.0
    retry_policy: RetryPolicy = RetryPolicy()
    name: str = "google_safe_browsing"

    def is_malicious(self, url: str) -> bool:
        if not self.api_key:
            return False
        try:
            payload = json.dumps(
                {
                    "client": {"clientId": "SecureFileAdvisor", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            data = _request_json_with_retry(
                req,
                timeout_s=self.timeout_s,
                policy=self.retry_policy,
                provider_name=self.name,
            )
            return bool(data.get("matches"))
        except Exception as exc:
            log.info("Google Safe Browsing lookup failed for %s: %s", url, exc)
            return False


FileAdapterFactory = Callable[..., FileReputationAdapter]
UrlAdapterFactory = Callable[..., UrlReputationAdapter]
_FILE_ADAPTER_FACTORIES: dict[str, FileAdapterFactory] = {}
_URL_ADAPTER_FACTORIES: dict[str, UrlAdapterFactory] = {}

_OAUTH_ADAPTERS: dict[str, OAuthProviderAdapter] = {}
_OAUTH_PROVIDER_BY_AUTH_MODE: dict[str, str] = {}


def register_file_adapter(name: str, factory: FileAdapterFactory):
    _FILE_ADAPTER_FACTORIES[name] = factory


def register_url_adapter(name: str, factory: UrlAdapterFactory):
    _URL_ADAPTER_FACTORIES[name] = factory


def get_file_adapter(name: str, **kwargs) -> FileReputationAdapter:
    try:
        factory = _FILE_ADAPTER_FACTORIES[name]
    except KeyError as exc:
        raise KeyError(f"Unknown file adapter: {name}") from exc
    return factory(**kwargs)


def get_url_adapter(name: str, **kwargs) -> UrlReputationAdapter:
    try:
        factory = _URL_ADAPTER_FACTORIES[name]
    except KeyError as exc:
        raise KeyError(f"Unknown URL adapter: {name}") from exc
    return factory(**kwargs)


def register_oauth_adapter(adapter: OAuthProviderAdapter):
    provider = adapter.provider_id.strip().lower()
    mode = adapter.legacy_auth_mode.strip().lower()
    _OAUTH_ADAPTERS[provider] = OAuthProviderAdapter(
        provider_id=provider,
        display_name=adapter.display_name,
        legacy_auth_mode=mode,
        auth_endpoint=adapter.auth_endpoint,
        token_endpoint=adapter.token_endpoint,
        default_scope=adapter.default_scope,
        auth_params=dict(adapter.auth_params),
        use_pkce=adapter.use_pkce,
        require_client_secret=adapter.require_client_secret,
        use_openid_nonce=adapter.use_openid_nonce,
    )
    _OAUTH_PROVIDER_BY_AUTH_MODE[mode] = provider


def get_oauth_adapter(provider_id: str) -> OAuthProviderAdapter:
    provider = provider_id.strip().lower()
    try:
        return _OAUTH_ADAPTERS[provider]
    except KeyError as exc:
        raise KeyError(f"Unknown OAuth provider: {provider_id}") from exc


def list_oauth_adapters() -> tuple[OAuthProviderAdapter, ...]:
    return tuple(_OAUTH_ADAPTERS.values())


def oauth_provider_from_auth_mode(auth_mode: str) -> str | None:
    mode = (auth_mode or "").strip().lower()
    return _OAUTH_PROVIDER_BY_AUTH_MODE.get(mode)


def oauth_auth_mode_for_provider(provider_id: str) -> str | None:
    try:
        return get_oauth_adapter(provider_id).legacy_auth_mode
    except KeyError:
        return None


def oauth_auth_modes() -> set[str]:
    return set(_OAUTH_PROVIDER_BY_AUTH_MODE.keys())


def normalize_oauth_selection(auth_mode: str, oauth_provider: str = "") -> tuple[str | None, str]:
    """Normalize legacy and generic OAuth auth config to runtime-safe values.

    Returns (provider_id_or_none, normalized_auth_mode).
    """
    mode = (auth_mode or "").strip().lower()
    provider = (oauth_provider or "").strip().lower()

    # Legacy mode values remain first-class and infer provider directly.
    legacy_provider = oauth_provider_from_auth_mode(mode)
    if legacy_provider:
        return legacy_provider, mode

    # Generic oauth mode requires a known provider, otherwise safely fall back.
    if mode == AUTH_MODE_OAUTH_GENERIC:
        if provider in _OAUTH_ADAPTERS:
            normalized_mode = _OAUTH_ADAPTERS[provider].legacy_auth_mode
            return provider, normalized_mode
        return None, AUTH_MODE_PASSWORD

    # Non-oauth or unknown mode.
    if not mode:
        return None, AUTH_MODE_PASSWORD
    return None, mode


# Built-in providers.
register_file_adapter("virustotal", lambda **kwargs: VirusTotalAdapter(**kwargs))
register_url_adapter("google_safe_browsing", lambda **kwargs: GoogleSafeBrowsingAdapter(**kwargs))

register_oauth_adapter(
    OAuthProviderAdapter(
        provider_id=OAUTH_PROVIDER_GOOGLE,
        display_name="Google",
        legacy_auth_mode="google_oauth",
        auth_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        default_scope="https://mail.google.com/",
        auth_params={"access_type": "offline", "prompt": "consent"},
        use_pkce=True,
        require_client_secret=False,
    )
)
register_oauth_adapter(
    OAuthProviderAdapter(
        provider_id=OAUTH_PROVIDER_MICROSOFT,
        display_name="Microsoft",
        legacy_auth_mode="microsoft_oauth",
        auth_endpoint="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_endpoint="https://login.microsoftonline.com/common/oauth2/v2.0/token",
        default_scope="offline_access https://outlook.office.com/IMAP.AccessAsUser.All",
        auth_params={"prompt": "select_account"},
        use_pkce=True,
        require_client_secret=False,
    )
)
register_oauth_adapter(
    OAuthProviderAdapter(
        provider_id=OAUTH_PROVIDER_YAHOO,
        display_name="Yahoo",
        legacy_auth_mode="yahoo_oauth",
        auth_endpoint="https://api.login.yahoo.com/oauth2/request_auth",
        token_endpoint="https://api.login.yahoo.com/oauth2/get_token",
        default_scope="mail-r",
        auth_params={},
        use_pkce=False,
        require_client_secret=True,
        use_openid_nonce=True,
    )
)
