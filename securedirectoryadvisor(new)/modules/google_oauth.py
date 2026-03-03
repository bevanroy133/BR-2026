"""
google_oauth.py - OAuth2 helpers for IMAP XOAUTH2 authentication.

Provides a desktop-friendly Authorization Code flow (loopback callback),
token refresh, and XOAUTH2 auth-string creation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from modules.provider_adapters import (
    OAUTH_PROVIDER_GOOGLE,
    OAUTH_PROVIDER_MICROSOFT,
    OAUTH_PROVIDER_YAHOO,
    get_oauth_adapter,
    list_oauth_adapters,
)

# Backward-compatible constants.
GOOGLE_IMAP_SCOPE = get_oauth_adapter(OAUTH_PROVIDER_GOOGLE).default_scope
MICROSOFT_IMAP_SCOPE = get_oauth_adapter(OAUTH_PROVIDER_MICROSOFT).default_scope
YAHOO_IMAP_SCOPE = get_oauth_adapter(OAUTH_PROVIDER_YAHOO).default_scope

# Token cache: keyed by (provider, client_id, refresh_token) ->
# (access_token, expiry_epoch_monotonic)
_token_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
_token_cache_lock = threading.Lock()
_TOKEN_EXPIRY_BUFFER = 60
_TOKEN_POST_MAX_ATTEMPTS = 3
_TOKEN_POST_BASE_DELAY_S = 0.35
_TOKEN_POST_MAX_DELAY_S = 2.0

_RETRYABLE_HTTP_STATUS = {408, 425, 429, 500, 502, 503, 504}


class OAuthError(Exception):
    """Raised when OAuth authorization or token operations fail."""


def oauth_supported_providers() -> tuple[str, ...]:
    return tuple(adapter.provider_id for adapter in list_oauth_adapters())


def oauth_provider_display_name(provider: str) -> str:
    try:
        return get_oauth_adapter(provider).display_name
    except KeyError:
        return provider


def oauth_default_scope(provider: str) -> str:
    try:
        return get_oauth_adapter(provider).default_scope
    except KeyError as exc:
        raise OAuthError(f"Unsupported OAuth provider: {provider}") from exc


def _require_oauth_adapter(provider: str):
    try:
        return get_oauth_adapter(provider)
    except KeyError as exc:
        raise OAuthError(f"Unsupported OAuth provider: {provider}") from exc


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    # RFC 7636 code_verifier length must be 43..128 characters.
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _post_form(url: str, payload: dict[str, str]) -> dict:
    last_exc: Exception | None = None
    for attempt in range(1, _TOKEN_POST_MAX_ATTEMPTS + 1):
        body = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            last_exc = exc
            raw = exc.read().decode("utf-8", errors="replace")
            retryable = exc.code in _RETRYABLE_HTTP_STATUS
            if retryable and attempt < _TOKEN_POST_MAX_ATTEMPTS:
                delay = min(_TOKEN_POST_MAX_DELAY_S, _TOKEN_POST_BASE_DELAY_S * (2 ** (attempt - 1)))
                time.sleep(delay)
                continue
            try:
                data = json.loads(raw)
                msg = data.get("error_description") or data.get("error") or raw
            except Exception:
                msg = raw or str(exc)
            raise OAuthError(f"Token endpoint error: {msg}") from exc
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_exc = exc
            if attempt < _TOKEN_POST_MAX_ATTEMPTS:
                delay = min(_TOKEN_POST_MAX_DELAY_S, _TOKEN_POST_BASE_DELAY_S * (2 ** (attempt - 1)))
                time.sleep(delay)
                continue
            raise OAuthError(f"OAuth network error: {exc}") from exc
        except Exception as exc:
            raise OAuthError(f"OAuth network error: {exc}") from exc
    if last_exc is not None:
        raise OAuthError(f"OAuth network error: {last_exc}") from last_exc
    raise OAuthError("OAuth token request failed.")


def run_oauth_flow(
    *,
    provider: str,
    client_id: str,
    client_secret: str = "",
    scope: str = "",
    timeout_seconds: int = 180,
) -> dict:
    """Run browser OAuth flow for the given provider and return token payload."""
    adapter = _require_oauth_adapter(provider)
    if not client_id.strip():
        raise OAuthError(f"{oauth_provider_display_name(provider)} OAuth Client ID is required.")
    if adapter.require_client_secret and not client_secret.strip():
        raise OAuthError(
            f"{oauth_provider_display_name(provider)} OAuth Client Secret is required."
        )

    verifier = ""
    challenge = ""
    if adapter.use_pkce:
        verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    result: dict[str, str] = {}
    done = threading.Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            code = query.get("code", [""])[0]
            recv_state = query.get("state", [""])[0]
            err = query.get("error", [""])[0]

            if err:
                result["error"] = f"Authorization failed: {err}"
            elif recv_state != state:
                result["error"] = "State mismatch in OAuth callback."
            elif not code:
                result["error"] = "Missing authorization code in callback."
            else:
                result["code"] = code

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if "error" in result:
                body = (
                    "<html><body><h3>Authorization failed</h3>"
                    "<p>You can close this window and return to Secure File Advisor.</p>"
                    "</body></html>"
                )
            else:
                body = (
                    "<html><body><h3>Authorization received</h3>"
                    "<p>You can close this window and return to Secure File Advisor.</p>"
                    "</body></html>"
                )
            self.wfile.write(body.encode("utf-8", errors="replace"))
            done.set()

        def log_message(self, fmt, *args):  # noqa: A003
            return

    server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    port = server.server_port
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    effective_scope = scope.strip() or adapter.default_scope
    params = {
        "client_id": client_id.strip(),
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": effective_scope,
        "state": state,
    }
    params.update(adapter.auth_params)
    if adapter.use_pkce:
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"
    if adapter.use_openid_nonce and "openid" in effective_scope.split():
        params["nonce"] = secrets.token_urlsafe(16)

    auth_url = f"{adapter.auth_endpoint}?{urllib.parse.urlencode(params)}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if not webbrowser.open(auth_url):
            raise OAuthError(
                f"Could not open browser for {oauth_provider_display_name(provider)} authorization."
            )
        if not done.wait(timeout_seconds):
            raise OAuthError(
                f"Timed out waiting for {oauth_provider_display_name(provider)} OAuth callback."
            )
    finally:
        server.shutdown()
        thread.join(timeout=2.0)
        server.server_close()

    if "error" in result:
        raise OAuthError(result["error"])
    code = result.get("code", "")
    if not code:
        raise OAuthError("OAuth callback did not return an authorization code.")

    token_payload = {
        "client_id": client_id.strip(),
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    if adapter.use_pkce:
        token_payload["code_verifier"] = verifier
    if client_secret.strip():
        token_payload["client_secret"] = client_secret.strip()

    token_data = _post_form(adapter.token_endpoint, token_payload)
    if not token_data.get("refresh_token"):
        raise OAuthError(
            f"{oauth_provider_display_name(provider)} did not return a refresh token. "
            "Ensure consent was granted and try again."
        )
    return token_data


def _parse_expires_in(raw_value) -> int:
    try:
        expires = int(raw_value)
    except (TypeError, ValueError):
        expires = 3600
    return max(60, expires)


def refresh_oauth_access_token(
    *,
    provider: str,
    client_id: str,
    refresh_token: str,
    client_secret: str = "",
) -> str:
    """Return a valid OAuth2 access token for IMAP XOAUTH2 login.

    Access tokens are cached in-memory for their lifetime to avoid repeated
    token endpoint round-trips during the same app session.
    """
    adapter = _require_oauth_adapter(provider)
    if not client_id.strip():
        raise OAuthError(f"{oauth_provider_display_name(provider)} OAuth Client ID is required.")
    if not refresh_token.strip():
        raise OAuthError(f"{oauth_provider_display_name(provider)} OAuth refresh token is missing.")
    if adapter.require_client_secret and not client_secret.strip():
        raise OAuthError(
            f"{oauth_provider_display_name(provider)} OAuth Client Secret is required."
        )

    cache_key = (provider, client_id.strip(), refresh_token.strip())
    with _token_cache_lock:
        cached = _token_cache.get(cache_key)
        if cached:
            access_token, expiry = cached
            if time.monotonic() < (expiry - _TOKEN_EXPIRY_BUFFER):
                return access_token

    payload = {
        "client_id": client_id.strip(),
        "refresh_token": refresh_token.strip(),
        "grant_type": "refresh_token",
    }
    if client_secret.strip():
        payload["client_secret"] = client_secret.strip()

    data = _post_form(adapter.token_endpoint, payload)
    access_token = str(data.get("access_token", "")).strip()
    if not access_token:
        raise OAuthError("Token refresh succeeded but no access token was returned.")

    expires_in = _parse_expires_in(data.get("expires_in", 3600))
    with _token_cache_lock:
        _token_cache[cache_key] = (access_token, time.monotonic() + expires_in)

    return access_token


# Backward-compatible wrappers used by existing code paths.
def run_google_oauth_flow(
    *,
    client_id: str,
    client_secret: str = "",
    scope: str = GOOGLE_IMAP_SCOPE,
    timeout_seconds: int = 180,
) -> dict:
    return run_oauth_flow(
        provider=OAUTH_PROVIDER_GOOGLE,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        timeout_seconds=timeout_seconds,
    )


def refresh_google_access_token(
    *,
    client_id: str,
    refresh_token: str,
    client_secret: str = "",
) -> str:
    return refresh_oauth_access_token(
        provider=OAUTH_PROVIDER_GOOGLE,
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
    )


def build_xoauth2_auth_string(email_address: str, access_token: str) -> bytes:
    """Return IMAP XOAUTH2 auth bytes for the given user/token."""
    auth = f"user={email_address}\x01auth=Bearer {access_token}\x01\x01"
    return auth.encode("utf-8")
