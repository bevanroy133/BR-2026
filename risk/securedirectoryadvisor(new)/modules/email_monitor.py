"""
email_monitor.py - Poll an IMAP mailbox for new unseen emails and pass raw
messages to a callback for security analysis.

Supports:
- Password/app-password login
- OAuth2 (XOAUTH2) login for supported providers
"""

from __future__ import annotations

import imaplib
import logging
import threading

from modules.provider_adapters import (
    AUTH_MODE_PASSWORD,
    OAUTH_PROVIDER_GOOGLE,
    OAUTH_PROVIDER_MICROSOFT,
    OAUTH_PROVIDER_YAHOO,
    normalize_oauth_selection,
    oauth_auth_mode_for_provider,
    oauth_auth_modes,
    oauth_provider_from_auth_mode,
)
from modules.google_oauth import (
    OAuthError,
    build_xoauth2_auth_string,
    oauth_provider_display_name,
    refresh_oauth_access_token,
)

log = logging.getLogger(__name__)

knownservers: dict[str, tuple[str, int]] = {
    "gmail.com":    ("imap.gmail.com", 993),
    "google.com":   ("imap.gmail.com", 993),
    "outlook.com":  ("outlook.office365.com", 993),
    "hotmail.com":  ("outlook.office365.com", 993),
    "live.com":     ("outlook.office365.com", 993),
    "yahoo.com":    ("imap.mail.yahoo.com", 993),
    "aol.com":      ("imap.aol.com", 993),
    "icloud.com":   ("imap.mail.me.com", 993),
    "me.com":       ("imap.mail.me.com", 993),
    "zoho.com":     ("imap.zoho.com", 993),
}

AUTH_PASSWORD = AUTH_MODE_PASSWORD
AUTH_GOOGLE_OAUTH = oauth_auth_mode_for_provider(OAUTH_PROVIDER_GOOGLE) or "google_oauth"
AUTH_MICROSOFT_OAUTH = (
    oauth_auth_mode_for_provider(OAUTH_PROVIDER_MICROSOFT) or "microsoft_oauth"
)
AUTH_YAHOO_OAUTH = oauth_auth_mode_for_provider(OAUTH_PROVIDER_YAHOO) or "yahoo_oauth"
OAUTH_AUTH_MODES = set(oauth_auth_modes())

_IMAP_CONNECT_MAX_ATTEMPTS = 3
_IMAP_CONNECT_BASE_DELAY_S = 0.4
_IMAP_CONNECT_MAX_DELAY_S = 2.0
_IMAP_COMMAND_MAX_ATTEMPTS = 3
_IMAP_COMMAND_BASE_DELAY_S = 0.25
_IMAP_COMMAND_MAX_DELAY_S = 1.25

_TRANSIENT_IMAP_ERROR_HINTS = (
    "timeout",
    "temporary",
    "temporarily",
    "try again",
    "rate limit",
    "too many",
    "unavailable",
    "server busy",
    "aborted",
    "network",
    "connection",
)


def guess_imap_server(email_address: str) -> tuple[str, int] | None:
    """Return (host, port) for well-known providers, or None."""
    domain = email_address.rsplit("@", 1)[-1].lower() if "@" in email_address else ""
    return knownservers.get(domain)


def _backoff_delay(attempt: int, base_delay_s: float, max_delay_s: float) -> float:
    return min(max_delay_s, base_delay_s * (2 ** (attempt - 1)))


def _is_transient_imap_error(exc: Exception) -> bool:
    if isinstance(exc, imaplib.IMAP4.abort):
        return True
    message = str(exc).lower()
    return any(token in message for token in _TRANSIENT_IMAP_ERROR_HINTS)


class EmailMonitor:
    """Periodically checks an IMAP mailbox for new unseen messages.

    Parameters
    ----------
    email_address : str
        Full email address (user@example.com).
    email_password : str
        Password or app-specific password (password auth mode).
    imap_server : str
        IMAP hostname. If empty, auto-detected from the email domain.
    imap_port : int
        IMAP port (default 993 for SSL).
    on_new_email : callable(uid: str, raw_bytes: bytes)
        Callback fired for each new unseen email.
    poll_interval : float
        Seconds between mailbox polls (default 60).
    folder : str
        IMAP folder to watch (default INBOX).
    auth_mode : str
        One of: "password", legacy provider modes, or "oauth" with oauth_provider.
    oauth_client_id : str
        OAuth Client ID for XOAUTH2 mode.
    oauth_client_secret : str
        OAuth Client Secret (provider-dependent).
    oauth_refresh_token : str
        OAuth refresh token.
    oauth_provider : str
        Optional OAuth provider id used when auth_mode is "oauth".
    """

    def __init__(
        self,
        email_address: str,
        email_password: str,
        imap_server: str = "",
        imap_port: int = 993,
        on_new_email=None,
        poll_interval: float = 60.0,
        folder: str = "INBOX",
        auth_mode: str = AUTH_PASSWORD,
        oauth_client_id: str = "",
        oauth_client_secret: str = "",
        oauth_refresh_token: str = "",
        oauth_provider: str = "",
    ):
        self.email_address = email_address
        self.email_password = email_password
        self.folder = folder
        self.on_new_email = on_new_email
        self.poll_interval = poll_interval
        valid_oauth_modes = set(oauth_auth_modes())
        provider_id, normalized_mode = normalize_oauth_selection(auth_mode, oauth_provider)
        valid_auth_modes = valid_oauth_modes | {AUTH_PASSWORD}
        self.auth_mode = normalized_mode if normalized_mode in valid_auth_modes else AUTH_PASSWORD
        self.oauth_provider = provider_id if self.auth_mode in valid_oauth_modes else None
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret
        self.oauth_refresh_token = oauth_refresh_token

        self._stop_event = threading.Event()
        self._seen_uids: set[str] = set()
        self._connection_error: str = ""

        if imap_server:
            self.imap_server = imap_server
            self.imap_port = imap_port
        else:
            guessed = guess_imap_server(email_address)
            if guessed:
                self.imap_server, self.imap_port = guessed
            else:
                self.imap_server = ""
                self.imap_port = imap_port

    @property
    def last_error(self) -> str:
        return self._connection_error

    def _wait_with_backoff(
        self,
        attempt: int,
        *,
        base_delay_s: float,
        max_delay_s: float,
    ) -> bool:
        delay = _backoff_delay(attempt, base_delay_s, max_delay_s)
        return self._stop_event.wait(delay)

    def _login(self, conn: imaplib.IMAP4_SSL):
        if self.auth_mode in OAUTH_AUTH_MODES:
            provider = self.oauth_provider or oauth_provider_from_auth_mode(self.auth_mode)
            if not provider:
                raise imaplib.IMAP4.error("Invalid OAuth provider selection.")
            try:
                access_token = refresh_oauth_access_token(
                    provider=provider,
                    client_id=self.oauth_client_id,
                    client_secret=self.oauth_client_secret,
                    refresh_token=self.oauth_refresh_token,
                )
            except OAuthError as exc:
                raise imaplib.IMAP4.error(str(exc)) from exc
            auth_bytes = build_xoauth2_auth_string(self.email_address, access_token)
            conn.authenticate("XOAUTH2", lambda _: auth_bytes)
            return

        conn.login(self.email_address, self.email_password)

    def _connect(self) -> imaplib.IMAP4_SSL | None:
        if not self.imap_server:
            self._connection_error = (
                f"Could not determine IMAP server for '{self.email_address}'. "
                "Please set it manually in Settings."
            )
            log.warning(self._connection_error)
            return None

        if self.auth_mode in OAUTH_AUTH_MODES:
            if not self.oauth_client_id or not self.oauth_refresh_token:
                provider = self.oauth_provider or oauth_provider_from_auth_mode(self.auth_mode)
                provider_name = oauth_provider_display_name(provider or "OAuth")
                self._connection_error = (
                    f"{provider_name} OAuth is selected but Client ID or Refresh Token is missing. "
                    f"Use Settings to authorize {provider_name} OAuth first."
                )
                log.warning(self._connection_error)
                return None
        else:
            if not self.email_password:
                self._connection_error = "Email password/app password is missing."
                log.warning(self._connection_error)
                return None

        for attempt in range(1, _IMAP_CONNECT_MAX_ATTEMPTS + 1):
            conn: imaplib.IMAP4_SSL | None = None
            try:
                conn = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, timeout=15)
                self._login(conn)
                conn.select(self.folder, readonly=True)
                self._connection_error = ""
                return conn
            except imaplib.IMAP4.error as exc:
                self._connection_error = f"Login failed: {exc}"
                transient = _is_transient_imap_error(exc)
                log.warning(
                    "IMAP login failed for %s (attempt %d/%d, transient=%s): %s",
                    self.email_address,
                    attempt,
                    _IMAP_CONNECT_MAX_ATTEMPTS,
                    transient,
                    exc,
                )
                if conn:
                    try:
                        conn.logout()
                    except Exception:
                        pass
                if transient and attempt < _IMAP_CONNECT_MAX_ATTEMPTS:
                    if self._wait_with_backoff(
                        attempt,
                        base_delay_s=_IMAP_CONNECT_BASE_DELAY_S,
                        max_delay_s=_IMAP_CONNECT_MAX_DELAY_S,
                    ):
                        break
                    continue
                # Credential/login failures are usually non-transient.
                return None
            except Exception as exc:
                self._connection_error = f"Connection error: {exc}"
                log.warning(
                    "IMAP connection error for %s (attempt %d/%d): %s",
                    self.email_address,
                    attempt,
                    _IMAP_CONNECT_MAX_ATTEMPTS,
                    exc,
                )
                if conn:
                    try:
                        conn.logout()
                    except Exception:
                        pass
                if attempt < _IMAP_CONNECT_MAX_ATTEMPTS:
                    if self._wait_with_backoff(
                        attempt,
                        base_delay_s=_IMAP_CONNECT_BASE_DELAY_S,
                        max_delay_s=_IMAP_CONNECT_MAX_DELAY_S,
                    ):
                        break
                    continue
                return None
        return None

    def _fetch_unseen_uids(self, conn: imaplib.IMAP4_SSL) -> list[str]:
        """Fetch stable IMAP UIDs for unseen messages."""
        for attempt in range(1, _IMAP_COMMAND_MAX_ATTEMPTS + 1):
            try:
                status, data = conn.uid("SEARCH", None, "UNSEEN")
                if status == "OK":
                    if not data or not data[0]:
                        return []
                    return data[0].decode().split()
                log.warning(
                    "IMAP search returned status %s (attempt %d/%d)",
                    status,
                    attempt,
                    _IMAP_COMMAND_MAX_ATTEMPTS,
                )
            except imaplib.IMAP4.error as exc:
                transient = _is_transient_imap_error(exc)
                log.warning(
                    "IMAP search failed (attempt %d/%d, transient=%s): %s",
                    attempt,
                    _IMAP_COMMAND_MAX_ATTEMPTS,
                    transient,
                    exc,
                )
                if not transient:
                    break
            except Exception as exc:
                log.warning(
                    "IMAP search failed (attempt %d/%d): %s",
                    attempt,
                    _IMAP_COMMAND_MAX_ATTEMPTS,
                    exc,
                )

            if attempt < _IMAP_COMMAND_MAX_ATTEMPTS:
                if self._wait_with_backoff(
                    attempt,
                    base_delay_s=_IMAP_COMMAND_BASE_DELAY_S,
                    max_delay_s=_IMAP_COMMAND_MAX_DELAY_S,
                ):
                    break

        return []

    def _fetch_messages_batch(
        self, conn: imaplib.IMAP4_SSL, uids: list[str]
    ) -> dict[str, bytes]:
        """Fetch multiple RFC822 messages in a single IMAP command.

        Returns a mapping of uid -> raw_bytes for successfully fetched messages.
        Falls back to an empty dict on failure.
        """
        if not uids:
            return {}
        uid_set = ",".join(uids)
        for attempt in range(1, _IMAP_COMMAND_MAX_ATTEMPTS + 1):
            try:
                status, data = conn.uid("FETCH", uid_set, "(RFC822)")
                if status != "OK" or not data:
                    log.warning(
                        "IMAP batch fetch returned status %s (attempt %d/%d)",
                        status,
                        attempt,
                        _IMAP_COMMAND_MAX_ATTEMPTS,
                    )
                else:
                    # imaplib interleaves response tuples with b')' separators.
                    # Each email produces a 2-tuple: (b'<uid> (RFC822 {size}', raw_bytes).
                    messages: dict[str, bytes] = {}
                    uid_iter = iter(uids)
                    for item in data:
                        if not isinstance(item, tuple) or len(item) < 2:
                            continue
                        header = item[0] if isinstance(item[0], bytes) else b""
                        raw = item[1]
                        if not isinstance(raw, (bytes, bytearray)):
                            continue

                        # Try to extract the UID from the response header first;
                        # fall back to consuming UIDs in request order.
                        uid_match = None
                        import re as _re
                        m = _re.search(rb"UID\s+(\d+)", header, _re.IGNORECASE)
                        if m:
                            uid_match = m.group(1).decode()
                        else:
                            try:
                                uid_match = next(uid_iter)
                            except StopIteration:
                                pass

                        if uid_match and uid_match in uids:
                            messages[uid_match] = bytes(raw)

                    return messages
            except imaplib.IMAP4.error as exc:
                transient = _is_transient_imap_error(exc)
                log.warning(
                    "IMAP batch fetch failed (attempt %d/%d, transient=%s): %s",
                    attempt,
                    _IMAP_COMMAND_MAX_ATTEMPTS,
                    transient,
                    exc,
                )
                if not transient:
                    break
            except Exception as exc:
                log.warning(
                    "IMAP batch fetch failed (attempt %d/%d): %s",
                    attempt,
                    _IMAP_COMMAND_MAX_ATTEMPTS,
                    exc,
                )

            if attempt < _IMAP_COMMAND_MAX_ATTEMPTS:
                if self._wait_with_backoff(
                    attempt,
                    base_delay_s=_IMAP_COMMAND_BASE_DELAY_S,
                    max_delay_s=_IMAP_COMMAND_MAX_DELAY_S,
                ):
                    break

        return {}

    def check_once(self) -> list[tuple[str, bytes]]:
        """Connect, fetch new unseen emails, return list of (uid, raw_bytes)."""
        conn = self._connect()
        if conn is None:
            return []

        results: list[tuple[str, bytes]] = []
        try:
            all_uids = self._fetch_unseen_uids(conn)
            new_uids = [uid for uid in all_uids if uid not in self._seen_uids]
            if new_uids:
                messages = self._fetch_messages_batch(conn, new_uids)
                for uid in new_uids:
                    raw = messages.get(uid)
                    if raw:
                        self._seen_uids.add(uid)
                        results.append((uid, raw))
        finally:
            try:
                conn.close()
                conn.logout()
            except Exception:
                pass
        return results

    def start(self):
        """Blocking poll loop. Run in a daemon thread."""
        log.info(
            "Email monitor starting for %s (poll every %.0fs)",
            self.email_address,
            self.poll_interval,
        )

        # Seed with current UIDs so we only alert on truly new messages.
        conn = self._connect()
        if conn:
            try:
                uids = self._fetch_unseen_uids(conn)
                self._seen_uids.update(uids)
                log.info("Seeded %d existing unseen emails", len(uids))
            finally:
                try:
                    conn.close()
                    conn.logout()
                except Exception:
                    pass

        while not self._stop_event.wait(self.poll_interval):
            conn = self._connect()
            if conn is None:
                continue
            try:
                all_uids = self._fetch_unseen_uids(conn)
                new_uids = [uid for uid in all_uids if uid not in self._seen_uids]
                if new_uids:
                    messages = self._fetch_messages_batch(conn, new_uids)
                    for uid in new_uids:
                        raw = messages.get(uid)
                        if raw and self.on_new_email:
                            self._seen_uids.add(uid)
                            try:
                                self.on_new_email(uid, raw)
                            except Exception:
                                log.exception("Email callback failed for UID %s", uid)
            finally:
                try:
                    conn.close()
                    conn.logout()
                except Exception:
                    pass

    def stop(self):
        self._stop_event.set()
        log.info("Email monitor stopped for %s", self.email_address)
