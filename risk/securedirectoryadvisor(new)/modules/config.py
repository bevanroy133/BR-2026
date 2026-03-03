"""
config.py - User configuration and app settings.

API keys are stored in the OS keychain via the `keyring` library when available,
falling back to the plain-text JSON config file if keyring is not installed.
"""

import contextlib
import copy
import json
import logging
import os
import threading

from modules.provider_adapters import AUTH_MODE_PASSWORD, normalize_oauth_selection, oauth_auth_modes
from modules.history_store import HistoryStore

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional keyring support
# ---------------------------------------------------------------------------
try:
    import keyring as _keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _keyring = None
    _KEYRING_AVAILABLE = False

_KEYRING_SERVICE = "SecureFileAdvisor"

# Keys that should be kept in the OS keychain rather than the plain JSON file.
_SECURE_KEYS = {
    "virustotal_api_key",
    "google_safe_browsing_key",
    "email_password",
    "email_oauth_client_secret",
    "email_oauth_refresh_token",
}


def _keyring_get(key: str) -> str:
    if not _KEYRING_AVAILABLE:
        return ""
    try:
        value = _keyring.get_password(_KEYRING_SERVICE, key)
        return value or ""
    except Exception as exc:
        log.warning("keyring read failed for %s: %s", key, exc)
        return ""


def _keyring_set(key: str, value: str):
    if not _KEYRING_AVAILABLE:
        return
    try:
        _keyring.set_password(_KEYRING_SERVICE, key, value)
    except Exception as exc:
        log.warning("keyring write failed for %s: %s", key, exc)


# ---------------------------------------------------------------------------
# Defaults (plain-text fields only)
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "downloads_folder": os.path.expanduser("~/Downloads"),
    "trusted_contact_name": "",
    "trusted_contact_email": "",
    "email_address": "",
    "email_auth_mode": "password",
    "email_oauth_provider": "",
    "email_oauth_client_id": "",
    "email_imap_server": "",
    "email_imap_port": 993,
    "email_monitoring_enabled": False,
    "email_poll_interval": 60,
}
_ALLOWED_CONFIG_KEYS = set(DEFAULT_CONFIG)

CONFIG_PATH = os.path.expanduser("~/.secure_file_advisor_config.json")


def _normalize_email_oauth_fields(data: dict):
    auth_mode = str(data.get("email_auth_mode", AUTH_MODE_PASSWORD)).strip().lower()
    oauth_provider = str(data.get("email_oauth_provider", "")).strip().lower()
    provider, normalized_mode = normalize_oauth_selection(auth_mode, oauth_provider)
    valid_modes = set(oauth_auth_modes()) | {AUTH_MODE_PASSWORD}
    if normalized_mode not in valid_modes:
        normalized_mode = AUTH_MODE_PASSWORD
        provider = None
    data["email_auth_mode"] = normalized_mode
    data["email_oauth_provider"] = provider or ""


class Config:
    def __init__(self):
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        self._batch_mode = False
        self._lock = threading.RLock()
        # Scan history is now stored separately in SQLite.
        self._history_store = HistoryStore()
        self.load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def load(self):
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if not isinstance(saved, dict):
                    raise json.JSONDecodeError("Config root must be a JSON object.", "", 0)

                # Migrate legacy in-config scan history into SQLite history store.
                legacy_history = saved.pop("scan_history", None)
                had_legacy_history_key = legacy_history is not None
                if isinstance(legacy_history, list) and legacy_history:
                    moved = self._history_store.migrate_legacy_entries(legacy_history)
                    if moved:
                        log.info("Migrated %d legacy scan history entries to SQLite.", moved)

                # Strip any API keys that may have been stored in an older
                # plaintext config and migrate them to the keychain.
                migrated_secure_keys = False
                for key in _SECURE_KEYS:
                    if key in saved:
                        legacy_value = saved.pop(key)
                        if legacy_value and _KEYRING_AVAILABLE:
                            log.info("Migrating %s from config file to keychain.", key)
                            _keyring_set(key, legacy_value)
                            migrated_secure_keys = True
                        elif legacy_value:
                            # Keyring unavailable: keep legacy plaintext value as fallback.
                            saved[key] = legacy_value

                sanitized = {k: v for k, v in saved.items() if k in _ALLOWED_CONFIG_KEYS}
                with self._lock:
                    self._data.update(sanitized)
                    _normalize_email_oauth_fields(self._data)
                    # Preserve legacy plaintext API-key fallback only when keyring is unavailable.
                    if not _KEYRING_AVAILABLE:
                        for key in _SECURE_KEYS:
                            if key in saved:
                                self._data[key] = saved[key]

                if migrated_secure_keys or had_legacy_history_key:
                    # Persist a cleaned config file with migrated keys removed.
                    self.save()
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not load config from %s: %s", CONFIG_PATH, exc)

    def save(self):
        with self._lock:
            if self._batch_mode:
                return
            tmp_path = f"{CONFIG_PATH}.tmp"
            config_dir = os.path.dirname(CONFIG_PATH) or "."
            payload = copy.deepcopy(self._data)
            _normalize_email_oauth_fields(payload)
            try:
                os.makedirs(config_dir, exist_ok=True)
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, CONFIG_PATH)
            except OSError as exc:
                log.error("Could not save config to %s: %s", CONFIG_PATH, exc)
                with contextlib.suppress(OSError):
                    os.remove(tmp_path)

    @contextlib.contextmanager
    def batch_update(self):
        """Context manager that suppresses intermediate saves and writes once on exit.

        Use this when setting multiple attributes at once to avoid redundant
        disk writes:

            with config.batch_update():
                config.trusted_contact_name  = "Alice"
                config.trusted_contact_email = "alice@example.com"
        """
        with self._lock:
            self._batch_mode = True
        try:
            yield
        finally:
            with self._lock:
                self._batch_mode = False
            self.save()

    # ------------------------------------------------------------------
    # Attribute access (routes secure keys through keychain)
    # ------------------------------------------------------------------
    def __getattr__(self, key):
        if key.startswith("_"):
            raise AttributeError(key)
        if key == "scan_history":
            return self._history_store.list_entries(limit=100)
        if key in _SECURE_KEYS:
            if _KEYRING_AVAILABLE:
                return _keyring_get(key)
            # Fallback: read from plain data dict (legacy or keyring unavailable)
            with self._lock:
                return self._data.get(key, "")
        with self._lock:
            try:
                value = self._data[key]
            except KeyError:
                raise AttributeError(f"No config key: {key}")
        if isinstance(value, (list, dict)):
            return copy.deepcopy(value)
        return value

    def __setattr__(self, key, value):
        if key.startswith("_"):
            super().__setattr__(key, value)
            return
        if key == "scan_history":
            # Preserve backward compatibility for any legacy callers that still
            # assign scan_history directly.
            if isinstance(value, list):
                self._history_store.replace_entries(value)
            else:
                self._history_store.clear_entries()
            return
        if key in _SECURE_KEYS:
            if _KEYRING_AVAILABLE:
                _keyring_set(key, value)
                return
            # Fallback: store in plain data dict
            with self._lock:
                self._data[key] = value
            self.save()
            return
        with self._lock:
            self._data[key] = value
        self.save()

    def add_scan_history(self, entry: dict):
        self._history_store.add_entry(entry)

    def clear_scan_history(self):
        self._history_store.clear_entries()
