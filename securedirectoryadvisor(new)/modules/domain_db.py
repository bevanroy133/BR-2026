"""
domain_db.py - Local database of known legitimate domains (powered by the Tranco list).

Downloads and caches the Tranco top-sites ranking so the analyzer can:
  1. Recognise known legitimate websites  ("coolmathgames.com" → safe)
  2. Detect high-confidence typosquats of popular sites
     ("coolmathgamess.com" → danger)

The list is stored as a plain-text file in the same directory as the config.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import time
import zipfile
from collections import defaultdict
from urllib.request import urlopen, Request

log = logging.getLogger(__name__)

_DB_DIR = os.path.expanduser("~/.secure_file_advisor_data")
_DB_FILE = os.path.join(_DB_DIR, "tranco_domains.txt")
_META_FILE = os.path.join(_DB_DIR, "tranco_meta.txt")

# Tranco provides a stable "latest" download endpoint.
_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Only load the top N domains — balances coverage vs. memory/speed.
_MAX_DOMAINS = 100_000

# Generic typosquat matching (outside the curated brand list) is intentionally
# conservative to reduce false positives:
# - very short labels are too ambiguous (e.g. adai vs addi),
# - only high-traffic targets are considered,
# - one-edit differences are treated as strong generic evidence.
_MIN_GENERIC_TYPOSQUAT_BASE_LEN = 6
_MAX_GENERIC_TYPOSQUAT_TARGET_RANK = 20_000
_MAX_GENERIC_TYPOSQUAT_DISTANCE = 1


class DomainDatabase:
    """In-memory set of known-good domains with fast typosquat lookup."""

    def __init__(self):
        self._domains: set[str] = set()
        self._rank: dict[str, int] = {}
        # Bucketed index: (length, first_char) → list of domains.
        # Used to narrow Levenshtein search space dramatically.
        self._buckets: dict[tuple[int, str], list[str]] = defaultdict(list)
        self._loaded = False
        self._load_from_disk()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def is_loaded(self) -> bool:
        return self._loaded and len(self._domains) > 0

    @property
    def domain_count(self) -> int:
        return len(self._domains)

    @property
    def last_updated(self) -> str | None:
        """Return ISO timestamp of last download, or None."""
        try:
            with open(_META_FILE, "r", encoding="utf-8") as f:
                return f.read().strip() or None
        except OSError:
            return None

    def is_known(self, domain: str) -> bool:
        """Return True if *domain* (e.g. 'coolmathgames.com') is in the database."""
        d = domain.lower().removeprefix("www.")
        if d in self._domains:
            return True
        # Also check without port
        host = d.split(":")[0]
        return host in self._domains

    def find_typosquat_target(self, domain: str, max_distance: int = 2) -> str | None:
        """If *domain* looks like a typosquat of a known domain, return that
        known domain.  Otherwise return None.

        This generic matcher is conservative by design. Short labels and low-rank
        targets create too many accidental near-matches, so we only consider:
          - base labels with length >= _MIN_GENERIC_TYPOSQUAT_BASE_LEN
          - targets ranked within top _MAX_GENERIC_TYPOSQUAT_TARGET_RANK
          - edit distance <= _MAX_GENERIC_TYPOSQUAT_DISTANCE

        Only compares against domains of similar length and same first character
        for performance (avoids O(100K) Levenshtein calls).
        """
        d = domain.lower().removeprefix("www.")
        # Strip the TLD to compare base names, since most typosquats target
        # the same TLD (coolmathgamess.com vs coolmathgames.com).
        parts = d.rsplit(".", 1)
        if len(parts) != 2:
            return None
        input_base, input_tld = parts

        if not input_base or len(input_base) < _MIN_GENERIC_TYPOSQUAT_BASE_LEN:
            return None

        # Keep caller compatibility while enforcing stricter internal defaults.
        max_distance = min(max_distance, _MAX_GENERIC_TYPOSQUAT_DISTANCE)

        # Search buckets with matching first character and similar length.
        candidates_checked = 0
        best_domain: str | None = None
        best_dist = max_distance + 1
        best_rank = 10**9
        for length_offset in range(max_distance + 1):
            for sign in (0, 1, -1):
                check_len = len(input_base) + sign * length_offset
                if check_len < 3:
                    continue
                first_char = input_base[0]
                bucket = self._buckets.get((check_len, first_char), [])
                for known_full in bucket:
                    kparts = known_full.rsplit(".", 1)
                    if len(kparts) != 2:
                        continue
                    known_base, known_tld = kparts
                    # Prefer same-TLD matches — a .com typosquat of a .com site.
                    if known_tld != input_tld:
                        continue
                    if known_base == input_base:
                        # Exact match → it's the real site, not a typosquat.
                        continue
                    dist = _levenshtein(input_base, known_base)
                    if 0 < dist <= max_distance:
                        rank = self._rank.get(known_full, 10**9)
                        if rank > _MAX_GENERIC_TYPOSQUAT_TARGET_RANK:
                            continue
                        if (dist < best_dist) or (dist == best_dist and rank < best_rank):
                            best_domain = known_full
                            best_dist = dist
                            best_rank = rank
                    candidates_checked += 1
                    if candidates_checked > 5000:
                        return best_domain
        return best_domain

    # ------------------------------------------------------------------
    # Download & persistence
    # ------------------------------------------------------------------
    def clear(self) -> bool:
        """Delete the domain database files from disk and reset in-memory state.

        Returns True if all files were removed (or did not exist), False if any
        removal failed.
        """
        success = True
        for path in (_DB_FILE, _META_FILE):
            if os.path.isfile(path):
                try:
                    os.remove(path)
                except OSError as exc:
                    log.warning("Could not remove %s: %s", path, exc)
                    success = False
        self._domains = set()
        self._rank = {}
        self._buckets = defaultdict(list)
        self._loaded = False
        return success

    def download(self, progress_callback=None) -> bool:
        """Download the Tranco top domains list.  Returns True on success.

        *progress_callback*, if provided, is called with (status_message: str).
        """
        def _progress(msg: str):
            log.info(msg)
            if progress_callback:
                progress_callback(msg)

        _progress("Downloading domain database…")
        try:
            req = Request(_TRANCO_URL, headers={"User-Agent": "SecureFileAdvisor/2.0"})
            with urlopen(req, timeout=60) as resp:
                data = resp.read()
        except Exception as exc:
            _progress(f"Download failed: {exc}")
            log.error("Tranco download failed: %s", exc)
            return False

        _progress("Extracting domains…")
        try:
            domains = self._parse_tranco_zip(data)
        except Exception as exc:
            _progress(f"Parse failed: {exc}")
            log.error("Tranco parse failed: %s", exc)
            return False

        if not domains:
            _progress("Download produced no domains — aborting.")
            return False

        _progress(f"Saving {len(domains):,} domains to disk…")
        self._save_to_disk(domains)
        self._index(domains)
        _progress(f"Domain database ready — {len(domains):,} sites loaded.")
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _parse_tranco_zip(self, data: bytes) -> list[str]:
        """Extract domain names from the Tranco CSV zip archive."""
        domains: list[str] = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if not name.endswith(".csv"):
                    continue
                with zf.open(name) as csvfile:
                    reader = csv.reader(io.TextIOWrapper(csvfile, encoding="utf-8"))
                    for row in reader:
                        if len(row) >= 2:
                            domain = row[1].strip().lower()
                            if domain and "." in domain:
                                domains.append(domain)
                            if len(domains) >= _MAX_DOMAINS:
                                break
        return domains

    def _save_to_disk(self, domains: list[str]):
        os.makedirs(_DB_DIR, exist_ok=True)
        with open(_DB_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(domains))
        with open(_META_FILE, "w", encoding="utf-8") as f:
            from datetime import datetime
            f.write(datetime.now().isoformat())

    def _load_from_disk(self):
        if not os.path.isfile(_DB_FILE):
            log.info("No domain database found at %s", _DB_FILE)
            return
        try:
            with open(_DB_FILE, "r", encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
            self._index(domains)
            log.info("Loaded %d domains from disk.", len(domains))
        except OSError as exc:
            log.warning("Could not load domain database: %s", exc)

    def _index(self, domains: list[str]):
        """Build the in-memory set and bucketed index."""
        self._domains = set(domains)
        self._rank = {}
        self._buckets = defaultdict(list)
        for idx, d in enumerate(domains, start=1):
            self._rank[d] = idx
            base = d.rsplit(".", 1)[0] if "." in d else d
            if base:
                key = (len(base), base[0])
                self._buckets[key].append(d)
        self._loaded = True


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance with early termination."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    if abs(len(a) - len(b)) > 2:
        return abs(len(a) - len(b))
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if ca == cb else 1),
            ))
        prev = curr
    return prev[-1]


# Module-level singleton so it's loaded once and shared.
_instance: DomainDatabase | None = None


def get_domain_db() -> DomainDatabase:
    """Return the shared DomainDatabase singleton."""
    global _instance
    if _instance is None:
        _instance = DomainDatabase()
    return _instance
