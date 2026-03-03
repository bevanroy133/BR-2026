"""
monitor.py - Watches the Downloads folder and fires a callback when a new file appears.
Uses polling (no third-party deps) so it works on Windows, macOS, and Linux.
"""

import logging
import os
import threading
import time

log = logging.getLogger(__name__)

# Browser temp extensions created while a download is still in progress.
_TEMP_EXTENSIONS = {".crdownload", ".part", ".partial", ".download", ".tmp"}


class DownloadMonitor:
    def __init__(
        self,
        watch_folder: str,
        on_new_file,
        poll_interval: float = 2.0,
        stable_timeout: float = 30.0,
    ):
        self.watch_folder = os.path.expanduser(watch_folder)
        self.on_new_file = on_new_file
        self.poll_interval = poll_interval
        self.stable_timeout = stable_timeout
        self._stop_event = threading.Event()
        self._known_files: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _is_temp_file(filename: str) -> bool:
        _, ext = os.path.splitext(filename)
        return ext.lower() in _TEMP_EXTENSIONS

    def _scan(self) -> set[str]:
        try:
            return set(
                os.path.join(self.watch_folder, f)
                for f in os.listdir(self.watch_folder)
                if os.path.isfile(os.path.join(self.watch_folder, f))
                and not self._is_temp_file(f)
            )
        except OSError as exc:
            log.warning("Could not scan %s: %s", self.watch_folder, exc)
            return set()

    def _wait_until_stable(
        self,
        filepath: str,
        interval: float = 0.5,
        stable_window: float = 1.5,
    ) -> bool:
        """Wait for sustained size stability before scanning.

        Returns True when scanning should proceed, False when monitoring is
        stopping or the file disappeared.
        """
        deadline = time.monotonic() + self.stable_timeout
        prev_size = None
        stable_for = 0.0

        while time.monotonic() < deadline:
            if self._stop_event.is_set():
                return False
            try:
                size = os.path.getsize(filepath)
            except OSError:
                return False

            if prev_size is not None and size == prev_size:
                stable_for += interval
                if stable_for >= stable_window:
                    return True
            else:
                prev_size = size
                stable_for = 0.0

            if self._stop_event.wait(interval):
                return False

        log.info(
            "File %s did not stabilize within %.1fs; scanning anyway.",
            filepath,
            self.stable_timeout,
        )
        return True

    def start(self):
        if not os.path.isdir(self.watch_folder):
            log.warning("Watch folder does not exist: %s", self.watch_folder)
            return

        with self._lock:
            self._known_files = self._scan()
        log.info("Monitoring %s (poll every %.1fs)", self.watch_folder, self.poll_interval)

        # _stop_event.wait() blocks for poll_interval seconds but returns immediately
        # when stop() is called, allowing a clean and instant shutdown.
        while not self._stop_event.wait(self.poll_interval):
            current = self._scan()
            with self._lock:
                new_files = current - self._known_files
                self._known_files = current

            for filepath in new_files:
                if not self._wait_until_stable(filepath):
                    continue
                try:
                    self.on_new_file(filepath)
                except Exception:
                    log.exception("Callback failed for %s", filepath)

    def stop(self):
        self._stop_event.set()
        log.info("Monitor stopped")
