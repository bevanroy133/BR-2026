#!/usr/bin/env python3
"""
Securious: Security Advisor - Advanced Edition
A friendly, proactive safety tool designed for elderly and non-technical users.
"""

import logging
import threading
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from modules.ui import SafetyAdvisorApp
from modules.monitor import DownloadMonitor
from modules.email_monitor import EmailMonitor, OAUTH_AUTH_MODES
from modules.config import Config
from modules.provider_adapters import AUTH_MODE_PASSWORD, normalize_oauth_selection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


def _email_monitor_ready(config: Config) -> bool:
    if not config.email_address:
        return False
    auth_mode = str(getattr(config, "email_auth_mode", AUTH_MODE_PASSWORD)).strip().lower()
    oauth_provider = str(getattr(config, "email_oauth_provider", "")).strip().lower()
    _provider, normalized_mode = normalize_oauth_selection(auth_mode, oauth_provider)
    if normalized_mode in OAUTH_AUTH_MODES:
        return bool(config.email_oauth_client_id and config.email_oauth_refresh_token)
    return bool(config.email_password)


def main():
    try:
        config = Config()
    except Exception as exc:
        try:
            err_root = tk.Tk()
            err_root.withdraw()
            messagebox.showerror(
                "Startup Error",
                f"Could not load settings:\n{exc}",
            )
            err_root.destroy()
        except Exception:
            print(f"Fatal: could not load settings: {exc}")
        return

    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("green")

    root = ctk.CTk()

    app = SafetyAdvisorApp(root, config)

    monitor = DownloadMonitor(
        watch_folder=config.downloads_folder,
        on_new_file=app.on_new_download_detected,
    )
    monitor_thread = threading.Thread(target=monitor.start, daemon=True, name="DownloadMonitor")
    monitor_thread.start()

    # Start email monitoring if configured
    email_monitor = None
    email_thread = None
    if _email_monitor_ready(config):
        email_monitor = EmailMonitor(
            email_address=config.email_address,
            email_password=config.email_password,
            imap_server=config.email_imap_server,
            imap_port=config.email_imap_port,
            auth_mode=config.email_auth_mode,
            oauth_client_id=config.email_oauth_client_id,
            oauth_client_secret=config.email_oauth_client_secret,
            oauth_refresh_token=config.email_oauth_refresh_token,
            oauth_provider=config.email_oauth_provider,
            on_new_email=app.on_new_email_detected,
            poll_interval=config.email_poll_interval,
        )
        email_thread = threading.Thread(target=email_monitor.start, daemon=True, name="EmailMonitor")
        email_thread.start()
        log.info("Email monitoring started for %s", config.email_address)

    def on_close():
        log.info("Shutting down...")
        monitor.stop()
        monitor_thread.join(timeout=2.0)
        if email_monitor:
            email_monitor.stop()
        if email_thread:
            email_thread.join(timeout=2.0)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    log.info("App started, monitoring %s", config.downloads_folder)
    root.mainloop()


if __name__ == "__main__":
    main()
