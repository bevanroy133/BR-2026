"""
ui.py - Main GUI for Securious: Security Advisor (Advanced Edition)
Designed for elderly and non-technical users: large text, clear colours, simple layout.
"""

import logging
import os
import platform
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, font as tkfont, messagebox

import customtkinter as ctk

try:
    import send2trash as _send2trash
    _SEND2TRASH_AVAILABLE = True
except ImportError:
    _send2trash = None
    _SEND2TRASH_AVAILABLE = False

from modules.analyzer import analyze_file, analyze_url, format_file_size, RISK_SAFE, RISK_CAUTION, RISK_DANGER
from modules.email_analyzer import analyze_email_message, analyze_eml_file
from modules.email_monitor import (
    EmailMonitor,
    AUTH_PASSWORD,
    OAUTH_AUTH_MODES,
)
from modules.provider_adapters import (
    get_oauth_adapter,
    list_oauth_adapters,
    normalize_oauth_selection,
    oauth_auth_modes,
)
from modules.google_oauth import (
    OAuthError,
    oauth_provider_display_name,
    run_oauth_flow,
)
from modules.domain_db import get_domain_db
from modules.contact import compose_message, open_mailto
from modules.verdict import coerce_verdict_fields

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLOURS = {
    "bg":               "#D6EBE1",
    "panel":            "#FFFFFF",
    "panel_warm":       "#EEF5F2",
    "accent":           "#1F5D4D",
    "accent_light":     "#C8E4D8",
    "coast":            "#2B7E87",
    "coast_light":      "#D8ECEF",
    "industrial":       "#5C6870",
    "industrial_light": "#DDE2E6",
    "safe":             "#237248",
    "safe_bg":          "#E3F3E8",
    "caution":          "#A86415",
    "caution_bg":       "#FEF3E3",
    "danger":           "#9B2C2C",
    "danger_bg":        "#FCECED",
    "text":             "#1F2B27",
    "subtext":          "#4E5E58",
    "border":           "#B5C6BC",
    "button":           "#2E7B62",
    "button_text":      "#F7FCF8",
    "button_hover":     "#225B49",
    "tab_bar":          "#3B8A72",
    "tab_active":       "#FFFFFF",
    "tab_inactive":     "#A8D5C4",
    "tab_inactive_hover": "#C2E3D6",
    "tab_text":         "#FFFFFF",
    "tab_text_inactive": "#1A4D3E",
    "input_bg":         "#FFFFFF",
    "input_border":     "#9EB3A8",
    "input_focus":      "#2B7E87",
    "status_bg":        "#DCE9E2",
    "prompt_bg":        "#E9F0F2",
}

RISK_COLOURS = {
    RISK_SAFE:    (COLOURS["safe"],    COLOURS["safe_bg"],    "✅ SAFE"),
    RISK_CAUTION: (COLOURS["caution"], COLOURS["caution_bg"], "⚠️ CAUTION"),
    RISK_DANGER:  (COLOURS["danger"],  COLOURS["danger_bg"],  "🛑 DANGER"),
}

_TAB_LABELS = [
    ("file",     "📁  Check a File"),
    ("url",      "🌐  Check a Website"),
    ("email",    "📧  Check Email"),
    ("history",  "📋  Past Checks"),
    ("settings", "⚙️  Settings"),
]
_TAB_KEY_TO_NAME = {k: n for k, n in _TAB_LABELS}
_TAB_NAME_TO_KEY = {n: k for k, n in _TAB_LABELS}


class SafetyAdvisorApp:
    def __init__(self, root: ctk.CTk, config):
        self.root = root
        self.config = config
        self.last_scan_result = None
        self._platform = platform.system()
        self._status_clear_id: str | None = None
        self._inbox_cancel: threading.Event | None = None
        self._inbox_conn = None
        self._check_inbox_btn: ctk.CTkButton | None = None
        self._cancel_inbox_btn: ctk.CTkButton | None = None
        self._protection_banners: list[ctk.CTkFrame] = []
        self._api_nudge_shown = False
        self._setup_fonts()
        self._build_window()

    # ------------------------------------------------------------------
    # Font setup
    # ------------------------------------------------------------------
    def _setup_fonts(self):
        base = 15  # Larger base for accessibility
        ui_family = self._pick_font_family("Trebuchet MS", "Segoe UI", "Calibri", "Verdana")
        title_family = self._pick_font_family("Book Antiqua", "Georgia", "Constantia", ui_family)
        self._ui_family = ui_family
        self.font_title = (title_family, base + 6, "bold")
        self.font_heading = (ui_family, base + 2, "bold")
        self.font_body = (ui_family, base)
        self.font_small = (ui_family, base - 2)
        self.font_button = (ui_family, base, "bold")
        self.font_risk = (ui_family, base + 8, "bold")
        self.font_tab = (ui_family, base - 1, "bold")

    def _pick_font_family(self, *choices: str) -> str:
        available = {name.lower(): name for name in tkfont.families()}
        for choice in choices:
            match = available.get(choice.lower())
            if match:
                return match
        return "TkDefaultFont"

    # ------------------------------------------------------------------
    # Window construction
    # ------------------------------------------------------------------
    def _build_window(self):
        self.root.title("Securious: Security Advisor")
        self.root.geometry("860x720")
        self.root.minsize(700, 600)
        self.root.configure(fg_color=COLOURS["bg"])
        self.root.resizable(True, True)
        self._build_menubar()

        self._build_header()
        self._build_statusbar()

        self.tabview = ctk.CTkTabview(
            self.root,
            fg_color=COLOURS["bg"],
            segmented_button_fg_color=COLOURS["tab_bar"],
            segmented_button_selected_color=COLOURS["tab_active"],
            segmented_button_selected_hover_color=COLOURS["accent_light"],
            segmented_button_unselected_color=COLOURS["tab_inactive"],
            segmented_button_unselected_hover_color=COLOURS["tab_inactive_hover"],
            corner_radius=8,
        )
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        for _key, name in _TAB_LABELS:
            self.tabview.add(name)
        self.tabview.configure(command=self._on_tab_changed)
        self.tabview._segmented_button.configure(
            font=self.font_tab,
            text_color=COLOURS["accent"],
        )

        self._build_file_page()
        self._build_url_page()
        self._build_email_page()
        self._build_history_page()
        self._build_settings_page()

        self.tabview.set(_TAB_KEY_TO_NAME["file"])
        self._active_tab = "file"

        if self._is_first_run():
            self.root.after(400, self._show_welcome_prompt)

    def _build_header(self):
        hdr = ctk.CTkFrame(self.root, fg_color=COLOURS["accent"], corner_radius=0)
        hdr.pack(fill="x")
        inner = ctk.CTkFrame(hdr, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=14)

        ctk.CTkLabel(
            inner, text="🛡  Securious: Security Advisor",
            font=self.font_title, text_color=COLOURS["button_text"],
        ).pack(side="left")
        ctk.CTkLabel(
            inner, text="Your personal safety assistant",
            font=self.font_small, text_color=COLOURS["coast_light"],
        ).pack(side="left", padx=(8, 0))

        ctk.CTkButton(
            inner, text="🛡  Need Help?",
            font=self.font_heading,
            fg_color="#FFFFFF", text_color=COLOURS["accent"],
            hover_color=COLOURS["coast_light"],
            corner_radius=8, height=40, cursor="hand2",
            command=self._show_how_to_use_help,
        ).pack(side="right")

        ctk.CTkFrame(self.root, fg_color=COLOURS["coast"], height=4, corner_radius=0).pack(fill="x")

    def _build_menubar(self):
        menubar = tk.Menu(self.root, font=self.font_body)
        help_menu = tk.Menu(menubar, tearoff=0, font=self.font_body)
        help_menu.add_command(
            label="🛡  How to Use This App",
            command=self._show_how_to_use_help,
        )
        help_menu.add_command(
            label="📁  How to Check a File",
            command=lambda: self._show_info_popup(
                "How to Check a File",
                "1. Click the \"Check a File\" tab at the top.\n"
                "2. Click the big \"Choose a File\" button.\n"
                "3. Find the file on your computer and select it.\n"
                "4. The app will check it and show you a result:\n"
                "   - Green (SAFE) = looks okay\n"
                "   - Yellow (CAUTION) = be careful, verify first\n"
                "   - Red (DANGER) = do not open it!\n\n"
                "The app also watches your Downloads folder automatically. "
                "When a new file appears, it will ask if you want to check it.",
            ),
        )
        help_menu.add_command(
            label="🌐  How to Check a Website",
            command=lambda: self._show_info_popup(
                "How to Check a Website",
                "1. Click the \"Check a Website\" tab at the top.\n"
                "2. Type or paste the website address (e.g. www.example.com).\n"
                "3. Click the big \"Check This Website\" button.\n"
                "4. The app will tell you if the website looks safe or suspicious.\n\n"
                "This is useful when you receive a link in an email or message "
                "and you're not sure if it's real.",
            ),
        )
        help_menu.add_command(
            label="📧  How to Check Email",
            command=lambda: self._show_info_popup(
                "How to Check Email",
                "There are two ways to check emails:\n\n"
                "Option 1: Check your inbox\n"
                "1. First, set up your email in Settings (click the ⚙️ Settings tab).\n"
                "2. Then go to the \"Check Email\" tab.\n"
                "3. Click \"Check My Inbox Now\".\n"
                "4. The app will look at your recent unread messages and warn you "
                "about any suspicious ones.\n\n"
                "Option 2: Check a saved email file\n"
                "1. If someone sent you a .eml file, go to the \"Check Email\" tab.\n"
                "2. Click \"Open a .eml File\" and select the file.\n\n"
                "Email monitoring is completely optional — it's up to you!",
            ),
        )
        help_menu.add_separator()
        help_menu.add_command(
            label="⚙️  Go to Settings",
            command=lambda: self._show_tab("settings"),
        )
        help_menu.add_separator()
        help_menu.add_command(
            label="ℹ️  About Securious",
            command=lambda: self._show_info_popup(
                "About Securious: Security Advisor",
                "Securious: Security Advisor is a free safety tool designed for "
                "everyone — especially people who are new to computers.\n\n"
                "What it does:\n"
                "• Checks files before you open them\n"
                "• Checks websites before you visit them\n"
                "• Checks emails for scams and phishing\n"
                "• Watches your Downloads folder for new files\n"
                "• Lets you ask a trusted contact for help\n\n"
                "Everything runs on your computer. No files or personal "
                "data are uploaded without your knowledge.\n\n"
                "Need help with anything? Click the "
                "\"🛡 Securious The Saviour\" button "
                "in Settings for step-by-step guidance!",
            ),
        )
        menubar.add_cascade(label=" 🛡 Help ", menu=help_menu)
        self.root.config(menu=menubar)

    def _on_tab_changed(self):
        name = self.tabview.get()
        key = _TAB_NAME_TO_KEY.get(name, "file")
        self._active_tab = key
        if key == "history":
            self._refresh_history()

    def _show_tab(self, key: str):
        name = _TAB_KEY_TO_NAME.get(key)
        if name:
            self.tabview.set(name)
        self._active_tab = key
        if key == "history":
            self._refresh_history()

    def _download_folder_help_text(self) -> str:
        home = os.path.expanduser("~")
        if self._platform == "Windows":
            examples = (
                f"- {home}\\Downloads (best default)\n"
                f"- {home}\\Desktop\n"
                f"- {home}\\Documents\n"
                "- C:\\Users\\<you>\\AppData\\Local\\Temp (advanced users)"
            )
        elif self._platform == "Darwin":
            examples = (
                f"- {home}/Downloads (best default)\n"
                f"- {home}/Desktop\n"
                f"- {home}/Documents\n"
                "- /private/tmp (advanced users)"
            )
        else:
            examples = (
                f"- {home}/Downloads (best default)\n"
                f"- {home}/Desktop\n"
                f"- {home}/Documents\n"
                "- /tmp (advanced users)"
            )

        return (
            "What does 'Downloads Folder to Watch' mean?\n\n"
            "This is the folder the app watches for newly downloaded files.\n"
            "When a new file appears there, the app can prompt you to scan it for safety.\n\n"
            "High-risk folders you may want to monitor:\n"
            "- Downloads folder\n"
            "- Desktop (people often save email attachments here)\n"
            "- Documents (shared files and invoices often land here)\n"
            "- Temporary folders (advanced users)\n"
            "- Cloud sync folders if they receive files automatically (OneDrive, Dropbox, Google Drive)\n\n"
            "Recommended approach:\n"
            "Start with your Downloads folder. If you frequently save files elsewhere,\n"
            "set this to the folder where unknown files usually appear first.\n\n"
            "Common folder examples for your computer:\n"
            f"{examples}"
        )

    def _show_how_to_use_help(self):
        self._show_info_popup(
            "How to Use This App",
            "Welcome! Here's a quick guide to get started.\n\n"
            "═══════════════════════════════════════\n"
            "THE TABS AT THE TOP\n"
            "═══════════════════════════════════════\n\n"
            "📁 Check a File\n"
            "Pick any file from your computer and the app will tell you "
            "if it's safe to open.\n\n"
            "🌐 Check a Website\n"
            "Type or paste a website address and the app will tell you "
            "if it looks real or fake.\n\n"
            "📧 Check Email\n"
            "Connect your email to scan for scams (optional), or open "
            "a saved .eml email file.\n\n"
            "📋 Past Checks\n"
            "See everything you've checked before.\n\n"
            "⚙️ Settings\n"
            "Set up your trusted contact, email, and other options. "
            "Each section has a \"🛡 Securious The Saviour\" button "
            "that explains everything.\n\n"
            "═══════════════════════════════════════\n"
            "AUTOMATIC PROTECTION\n"
            "═══════════════════════════════════════\n\n"
            "The app watches your Downloads folder in the background. "
            "When a new file appears, it asks if you'd like to check it.\n\n"
            "═══════════════════════════════════════\n"
            "WHAT DO THE COLOURS MEAN?\n"
            "═══════════════════════════════════════\n\n"
            "✅ Green (SAFE) — No problems found. You can open it.\n"
            "⚠️ Yellow (CAUTION) — Something looks off. Verify before opening.\n"
            "🛑 Red (DANGER) — Do NOT open this! Ask your trusted contact.\n\n"
            "═══════════════════════════════════════\n"
            "NEED MORE HELP?\n"
            "═══════════════════════════════════════\n\n"
            "Go to Settings and click any \"🛡 Securious The Saviour\" "
            "button for detailed help on that section.",
        )

    def _show_download_folder_help(self):
        self._show_info_popup(
            "Downloads Folder Help",
            self._download_folder_help_text(),
        )

    # ------------------------------------------------------------------
    # Protection-level banner (shared across scan tabs)
    # ------------------------------------------------------------------
    def _protection_status(self) -> tuple[str, str, str]:
        """Return (level, text, colour) based on configured API keys."""
        has_vt = bool(self.config.virustotal_api_key)
        has_gsb = bool(self.config.google_safe_browsing_key)
        if has_vt and has_gsb:
            return (
                "full",
                "🛡  Full Protection — scans use VirusTotal + Google Safe Browsing",
                COLOURS["safe"],
            )
        if has_vt:
            return (
                "partial",
                "\u26a0\ufe0f  Partial Protection — add a Google Safe Browsing key for full coverage",
                COLOURS["caution"],
            )
        if has_gsb:
            return (
                "partial",
                "\u26a0\ufe0f  Partial Protection — add a VirusTotal key for full coverage",
                COLOURS["caution"],
            )
        return (
            "basic",
            "\u26a0\ufe0f  Basic Protection only — add free API keys for much stronger scanning",
            COLOURS["caution"],
        )

    def _build_protection_banner(self, parent) -> ctk.CTkFrame:
        """Create a protection-level bar at the top of a scan tab."""
        level, text, fg = self._protection_status()
        bg = COLOURS["safe_bg"] if level == "full" else COLOURS["caution_bg"]

        banner = ctk.CTkFrame(parent, fg_color=bg, corner_radius=8)
        banner.pack(fill="x", pady=(6, 0))

        ctk.CTkLabel(
            banner, text=text,
            font=self.font_small, text_color=fg, anchor="w",
        ).pack(side="left", padx=14, pady=8)

        if level != "full":
            ctk.CTkButton(
                banner, text="Go to Settings",
                font=self.font_small, text_color=COLOURS["accent"],
                fg_color="transparent", hover_color=COLOURS["accent_light"],
                cursor="hand2", width=0, height=28,
                command=lambda: self._show_tab("settings"),
            ).pack(side="right", padx=(0, 14), pady=8)

        self._protection_banners.append(banner)
        return banner

    def _refresh_protection_banners(self):
        """Rebuild every protection banner in-place after keys change."""
        level, text, fg = self._protection_status()
        bg = COLOURS["safe_bg"] if level == "full" else COLOURS["caution_bg"]

        for banner in self._protection_banners:
            if not banner.winfo_exists():
                continue
            for w in banner.winfo_children():
                w.destroy()
            banner.configure(fg_color=bg)
            ctk.CTkLabel(
                banner, text=text,
                font=self.font_small, text_color=fg, anchor="w",
            ).pack(side="left", padx=14, pady=8)
            if level != "full":
                ctk.CTkButton(
                    banner, text="Go to Settings",
                    font=self.font_small, text_color=COLOURS["accent"],
                    fg_color="transparent", hover_color=COLOURS["accent_light"],
                    cursor="hand2", width=0, height=28,
                    command=lambda: self._show_tab("settings"),
                ).pack(side="right", padx=(0, 14), pady=8)

    # ------------------------------------------------------------------
    # File check page
    # ------------------------------------------------------------------
    def _build_file_page(self):
        page = self.tabview.tab(_TAB_KEY_TO_NAME["file"])

        self._build_protection_banner(page)

        card, content = self._hero_card(page)
        ctk.CTkLabel(
            content, text="📁  Check a File Before Opening It",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", pady=(0, 6))
        self._wrap_label(
            content,
            text=(
                "Not sure if a file is safe to open? Click the big button below to select it.\n"
                "We'll check it and tell you in plain English whether it looks safe."
            ),
            font=self.font_body, fg=COLOURS["text"],
        ).pack(fill="x")
        card.pack(fill="x", pady=(10, 4))

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        self._make_big_button(
            btn_frame,
            "📂   Browse for a File...",
            self._on_browse_file,
            width=360,
        ).pack(pady=6)

        ctk.CTkLabel(
            btn_frame,
            text="— or wait: we'll automatically check new files as they appear in your Downloads folder —",
            font=self.font_small, text_color=COLOURS["subtext"],
        ).pack()

        self.file_result_frame = ctk.CTkFrame(page, fg_color="transparent")
        self.file_result_frame.pack(fill="both", expand=True, pady=4)

    def _on_browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select a file to check",
            parent=self.root
        )
        if filepath:
            self._run_file_scan(filepath)

    def _run_file_scan(self, filepath: str):
        self._set_status("Checking file, please wait…")
        self._show_scanning(self.file_result_frame)

        def worker():
            try:
                result = analyze_file(
                    filepath,
                    vt_api_key=self.config.virustotal_api_key
                )
                self.config.add_scan_history(result)
                self.last_scan_result = result
                self._safe_after(lambda r=result: self._display_result(r, self.file_result_frame))
                self._safe_after(lambda: self._set_status("Ready"))
            except Exception as exc:
                log.exception("File scan failed for %s", filepath)
                err_text = (
                    "Something went wrong while checking this file.\n\n"
                    f"Error: {exc}\n\nPlease try again."
                )
                self._safe_after(lambda msg=err_text: self._show_message(
                    self.file_result_frame,
                    msg,
                    RISK_CAUTION,
                ))
                self._safe_after(lambda: self._set_status("Check failed - see details above"))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # URL check page
    # ------------------------------------------------------------------
    def _build_url_page(self):
        page = self.tabview.tab(_TAB_KEY_TO_NAME["url"])

        self._build_protection_banner(page)

        card, content = self._hero_card(page)
        ctk.CTkLabel(
            content, text="🌐  Check a Website Before Visiting It",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", pady=(0, 6))
        self._wrap_label(
            content,
            text=(
                "Got a link in an email or message and not sure if it's safe?\n"
                "Copy and paste the web address below and press 'Check This Website'."
            ),
            font=self.font_body, fg=COLOURS["text"],
        ).pack(fill="x")
        card.pack(fill="x", pady=(10, 4))

        entry_card, entry_content = self._card(page)
        ctk.CTkLabel(
            entry_content, text="Paste the web address here:",
            font=self.font_body, text_color=COLOURS["text"], anchor="w",
        ).pack(fill="x", pady=(0, 6))

        self.url_entry_var = tk.StringVar()
        url_entry = ctk.CTkEntry(
            entry_content, textvariable=self.url_entry_var,
            font=self.font_body, fg_color=COLOURS["input_bg"],
            text_color=COLOURS["text"], border_color=COLOURS["input_border"],
            corner_radius=6, height=36,
            placeholder_text="e.g. https://example.com",
        )
        url_entry.pack(fill="x", pady=(0, 10))
        url_entry.bind("<Return>", lambda e: self._on_check_url())

        self._make_big_button(entry_content, "🔍   Check This Website", self._on_check_url, width=300).pack(pady=4)
        entry_card.pack(fill="x", pady=(0, 4))

        self.url_result_frame = ctk.CTkFrame(page, fg_color="transparent")
        self.url_result_frame.pack(fill="both", expand=True, pady=4)

    def _on_check_url(self):
        url = self.url_entry_var.get().strip()
        if not url:
            self._show_message(self.url_result_frame, "Please paste a web address first.", RISK_CAUTION)
            return
        test_url = url if url.startswith(("http://", "https://")) else "https://" + url
        if "." not in test_url.split("//", 1)[-1].split("/")[0]:
            self._show_message(
                self.url_result_frame,
                "That doesn't look like a web address. Please check it and try again.\n\n"
                "Example:  www.google.com  or  https://www.bbc.co.uk",
                RISK_CAUTION,
            )
            return
        self._set_status("Checking website, please wait…")
        self._show_scanning(self.url_result_frame)

        def worker():
            try:
                result = analyze_url(url, gsb_api_key=self.config.google_safe_browsing_key)
                self.config.add_scan_history(result)
                self.last_scan_result = result
                self._safe_after(lambda r=result: self._display_result(r, self.url_result_frame))
                self._safe_after(lambda: self._set_status("Ready"))
            except Exception as exc:
                log.exception("URL scan failed for %s", url)
                err_text = (
                    "Something went wrong while checking this website.\n\n"
                    f"Error: {exc}\n\nPlease try again."
                )
                self._safe_after(lambda msg=err_text: self._show_message(
                    self.url_result_frame,
                    msg,
                    RISK_CAUTION,
                ))
                self._safe_after(lambda: self._set_status("Check failed - see details above"))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Email check page
    # ------------------------------------------------------------------
    def _build_email_page(self):
        page = self.tabview.tab(_TAB_KEY_TO_NAME["email"])

        self._build_protection_banner(page)

        card, content = self._hero_card(page)
        ctk.CTkLabel(
            content, text="📧  Check Your Emails for Scams",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", pady=(0, 6))
        self._wrap_label(
            content,
            text=(
                "Connect your email account to scan incoming messages for phishing,\n"
                "suspicious links, and dangerous attachments. You can also check\n"
                "a saved .eml file from your computer."
            ),
            font=self.font_body, fg=COLOURS["text"],
        ).pack(fill="x")
        card.pack(fill="x", pady=(10, 4))

        btn_frame = ctk.CTkFrame(page, fg_color="transparent")
        btn_frame.pack(fill="x", pady=6)

        self._check_inbox_btn = self._make_big_button(
            btn_frame,
            "📥   Check My Inbox Now",
            self._on_check_inbox,
            width=300,
        )
        self._check_inbox_btn.pack(side="left", padx=(0, 10), pady=6)

        self._cancel_inbox_btn = self._make_big_button(
            btn_frame,
            "✖   Cancel Check",
            self._on_cancel_inbox,
            width=200,
            tone="coast",
        )
        self._cancel_inbox_btn.pack_forget()

        self._make_big_button(
            btn_frame,
            "📂   Open a .eml File...",
            self._on_browse_eml,
            width=260,
            tone="coast",
        ).pack(side="left", pady=6)

        self._email_status_frame = ctk.CTkFrame(page, fg_color="transparent")
        self._email_status_frame.pack(fill="x", pady=(0, 4))
        self._email_status_label = ctk.CTkLabel(
            self._email_status_frame, text="",
            font=self.font_small, text_color=COLOURS["subtext"], anchor="w",
        )
        self._email_status_label.pack(fill="x")
        self._update_email_status_label()

        self.email_result_frame = ctk.CTkFrame(page, fg_color="transparent")
        self.email_result_frame.pack(fill="both", expand=True, pady=4)

    def _oauth_provider_for_mode(self, auth_mode: str) -> str | None:
        raw_mode = (auth_mode or "").strip().lower()
        provider = str(getattr(self.config, "email_oauth_provider", "")).strip().lower()
        resolved_provider, normalized_mode = normalize_oauth_selection(raw_mode, provider)
        valid_modes = set(oauth_auth_modes()) | {AUTH_PASSWORD}
        if normalized_mode not in valid_modes:
            return None
        return resolved_provider

    def _oauth_adapter_for_mode(self, auth_mode: str):
        provider = self._oauth_provider_for_mode(auth_mode)
        if not provider:
            return None
        try:
            return get_oauth_adapter(provider)
        except KeyError:
            return None

    def _oauth_provider_display_for_mode(self, auth_mode: str) -> str:
        provider = self._oauth_provider_for_mode(auth_mode)
        return oauth_provider_display_name(provider) if provider else "OAuth2"

    def _update_email_status_label(self):
        email_addr = self.config.email_address
        raw_mode = str(getattr(self.config, "email_auth_mode", AUTH_PASSWORD)).strip().lower()
        _provider, auth_mode = normalize_oauth_selection(
            raw_mode,
            str(getattr(self.config, "email_oauth_provider", "")).strip().lower(),
        )
        if email_addr:
            if auth_mode in OAUTH_AUTH_MODES:
                provider_name = self._oauth_provider_display_for_mode(auth_mode)
                has_oauth = bool(self.config.email_oauth_client_id and self.config.email_oauth_refresh_token)
                text = f"Connected account: {email_addr} ({provider_name} OAuth2)" if has_oauth else (
                    f"Account set: {email_addr} ({provider_name} OAuth2 not authorized yet)"
                )
            else:
                text = f"Connected account: {email_addr} (password/app password mode)"
            self._email_status_label.configure(
                text=text,
                text_color=COLOURS["safe"],
            )
        else:
            self._email_status_label.configure(
                text="No email account configured. Go to Settings -> Email Account to set one up.",
                text_color=COLOURS["caution"],
            )

    def _on_browse_eml(self):
        filepath = filedialog.askopenfilename(
            title="Select an .eml email file to check",
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")],
            parent=self.root,
        )
        if filepath:
            self._run_eml_scan(filepath)

    def _run_eml_scan(self, filepath: str):
        self._set_status("Checking email file, please wait…")
        self._show_scanning(self.email_result_frame)

        def worker():
            try:
                result = analyze_eml_file(
                    filepath,
                    gsb_api_key=self.config.google_safe_browsing_key,
                    vt_api_key=self.config.virustotal_api_key,
                )
                self.config.add_scan_history(result)
                self.last_scan_result = result
                self._safe_after(lambda r=result: self._display_email_result(r, self.email_result_frame))
                self._safe_after(lambda: self._set_status("Ready"))
            except Exception as exc:
                log.exception("Email file scan failed for %s", filepath)
                err_text = (
                    "Something went wrong while checking this email file.\n\n"
                    f"Error: {exc}\n\nPlease try again."
                )
                self._safe_after(lambda msg=err_text: self._show_message(
                    self.email_result_frame, msg, RISK_CAUTION,
                ))
                self._safe_after(lambda: self._set_status("Check failed - see details above"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_cancel_inbox(self):
        if self._inbox_cancel is not None:
            self._inbox_cancel.set()
        conn = getattr(self, "_inbox_conn", None)
        if conn is not None:
            try:
                conn.shutdown()
            except Exception:
                pass
        self._show_message(
            self.email_result_frame, "Cancelling… please wait a moment.", RISK_SAFE,
        )
        self._set_status("Cancelling email check…")

    def _restore_inbox_buttons(self):
        """Re-show the check button and hide the cancel button."""
        if self._cancel_inbox_btn:
            self._cancel_inbox_btn.pack_forget()
        if self._check_inbox_btn:
            self._check_inbox_btn.configure(state="normal")
            self._check_inbox_btn.pack(side="left", padx=(0, 10), pady=6)

    def _on_check_inbox(self):
        email_addr = self.config.email_address
        oauth_provider_cfg = str(getattr(self.config, "email_oauth_provider", "")).strip().lower()
        provider_id, auth_mode = normalize_oauth_selection(
            str(getattr(self.config, "email_auth_mode", AUTH_PASSWORD)).strip().lower(),
            oauth_provider_cfg,
        )
        if auth_mode not in (set(oauth_auth_modes()) | {AUTH_PASSWORD}):
            auth_mode = AUTH_PASSWORD
        oauth_adapter = self._oauth_adapter_for_mode(auth_mode)
        oauth_provider = provider_id or self._oauth_provider_for_mode(auth_mode) or ""
        email_pass = self.config.email_password
        oauth_client_id = self.config.email_oauth_client_id
        oauth_client_secret = self.config.email_oauth_client_secret
        oauth_refresh_token = self.config.email_oauth_refresh_token

        missing = False
        if not email_addr:
            missing = True
        elif auth_mode in OAUTH_AUTH_MODES:
            missing = not (oauth_client_id and oauth_refresh_token)
            if oauth_adapter and oauth_adapter.require_client_secret and not oauth_client_secret:
                missing = True
        else:
            missing = not email_pass

        if missing:
            if auth_mode in OAUTH_AUTH_MODES:
                provider_name = self._oauth_provider_display_for_mode(auth_mode)
                guidance = (
                    f"Go to Settings -> Email Account, select {provider_name} OAuth2, "
                    "save your account details, then click 'Authorize Selected OAuth2'."
                )
                if oauth_adapter and oauth_adapter.require_client_secret:
                    guidance += f" {provider_name} also requires a Client Secret."
            else:
                guidance = (
                    "Go to Settings -> Email Account and enter your email address "
                    "and password (or app password)."
                )
            self._show_message(
                self.email_result_frame,
                "Please set up your email account in Settings first.\n\n"
                f"{guidance}",
                RISK_CAUTION,
            )
            return

        self._set_status("Connecting to your email, please wait…")
        self._show_scanning(self.email_result_frame)

        cancel_event = threading.Event()
        self._inbox_cancel = cancel_event
        if self._check_inbox_btn:
            self._check_inbox_btn.configure(state="disabled")
            self._check_inbox_btn.pack_forget()
        if self._cancel_inbox_btn:
            self._cancel_inbox_btn.pack(side="left", padx=(0, 10), pady=6)

        def _cancelled():
            self._safe_after(lambda: self._show_message(
                self.email_result_frame, "Email check cancelled.", RISK_SAFE,
            ))
            self._safe_after(lambda: self._set_status("Cancelled"))
            self._safe_after(self._restore_inbox_buttons)

        def _close_conn(conn):
            self._inbox_conn = None
            if conn is None:
                return
            try:
                conn.close()
                conn.logout()
            except Exception:
                pass

        def worker():
            conn = None
            try:
                imap_server = self.config.email_imap_server
                imap_port = self.config.email_imap_port
                monitor = EmailMonitor(
                    email_address=email_addr,
                    email_password=email_pass,
                    imap_server=imap_server,
                    imap_port=imap_port,
                    auth_mode=auth_mode,
                    oauth_client_id=oauth_client_id,
                    oauth_client_secret=oauth_client_secret,
                    oauth_refresh_token=oauth_refresh_token,
                    oauth_provider=oauth_provider,
                )

                conn = monitor._connect()
                self._inbox_conn = conn

                if cancel_event.is_set():
                    _close_conn(conn)
                    _cancelled()
                    return

                if conn is None:
                    self._safe_after(lambda err=monitor.last_error: self._show_message(
                        self.email_result_frame,
                        f"Could not connect to your email:\n\n{err}\n\n"
                        "Please check your email settings (address, password, IMAP server).",
                        RISK_CAUTION,
                    ))
                    self._safe_after(lambda: self._set_status("Email check failed"))
                    self._safe_after(self._restore_inbox_buttons)
                    return

                all_uids = monitor._fetch_unseen_uids(conn)
                if cancel_event.is_set():
                    _close_conn(conn)
                    _cancelled()
                    return

                new_uids = [uid for uid in all_uids if uid not in monitor._seen_uids]

                if not new_uids:
                    _close_conn(conn)
                    self._safe_after(lambda: self._show_message(
                        self.email_result_frame,
                        "No new unread emails found in your inbox.\n\n"
                        "All caught up! We'll keep watching for new messages.",
                        RISK_SAFE,
                    ))
                    self._safe_after(lambda: self._set_status("Ready - no new emails"))
                    self._safe_after(self._restore_inbox_buttons)
                    return

                emails = []
                total = len(new_uids)
                for i, uid in enumerate(new_uids, 1):
                    if cancel_event.is_set():
                        _close_conn(conn)
                        _cancelled()
                        return
                    self._safe_after(
                        lambda n=i, t=total: self._set_status(
                            f"Downloading email {n} of {t}…"
                        )
                    )
                    try:
                        fetched = monitor._fetch_messages_batch(conn, [uid])
                        raw = fetched.get(uid)
                        if raw:
                            monitor._seen_uids.add(uid)
                            emails.append((uid, raw))
                    except Exception:
                        if cancel_event.is_set():
                            break
                        log.warning("Failed to fetch UID %s, skipping", uid)

                _close_conn(conn)
                conn = None

                if cancel_event.is_set():
                    _cancelled()
                    return

                if not emails:
                    self._safe_after(lambda: self._show_message(
                        self.email_result_frame,
                        "No new unread emails found in your inbox.\n\n"
                        "All caught up! We'll keep watching for new messages.",
                        RISK_SAFE,
                    ))
                    self._safe_after(lambda: self._set_status("Ready - no new emails"))
                    self._safe_after(self._restore_inbox_buttons)
                    return

                results = []
                for i, (uid, raw) in enumerate(emails, 1):
                    if cancel_event.is_set():
                        _cancelled()
                        return
                    self._safe_after(
                        lambda n=i, t=len(emails): self._set_status(
                            f"Analysing email {n} of {t}…"
                        )
                    )
                    result = analyze_email_message(
                        raw,
                        message_uid=uid,
                        gsb_api_key=self.config.google_safe_browsing_key,
                        vt_api_key=self.config.virustotal_api_key,
                    )
                    results.append(result)

                with self.config.batch_update():
                    for result in results:
                        self.config.add_scan_history(result)

                self._safe_after(lambda r=results: self._display_inbox_results(r))
                self._safe_after(lambda: self._set_status(f"Checked {len(results)} email(s)"))
                self._safe_after(self._restore_inbox_buttons)
            except Exception as exc:
                _close_conn(conn)
                if cancel_event.is_set():
                    _cancelled()
                    return
                log.exception("Inbox check failed")
                self._safe_after(lambda msg=str(exc): self._show_message(
                    self.email_result_frame,
                    f"Something went wrong checking your inbox:\n\n{msg}",
                    RISK_CAUTION,
                ))
                self._safe_after(lambda: self._set_status("Email check failed"))
                self._safe_after(self._restore_inbox_buttons)

        threading.Thread(target=worker, daemon=True).start()

    def _display_inbox_results(self, results: list[dict]):
        self._clear(self.email_result_frame)

        header_card, header_content = self._card(self.email_result_frame)
        danger_count = sum(1 for r in results if r.get("overall_risk") == RISK_DANGER)
        caution_count = sum(1 for r in results if r.get("overall_risk") == RISK_CAUTION)
        safe_count = sum(1 for r in results if r.get("overall_risk") == RISK_SAFE)

        summary = f"Checked {len(results)} email(s): "
        parts = []
        if danger_count:
            parts.append(f"🛑 {danger_count} dangerous")
        if caution_count:
            parts.append(f"⚠️ {caution_count} suspicious")
        if safe_count:
            parts.append(f"✅ {safe_count} safe")
        summary += ", ".join(parts)

        ctk.CTkLabel(
            header_content, text=summary,
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x")
        header_card.pack(fill="x", pady=(4, 4))

        scroll_frame = ctk.CTkScrollableFrame(
            self.email_result_frame, fg_color=COLOURS["bg"],
        )
        scroll_frame.pack(fill="both", expand=True)

        risk_order = {RISK_DANGER: 0, RISK_CAUTION: 1, RISK_SAFE: 2}
        sorted_results = sorted(results, key=lambda r: risk_order.get(r.get("overall_risk", RISK_CAUTION), 1))

        for result in sorted_results:
            risk = result.get("overall_risk", RISK_CAUTION)
            fg_colour, bg_colour, risk_label = RISK_COLOURS.get(
                risk, (COLOURS["caution"], COLOURS["caution_bg"], "⚠️ CAUTION")
            )

            card = ctk.CTkFrame(
                scroll_frame, fg_color=bg_colour, corner_radius=8,
                border_width=1, border_color=COLOURS["industrial_light"],
            )
            card.pack(fill="x", pady=3, padx=2)

            top_row = ctk.CTkFrame(card, fg_color="transparent")
            top_row.pack(fill="x", padx=14, pady=(10, 0))

            ctk.CTkLabel(
                top_row, text=risk_label, font=self.font_button, text_color=fg_colour,
            ).pack(side="left")

            sender = result.get("sender", "")
            subject = result.get("subject", "(no subject)")
            info_text = f"From: {sender}\nSubject: {subject}"
            self._wrap_label(
                top_row, text=info_text,
                font=self.font_body, fg=COLOURS["text"], justify="left",
            ).pack(side="left", padx=(12, 0), fill="x", expand=True)

            btn_row = ctk.CTkFrame(card, fg_color="transparent")
            btn_row.pack(fill="x", padx=14, pady=(6, 10))
            self._make_button(
                btn_row, "View Details",
                lambda r=result: self._show_email_detail_popup(r),
                tone="coast",
            ).pack(side="left", padx=(0, 8))
            self._make_button(
                btn_row, "📄 Report",
                lambda r=result: self._show_risk_report_popup(r),
                tone="industrial",
            ).pack(side="left")

    def _display_email_result(self, result: dict, container):
        """Display a single email analysis result (used for .eml file scans)."""
        self._display_result(result, container)

    def _show_email_detail_popup(self, result: dict):
        """Show email scan details in a popup window."""
        popup = self._popup("Email Scan Details", "720x560")
        popup.configure(fg_color=COLOURS["bg"])

        risk = result.get("overall_risk", "caution")
        fg_colour, bg_colour, risk_label = RISK_COLOURS.get(
            risk, (COLOURS["caution"], COLOURS["caution_bg"], "⚠️ CAUTION")
        )

        banner = ctk.CTkFrame(popup, fg_color=bg_colour, corner_radius=0)
        banner.pack(fill="x")
        banner_inner = ctk.CTkFrame(banner, fg_color="transparent")
        banner_inner.pack(fill="x", padx=20, pady=12)
        ctk.CTkLabel(
            banner_inner, text=risk_label,
            font=self.font_risk, text_color=fg_colour,
        ).pack(side="left")

        verdict = coerce_verdict_fields(result)
        score = verdict.get("risk_score")
        confidence = str(verdict.get("confidence", "")).strip().title()

        meta_parts = []
        if isinstance(score, int):
            meta_parts.append(f"Risk score: {score}/100")
        if confidence:
            meta_parts.append(f"Confidence: {confidence}")
        meta_line = " | ".join(meta_parts) if meta_parts else ""

        info = f"From: {result.get('sender', '')}\nSubject: {result.get('subject', '')}"
        if meta_line:
            info += f"\n{meta_line}"

        ctk.CTkLabel(
            banner_inner, text=info, font=self.font_small,
            text_color=COLOURS["subtext"], justify="left",
        ).pack(side="left", padx=16)

        meta_card, meta_content = self._card(popup)
        meta_items = [
            ("From:", result.get("sender", "")),
            ("To:", result.get("recipient", "")),
            ("Date:", result.get("date", "")),
            ("Subject:", result.get("subject", "")),
            ("Links found:", str(result.get("url_count", 0))),
            ("Attachments:", ", ".join(result.get("attachments", [])) or "None"),
        ]
        for label, value in meta_items:
            row = ctk.CTkFrame(meta_content, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(
                row, text=label, font=self.font_body, text_color=COLOURS["accent"],
                width=140, anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=value, font=self.font_body, text_color=COLOURS["text"],
                anchor="w",
            ).pack(side="left", fill="x", expand=True)
        meta_card.pack(fill="x", padx=16, pady=(8, 4))

        scroll_frame = ctk.CTkScrollableFrame(popup, fg_color=COLOURS["bg"])
        scroll_frame.pack(fill="both", expand=True, padx=16, pady=4)

        for finding in result.get("findings", []):
            frisk = finding.get("risk", "caution")
            ffg, fbg, _ = RISK_COLOURS.get(frisk, (COLOURS["caution"], COLOURS["caution_bg"], ""))
            fcard = ctk.CTkFrame(scroll_frame, fg_color=fbg, corner_radius=8,
                                 border_width=1, border_color=COLOURS["industrial_light"])
            fcard.pack(fill="x", pady=4, padx=2)
            self._wrap_label(fcard, text=finding["title"],
                             font=self.font_heading, fg=ffg).pack(fill="x", padx=14, pady=(10, 0))
            self._wrap_label(fcard, text=finding["detail"],
                             font=self.font_body, fg=COLOURS["text"]).pack(fill="x", padx=14, pady=(4, 10))

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(6, 16))
        self._make_button(btn_row, "📄  View Report", lambda r=result: self._show_risk_report_popup(r), tone="industrial").pack(side="left", padx=(0, 8))
        self._make_button(btn_row, "Copy Report", lambda r=result: self._copy_risk_report_to_clipboard(r), tone="industrial").pack(side="left", padx=(0, 8))
        if self.config.trusted_contact_email:
            self._make_button(
                btn_row,
                f"📨  Ask {self.config.trusted_contact_name or 'My Trusted Contact'}",
                lambda r=result: self._ask_for_help(r),
                tone="industrial",
            ).pack(side="left", padx=(0, 8))
        self._make_button(btn_row, "Close", popup.destroy, tone="coast").pack(side="right")

    def on_new_email_detected(self, uid: str, raw_bytes: bytes):
        """Called by the EmailMonitor when a new email arrives."""
        self._safe_after(lambda u=uid, r=raw_bytes: self._auto_email_scan(u, r))

    def _auto_email_scan(self, uid: str, raw_bytes: bytes):
        """Automatically scan a new email and show a popup."""
        def worker():
            try:
                result = analyze_email_message(
                    raw_bytes,
                    message_uid=uid,
                    gsb_api_key=self.config.google_safe_browsing_key,
                    vt_api_key=self.config.virustotal_api_key,
                )
                self.config.add_scan_history(result)
                if result.get("overall_risk") != RISK_SAFE:
                    self._safe_after(lambda r=result: self._auto_email_popup(r))
            except Exception:
                log.exception("Auto email scan failed for UID %s", uid)

        threading.Thread(target=worker, daemon=True).start()

    def _auto_email_popup(self, result: dict):
        """Show a popup alert when a suspicious email is detected."""
        risk = result.get("overall_risk", RISK_CAUTION)
        fg_colour, bg_colour, risk_label = RISK_COLOURS.get(
            risk, (COLOURS["caution"], COLOURS["caution_bg"], "⚠️ CAUTION")
        )

        popup = self._popup("Suspicious Email Detected!", "620x360", resizable=False)
        popup.configure(fg_color=COLOURS["prompt_bg"])

        shell = ctk.CTkFrame(popup, fg_color=COLOURS["industrial"], corner_radius=10)
        shell.pack(fill="both", expand=True, padx=18, pady=18)
        body = ctk.CTkFrame(shell, fg_color=COLOURS["prompt_bg"], corner_radius=8)
        body.pack(fill="both", expand=True, padx=2, pady=2)

        ctk.CTkLabel(
            body, text="Prompt: Suspicious email detected",
            font=self.font_small, text_color=COLOURS["industrial"], anchor="w",
        ).pack(fill="x", padx=18, pady=(16, 0))

        self._wrap_label(
            body,
            text=f"{risk_label}  A suspicious email was found in your inbox!",
            font=self.font_heading, fg=fg_colour,
        ).pack(fill="x", padx=18, pady=(6, 6))

        sender = result.get("sender", "Unknown")
        subject = result.get("subject", "(no subject)")
        ctk.CTkLabel(
            body, text=f"From: {sender}\nSubject: {subject}",
            font=self.font_body, text_color=COLOURS["text"],
            anchor="w", justify="left",
        ).pack(fill="x", padx=18, pady=2)

        self._wrap_label(
            body,
            text="Would you like to see the full security analysis?",
            font=self.font_body, fg=COLOURS["subtext"],
        ).pack(fill="x", padx=18, pady=(4, 10))

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(anchor="w", padx=18, pady=(0, 16))

        def view_details():
            popup.destroy()
            self._show_tab("email")
            self._display_email_result(result, self.email_result_frame)

        self._make_button(btn_row, "✅  Show me the details", view_details, tone="coast").pack(side="left", padx=(0, 10))
        self._make_button(btn_row, "Dismiss", popup.destroy, tone="industrial").pack(side="left")

    # ------------------------------------------------------------------
    # History page
    # ------------------------------------------------------------------
    def _build_history_page(self):
        page = self.tabview.tab(_TAB_KEY_TO_NAME["history"])

        hdr_card, hdr_content = self._card(page)
        ctk.CTkLabel(
            hdr_content, text="📋  Your Past Checks",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            hdr_content,
            text="Here is a list of files and websites you've checked before.",
            font=self.font_body, text_color=COLOURS["subtext"], anchor="w",
        ).pack(fill="x")
        hdr_card.pack(fill="x", pady=(10, 4))

        list_frame = ctk.CTkFrame(page, fg_color="transparent")
        list_frame.pack(fill="both", expand=True)

        scrollbar = ctk.CTkScrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self.history_listbox = tk.Listbox(
            list_frame,
            font=self.font_body,
            yscrollcommand=scrollbar.set,
            selectbackground=COLOURS["coast"],
            selectforeground=COLOURS["button_text"],
            bg=COLOURS["panel_warm"],
            fg=COLOURS["text"],
            bd=0, relief="flat",
            activestyle="none",
            height=18,
        )
        self.history_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.configure(command=self.history_listbox.yview)

        self.history_listbox.bind("<<ListboxSelect>>", self._on_history_select)

        btn_row = ctk.CTkFrame(page, fg_color="transparent")
        btn_row.pack(pady=8)
        self._make_button(btn_row, "Refresh List", self._refresh_history).pack(side="left", padx=(0, 8))
        self._make_button(btn_row, "🗑️  Clear All History", self._clear_history, tone="industrial").pack(side="left")

    def _refresh_history(self):
        self.history_listbox.delete(0, "end")
        for entry in self.config.scan_history:
            scanned_at = entry.get("scanned_at", "")[:16].replace("T", " ")
            risk = entry.get("overall_risk", "?").upper()
            verdict = coerce_verdict_fields(entry)
            score = verdict.get("risk_score")
            score_text = f"{score:>3}/100" if isinstance(score, int) else "--/100"
            scan_type = entry.get("type", "")
            if scan_type == "file":
                label = f"[{scanned_at}]  {risk:<8}  {score_text}  📁 {entry.get('filename','?')}"
            elif scan_type == "email":
                sender = entry.get("sender_email", "?")
                subject = entry.get("subject", "(no subject)")[:40]
                label = f"[{scanned_at}]  {risk:<8}  {score_text}  📧 {sender} - {subject}"
            else:
                label = f"[{scanned_at}]  {risk:<8}  {score_text}  🌐 {entry.get('url','?')}"
            self.history_listbox.insert("end", label)

    def _on_history_select(self, _event=None):
        selection = self.history_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        history = self.config.scan_history
        if idx >= len(history):
            return
        entry = history[idx]
        self._show_history_detail(entry)

    def _clear_history(self):
        if not self.config.scan_history:
            self._set_status_temp("History is already empty.")
            return
        confirmed = messagebox.askyesno(
            "Clear History?",
            "Are you sure you want to delete all past scan results?\n\n"
            "This cannot be undone.",
            parent=self.root,
        )
        if not confirmed:
            return
        self.config.clear_scan_history()
        self._refresh_history()
        self._set_status_temp("Scan history cleared ✓")

    def _show_history_detail(self, entry: dict):
        popup = self._popup("Scan Details", "680x520")
        popup.configure(fg_color=COLOURS["bg"])

        scanned_at = entry.get("scanned_at", "")[:16].replace("T", " ")
        risk = entry.get("overall_risk", "caution")
        fg_colour, bg_colour, risk_label = RISK_COLOURS.get(
            risk, (COLOURS["caution"], COLOURS["caution_bg"], "⚠️ CAUTION")
        )

        banner = ctk.CTkFrame(popup, fg_color=bg_colour, corner_radius=0)
        banner.pack(fill="x")
        banner_inner = ctk.CTkFrame(banner, fg_color="transparent")
        banner_inner.pack(fill="x", padx=20, pady=12)
        ctk.CTkLabel(
            banner_inner, text=risk_label,
            font=self.font_risk, text_color=fg_colour,
        ).pack(side="left")
        name = entry.get("filename") or entry.get("url", "")
        verdict = coerce_verdict_fields(entry)
        score = verdict.get("risk_score")
        confidence = str(verdict.get("confidence", "")).strip().title()
        subtitle = f"{name}  •  {scanned_at}"
        if isinstance(score, int) or confidence:
            meta = []
            if isinstance(score, int):
                meta.append(f"Risk score: {score}/100")
            if confidence:
                meta.append(f"Confidence: {confidence}")
            subtitle = f"{subtitle}\n{' | '.join(meta)}"
        ctk.CTkLabel(
            banner_inner, text=subtitle,
            font=self.font_small, text_color=COLOURS["subtext"], justify="left",
        ).pack(side="left", padx=16)

        scroll_frame = ctk.CTkScrollableFrame(popup, fg_color=COLOURS["bg"])
        scroll_frame.pack(fill="both", expand=True, padx=16, pady=8)

        for finding in entry.get("findings", []):
            frisk = finding.get("risk", "caution")
            ffg, fbg, _ = RISK_COLOURS.get(frisk, (COLOURS["caution"], COLOURS["caution_bg"], ""))
            card = ctk.CTkFrame(scroll_frame, fg_color=fbg, corner_radius=8,
                                border_width=1, border_color=COLOURS["industrial_light"])
            card.pack(fill="x", pady=4, padx=2)
            self._wrap_label(card, text=finding["title"],
                             font=self.font_heading, fg=ffg).pack(fill="x", padx=14, pady=(10, 0))
            self._wrap_label(card, text=finding["detail"],
                             font=self.font_body, fg=COLOURS["text"]).pack(fill="x", padx=14, pady=(4, 10))

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(6, 16))
        self._make_button(btn_row, "📄  View Report", lambda r=entry: self._show_risk_report_popup(r), tone="industrial").pack(side="left", padx=(0, 8))
        self._make_button(btn_row, "Copy Report", lambda r=entry: self._copy_risk_report_to_clipboard(r), tone="industrial").pack(side="left", padx=(0, 8))
        self._make_button(btn_row, "Close", popup.destroy, tone="coast").pack(side="right")

    # ------------------------------------------------------------------
    # Settings page
    # ------------------------------------------------------------------
    def _build_settings_page(self):
        page = self.tabview.tab(_TAB_KEY_TO_NAME["settings"])

        content = ctk.CTkScrollableFrame(page, fg_color=COLOURS["bg"])
        content.pack(fill="both", expand=True)

        # --- Trusted Contact ---
        contact_card, contact_inner = self._card(content)
        contact_header = ctk.CTkFrame(contact_inner, fg_color="transparent")
        contact_header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            contact_header, text="👤  Your Trusted Contact",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(side="left", fill="x", expand=True)
        self._make_info_button(
            contact_header,
            "What is a Trusted Contact?",
            "A trusted contact is someone you trust to help you stay safe online "
            "— for example, a family member, friend, or caregiver.\n\n"
            "When this app finds something suspicious (like a dangerous file or "
            "a scam email), you'll see an \"Ask for Help\" button. Clicking it "
            "opens your email app with a pre-written message to your trusted contact, "
            "explaining what was found and asking them to take a look.\n\n"
            "How to set it up:\n"
            "1. Type their name in the \"Their name\" box.\n"
            "2. Type their email address in the \"Their email address\" box.\n"
            "3. Click \"Save Contact\".\n\n"
            "That's it! You can change it any time.",
        ).pack(side="right")
        ctk.CTkLabel(
            contact_inner,
            text="When something looks suspicious, you can send them a message for help.",
            font=self.font_body, text_color=COLOURS["subtext"], anchor="w",
        ).pack(fill="x", pady=(0, 8))

        self._contact_name_var = tk.StringVar(value=self.config.trusted_contact_name)
        self._contact_email_var = tk.StringVar(value=self.config.trusted_contact_email)

        for label, var in [("Their name:", self._contact_name_var), ("Their email address:", self._contact_email_var)]:
            row = ctk.CTkFrame(contact_inner, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, font=self.font_body, text_color=COLOURS["text"], width=220, anchor="w").pack(side="left")
            ctk.CTkEntry(
                row, textvariable=var, font=self.font_body,
                fg_color=COLOURS["input_bg"], text_color=COLOURS["text"],
                border_color=COLOURS["input_border"], corner_radius=6, height=36,
            ).pack(side="left", fill="x", expand=True)

        contact_save_row = ctk.CTkFrame(contact_inner, fg_color="transparent")
        contact_save_row.pack(fill="x", pady=(10, 0))
        self._make_button(contact_save_row, "💾  Save Contact", self._save_contact).pack(side="left")
        self._contact_save_label = ctk.CTkLabel(
            contact_save_row, text="", font=self.font_body,
            text_color=COLOURS["safe"], anchor="w",
        )
        self._contact_save_label.pack(side="left", padx=(12, 0))
        contact_card.pack(fill="x", pady=(10, 4), padx=(0, 10))

        # --- Downloads Folder ---
        dl_card, dl_inner = self._card(content)
        dl_header = ctk.CTkFrame(dl_inner, fg_color="transparent")
        dl_header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            dl_header, text="📂  Downloads Folder to Watch",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(side="left", fill="x", expand=True)
        self._make_info_button(
            dl_header,
            "Downloads Folder Help",
            self._download_folder_help_text(),
        ).pack(side="right")
        ctk.CTkLabel(
            dl_inner,
            text="We'll automatically check any file that appears here.",
            font=self.font_body, text_color=COLOURS["subtext"], anchor="w",
        ).pack(fill="x", pady=(0, 8))

        self._dl_folder_var = tk.StringVar(value=self.config.downloads_folder)
        row = ctk.CTkFrame(dl_inner, fg_color="transparent")
        row.pack(fill="x", pady=3)
        ctk.CTkEntry(
            row, textvariable=self._dl_folder_var, font=self.font_body,
            fg_color=COLOURS["input_bg"], text_color=COLOURS["text"],
            border_color=COLOURS["input_border"], corner_radius=6, height=36,
        ).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(
            row, text="Browse…", font=self.font_small,
            fg_color=COLOURS["button"], text_color=COLOURS["button_text"],
            hover_color=COLOURS["button_hover"], corner_radius=6,
            width=80, height=36, cursor="hand2",
            command=self._browse_dl_folder,
        ).pack(side="left", padx=(6, 0))

        dl_save_row = ctk.CTkFrame(dl_inner, fg_color="transparent")
        dl_save_row.pack(fill="x", pady=(10, 0))
        self._make_button(dl_save_row, "💾  Save Folder", self._save_dl_folder).pack(side="left")
        self._dl_save_label = ctk.CTkLabel(
            dl_save_row, text="", font=self.font_body,
            text_color=COLOURS["safe"], anchor="w",
        )
        self._dl_save_label.pack(side="left", padx=(12, 0))
        dl_card.pack(fill="x", pady=(0, 4), padx=(0, 10))

        # --- Email Account ---
        email_card, email_inner = self._card(content)
        email_header = ctk.CTkFrame(email_inner, fg_color="transparent")
        email_header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            email_header, text="📧  Email Account (for inbox monitoring)",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(side="left", fill="x", expand=True)
        self._make_info_button(
            email_header,
            "Email Monitoring Help",
            "This connects your email so the app can check new messages "
            "for scams, phishing, and dangerous attachments.\n\n"
            "This is completely optional — it's up to you! The app works "
            "fine without it. You can always set it up later.\n\n"
            "How does it work?\n"
            "The app reads your inbox (it never sends emails or changes anything). "
            "When it finds a suspicious message, it warns you.\n\n"
            "═══════════════════════════════════════\n"
            "SIGN-IN METHOD\n"
            "═══════════════════════════════════════\n\n"
            "Choose your email provider from the dropdown (Google, Microsoft, "
            "or Yahoo). This opens your browser so you sign in directly — the "
            "app never sees your password. It gets a special permission token "
            "instead.\n\n"
            "You need a \"Client ID\" to use this. See below for how to get one.\n\n"
            "═══════════════════════════════════════\n"
            "HOW TO GET A CLIENT ID\n"
            "═══════════════════════════════════════\n\n"
            "--- Gmail (Google) ---\n"
            "1. Go to console.cloud.google.com\n"
            "2. Click \"Select a project\" at the top, then \"New Project\". "
            "Give it any name (e.g. \"My Email App\") and click Create.\n"
            "3. In the left menu, go to \"APIs & Services\" > \"Library\".\n"
            "4. Search for \"Gmail API\" and click Enable.\n"
            "5. Go to \"APIs & Services\" > \"OAuth consent screen\".\n"
            "   - Choose \"External\", click Create.\n"
            "   - Fill in the app name (anything you like) and your email. "
            "Click through the rest and Save.\n"
            "6. Go to \"APIs & Services\" > \"Credentials\".\n"
            "7. Click \"+ Create Credentials\" > \"OAuth Client ID\".\n"
            "   - Application type: \"Desktop app\".\n"
            "   - Click Create.\n"
            "8. Copy the \"Client ID\" and paste it into the Client ID field here.\n"
            "   You do NOT need the Client Secret for Gmail.\n\n"
            "--- Microsoft (Outlook / Hotmail) ---\n"
            "1. Go to portal.azure.com and sign in with your Microsoft account.\n"
            "2. Search for \"App registrations\" and click it.\n"
            "3. Click \"+ New registration\".\n"
            "   - Name: anything (e.g. \"My Email App\").\n"
            "   - Supported account types: \"Personal Microsoft accounts only\".\n"
            "   - Redirect URI: select \"Public client/native\" and type: "
            "http://localhost\n"
            "   - Click Register.\n"
            "4. On the app page, copy the \"Application (client) ID\" — "
            "that's your Client ID.\n"
            "   You do NOT need a Client Secret for Microsoft.\n\n"
            "--- Yahoo ---\n"
            "1. Go to developer.yahoo.com and sign in.\n"
            "2. Click \"My Apps\" > \"Create an App\".\n"
            "   - Application Name: anything.\n"
            "   - Application Type: \"Installed Application\".\n"
            "   - API Permissions: select \"Mail\" (read).\n"
            "   - Redirect URI: https://localhost\n"
            "   - Click Create.\n"
            "3. Copy the \"Client ID\" and paste it here.\n"
            "4. Yahoo ALSO requires the \"Client Secret\" — copy that too "
            "and paste it into the Client Secret field.\n\n"
            "═══════════════════════════════════════\n"
            "DO I NEED A CLIENT SECRET?\n"
            "═══════════════════════════════════════\n\n"
            "• Gmail: NO — leave it blank.\n"
            "• Microsoft: NO — leave it blank.\n"
            "• Yahoo: YES — paste it into the \"Client Secret\" field.\n\n"
            "═══════════════════════════════════════\n"
            "OTHER FIELDS\n"
            "═══════════════════════════════════════\n\n"
            "IMAP server and port:\n"
            "Usually leave these blank — the app figures them out "
            "from your email address. Only fill them in if you have a "
            "custom email provider.\n\n"
            "If any of this feels complicated, ask your trusted contact "
            "to help you set it up! They can do it in a few minutes.",
        ).pack(side="right")
        self._wrap_label(
            email_inner,
            text=(
                "Connect your email account so we can check incoming messages for\n"
                "phishing, scams, and dangerous attachments."
            ),
            font=self.font_small, fg=COLOURS["subtext"],
        ).pack(fill="x", pady=(0, 8))

        self._email_addr_var = tk.StringVar(value=self.config.email_address)
        _provider, normalized_mode = normalize_oauth_selection(
            str(getattr(self.config, "email_auth_mode", AUTH_PASSWORD)).strip().lower(),
            str(getattr(self.config, "email_oauth_provider", "")).strip().lower(),
        )
        if normalized_mode not in (set(oauth_auth_modes()) | {AUTH_PASSWORD}):
            normalized_mode = AUTH_PASSWORD
        self._email_auth_mode_var = tk.StringVar(value=normalized_mode)
        self._email_pass_var = tk.StringVar(value=self.config.email_password)  # kept for backend compat
        self._email_oauth_client_id_var = tk.StringVar(value=self.config.email_oauth_client_id)
        self._email_oauth_client_secret_var = tk.StringVar(value=self.config.email_oauth_client_secret)
        self._email_imap_var = tk.StringVar(value=self.config.email_imap_server)
        self._email_port_var = tk.StringVar(value=str(self.config.email_imap_port))

        row = ctk.CTkFrame(email_inner, fg_color="transparent")
        row.pack(fill="x", pady=3)
        ctk.CTkLabel(row, text="Email address:", font=self.font_body, text_color=COLOURS["text"],
                     width=220, anchor="w").pack(side="left")
        ctk.CTkEntry(
            row, textvariable=self._email_addr_var, font=self.font_body,
            fg_color=COLOURS["input_bg"], text_color=COLOURS["text"],
            border_color=COLOURS["input_border"], corner_radius=6, height=36,
        ).pack(side="left", fill="x", expand=True)

        mode_row = ctk.CTkFrame(email_inner, fg_color="transparent")
        mode_row.pack(fill="x", pady=3)
        ctk.CTkLabel(mode_row, text="Sign-in method:", font=self.font_body, text_color=COLOURS["text"],
                     width=220, anchor="w").pack(side="left")
        oauth_modes = [adapter.legacy_auth_mode for adapter in list_oauth_adapters()]
        mode_options = oauth_modes
        ctk.CTkOptionMenu(
            mode_row,
            variable=self._email_auth_mode_var,
            values=mode_options,
            command=lambda _mode: self._update_oauth_status_label(),
            font=self.font_body,
            fg_color=COLOURS["input_bg"],
            text_color=COLOURS["text"],
            button_color=COLOURS["accent_light"],
            button_hover_color=COLOURS["accent"],
            dropdown_fg_color=COLOURS["panel"],
            dropdown_text_color=COLOURS["text"],
            dropdown_hover_color=COLOURS["accent_light"],
            corner_radius=6,
        ).pack(side="left", fill="x", expand=True)

        row = ctk.CTkFrame(email_inner, fg_color="transparent")
        row.pack(fill="x", pady=3)
        ctk.CTkLabel(row, text="Client ID (for sign-in):", font=self.font_body,
                     text_color=COLOURS["text"], width=220, anchor="w").pack(side="left")
        ctk.CTkEntry(
            row, textvariable=self._email_oauth_client_id_var, font=self.font_body,
            fg_color=COLOURS["input_bg"], text_color=COLOURS["text"],
            border_color=COLOURS["input_border"], corner_radius=6, height=36,
        ).pack(side="left", fill="x", expand=True)

        row = ctk.CTkFrame(email_inner, fg_color="transparent")
        row.pack(fill="x", pady=3)
        ctk.CTkLabel(row, text="Client Secret (if needed):", font=self.font_body,
                     text_color=COLOURS["text"], width=220, anchor="w").pack(side="left")
        self._make_secret_entry(row, self._email_oauth_client_secret_var)

        oauth_row = ctk.CTkFrame(email_inner, fg_color="transparent")
        oauth_row.pack(fill="x", pady=(6, 0))
        self._make_button(
            oauth_row,
            "\U0001f511  Sign In with Email Provider",
            self._authorize_oauth,
            tone="coast",
        ).pack(side="left", padx=(0, 8))
        self._make_button(
            oauth_row,
            "Remove Saved Sign-In",
            self._clear_oauth_token,
            tone="industrial",
        ).pack(side="left")
        self._oauth_status_label = ctk.CTkLabel(
            oauth_row, text="", font=self.font_small,
            text_color=COLOURS["subtext"], anchor="w",
        )
        self._oauth_status_label.pack(side="left", padx=(12, 0))
        self._update_oauth_status_label()

        for label, var in [
            ("IMAP server (optional):", self._email_imap_var),
            ("IMAP port:", self._email_port_var),
        ]:
            row = ctk.CTkFrame(email_inner, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, font=self.font_body, text_color=COLOURS["text"],
                         width=220, anchor="w").pack(side="left")
            ctk.CTkEntry(
                row, textvariable=var, font=self.font_body,
                fg_color=COLOURS["input_bg"], text_color=COLOURS["text"],
                border_color=COLOURS["input_border"], corner_radius=6, height=36,
            ).pack(side="left", fill="x", expand=True)

        email_save_row = ctk.CTkFrame(email_inner, fg_color="transparent")
        email_save_row.pack(fill="x", pady=(10, 0))
        self._make_button(email_save_row, "💾  Save Email Settings", self._save_email_settings).pack(side="left", padx=(0, 8))
        self._make_button(email_save_row, "🔌  Test Connection", self._test_email_connection, tone="coast").pack(side="left")
        self._email_save_label = ctk.CTkLabel(
            email_save_row, text="", font=self.font_body,
            text_color=COLOURS["safe"], anchor="w",
        )
        self._email_save_label.pack(side="left", padx=(12, 0))

        ctk.CTkLabel(
            email_inner,
            text=(
                "For Google/Microsoft/Yahoo: paste your Client ID above, then click\n"
                "\"Sign In with Email Provider\" — it will open your browser to sign in safely.\n"
                "If you just use a password or app password, you can skip the Client ID fields."
            ),
            font=self.font_small, text_color=COLOURS["subtext"],
            anchor="w", justify="left",
        ).pack(fill="x", pady=(8, 0))

        email_card.pack(fill="x", pady=(0, 4), padx=(0, 10))

        # --- Optional API Keys ---
        api_card, api_inner = self._card(content)
        api_header = ctk.CTkFrame(api_inner, fg_color="transparent")
        api_header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            api_header, text="🔑  HIGHLY RECOMMENDED: Advanced Checking (API Keys)",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(side="left", fill="x", expand=True)
        self._make_info_button(
            api_header,
            "What are API Keys?",
            "API keys are like special passwords that let this app talk to "
            "online security services. They make your scans much stronger.\n\n"
            "You do NOT need these for the app to work — the basic checks "
            "work fine without them. These are completely optional.\n\n"
            "VirusTotal:\n"
            "This service checks files against 70+ antivirus programs at once. "
            "To get a free key:\n"
            "1. Go to virustotal.com\n"
            "2. Create a free account\n"
            "3. Click your profile picture → API key\n"
            "4. Copy the key and paste it here\n\n"
            "Google Safe Browsing:\n"
            "This checks websites against Google's database of known dangerous "
            "sites. To get a free key:\n"
            "1. Go to console.cloud.google.com\n"
            "2. Create a project\n"
            "3. Enable the \"Safe Browsing API\"\n"
            "4. Create an API key and paste it here\n\n"
            "Both services have free tiers that are more than enough for "
            "personal use. If this sounds complicated, ask your trusted "
            "contact to help you set it up!",
        ).pack(side="right")
        self._wrap_label(
            api_inner,
            text=(
                "For extra protection, you can add free API keys from VirusTotal and Google.\n"
                "These let us check files and websites against real-world security databases.\n"
                "Leave blank to skip — the basic checks still work without these."
            ),
            font=self.font_small, fg=COLOURS["subtext"],
        ).pack(fill="x", pady=(0, 8))

        self._vt_key_var  = tk.StringVar(value=self.config.virustotal_api_key)
        self._gsb_key_var = tk.StringVar(value=self.config.google_safe_browsing_key)

        for label, var, service in [
            ("VirusTotal API key:", self._vt_key_var, "virustotal"),
            ("Google Safe Browsing key:", self._gsb_key_var, "google_safe_browsing"),
        ]:
            row = ctk.CTkFrame(api_inner, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, font=self.font_body, text_color=COLOURS["text"], width=250, anchor="w").pack(side="left")
            self._make_secret_entry(row, var)
            ctk.CTkButton(
                row, text="📋 How to get this key",
                font=self.font_small,
                fg_color=COLOURS["coast"], text_color=COLOURS["button_text"],
                hover_color=COLOURS["accent"],
                corner_radius=6, width=180, height=36, cursor="hand2",
                command=lambda s=service: self._show_api_key_guide(s),
            ).pack(side="left", padx=(8, 0))

        save_row = ctk.CTkFrame(api_inner, fg_color="transparent")
        save_row.pack(fill="x", pady=(10, 0))
        self._make_button(save_row, "💾  Save Keys", self._save_api_keys).pack(side="left")
        self._api_save_label = ctk.CTkLabel(
            save_row, text="", font=self.font_body,
            text_color=COLOURS["safe"], anchor="w",
        )
        self._api_save_label.pack(side="left", padx=(12, 0))

        api_card.pack(fill="x", pady=(0, 4), padx=(0, 10))

        # --- Domain Database ---
        db_card, db_inner = self._card(content)
        db_header = ctk.CTkFrame(db_inner, fg_color="transparent")
        db_header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(
            db_header, text="🌐  Website Safety Database",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(side="left", fill="x", expand=True)
        self._make_info_button(
            db_header,
            "Website Safety Database Help",
            "This downloads a list of the 100,000 most popular websites "
            "in the world (e.g. google.com, youtube.com, amazon.com).\n\n"
            "Why is this useful?\n"
            "Scammers often create fake websites that look almost identical "
            "to real ones — for example, \"amaz0n.com\" instead of \"amazon.com\". "
            "This is called \"typosquatting\".\n\n"
            "With this database, the app can spot these fakes much more "
            "accurately by comparing any website you check against the list "
            "of known real websites.\n\n"
            "How to use it:\n"
            "1. Click \"Download / Update Database\" below.\n"
            "2. Wait for the download to finish (usually under a minute).\n"
            "3. That's it — the app will use it automatically.\n\n"
            "You can update it any time to get the latest list. "
            "The data is stored only on your computer.",
        ).pack(side="right")
        self._wrap_label(
            db_inner,
            text=(
                "Download a list of the top 100,000 most-visited websites worldwide.\n"
                "This lets us speed up our checks for look-alike sites (typosquatting) — for example,\n"
                "spotting that 'coolmathgamess.com' is a fake version of 'coolmathgames.com'."
            ),
            font=self.font_small, fg=COLOURS["subtext"],
        ).pack(fill="x", pady=(0, 8))

        self._db_status_label = ctk.CTkLabel(
            db_inner, text="", font=self.font_body,
            text_color=COLOURS["text"], anchor="w",
        )
        self._db_status_label.pack(fill="x", pady=(0, 6))
        self._update_db_status_label()

        self._db_btn_row = ctk.CTkFrame(db_inner, fg_color="transparent")
        self._db_btn_row.pack(fill="x", pady=(4, 0))
        self._make_button(self._db_btn_row, "⬇️  Download / Update Database", self._download_domain_db).pack(side="left")
        self._make_button(
            self._db_btn_row, "🗑️  Delete Database", self._delete_domain_db, tone="industrial"
        ).pack(side="left", padx=(8, 0))
        self._db_progress_label = ctk.CTkLabel(
            self._db_btn_row, text="", font=self.font_small,
            text_color=COLOURS["coast"], anchor="w",
        )
        self._db_progress_label.pack(side="left", padx=(12, 0))
        self._db_dismiss_btn = ctk.CTkButton(
            self._db_btn_row, text="✕", font=self.font_small,
            fg_color="transparent", text_color=COLOURS["subtext"],
            hover_color=COLOURS["industrial_light"],
            corner_radius=4, width=28, height=28, cursor="hand2",
            command=self._dismiss_db_progress,
        )
        self._db_dismiss_btn.pack_forget()

        self._db_confirm_row = ctk.CTkFrame(
            db_inner, fg_color=COLOURS["caution_bg"], corner_radius=8,
            border_width=1, border_color=COLOURS["caution"],
        )
        confirm_inner = ctk.CTkFrame(self._db_confirm_row, fg_color="transparent")
        confirm_inner.pack(fill="x", padx=10, pady=8)
        ctk.CTkLabel(
            confirm_inner,
            text="Delete the database?  This removes all downloaded data.",
            font=self.font_body, text_color=COLOURS["caution"],
        ).pack(side="left", padx=(0, 12))
        self._make_button(
            confirm_inner, "Yes, Delete", self._confirm_delete_domain_db, tone="industrial"
        ).pack(side="left", padx=(0, 6))
        self._make_button(
            confirm_inner, "✕  Cancel", self._cancel_delete_domain_db, tone="coast"
        ).pack(side="left")

        db_card.pack(fill="x", pady=(0, 4), padx=(0, 10))

    def _flash_save_confirmation(self, label: ctk.CTkLabel, text: str = "Saved ✓"):
        """Briefly show a green confirmation next to a save button, then fade it."""
        label.configure(text=text)
        def clear():
            try:
                label.configure(text="")
            except tk.TclError:
                pass
        self.root.after(3000, clear)

    def _save_contact(self):
        with self.config.batch_update():
            self.config.trusted_contact_name  = self._contact_name_var.get().strip()
            self.config.trusted_contact_email = self._contact_email_var.get().strip()
        self._flash_save_confirmation(self._contact_save_label, "✅  Contact saved!")
        self._set_status_temp("Trusted contact saved ✓")

    def _browse_dl_folder(self):
        folder = filedialog.askdirectory(title="Select your Downloads folder", parent=self.root)
        if folder:
            self._dl_folder_var.set(folder)

    def _save_dl_folder(self):
        self.config.downloads_folder = self._dl_folder_var.get().strip()
        self._flash_save_confirmation(self._dl_save_label, "✅  Folder saved! Restart to apply.")
        self._set_status_temp("Downloads folder saved ✓ (restart the app to apply)")

    def _save_api_keys(self):
        with self.config.batch_update():
            self.config.virustotal_api_key       = self._vt_key_var.get().strip()
            self.config.google_safe_browsing_key = self._gsb_key_var.get().strip()
        self._flash_save_confirmation(self._api_save_label, "✅  Keys saved successfully!")
        self._set_status_temp("API keys saved ✓")
        self._refresh_protection_banners()
        self._update_protection_indicator()

    def _update_oauth_status_label(self):
        label = getattr(self, "_oauth_status_label", None)
        if not label:
            return

        raw_mode = (
            self._email_auth_mode_var.get().strip().lower()
            if hasattr(self, "_email_auth_mode_var")
            else AUTH_PASSWORD
        )
        _provider, auth_mode = normalize_oauth_selection(
            raw_mode,
            str(getattr(self.config, "email_oauth_provider", "")).strip().lower(),
        )
        if auth_mode not in (set(oauth_auth_modes()) | {AUTH_PASSWORD}):
            auth_mode = AUTH_PASSWORD
        provider_name = self._oauth_provider_display_for_mode(auth_mode)
        has_client_id = bool(
            self._email_oauth_client_id_var.get().strip()
            if hasattr(self, "_email_oauth_client_id_var")
            else self.config.email_oauth_client_id
        )
        has_refresh = bool(self.config.email_oauth_refresh_token)

        if auth_mode not in OAUTH_AUTH_MODES:
            label.configure(text="OAuth2 not active (authentication mode is password).", text_color=COLOURS["subtext"])
            return

        if has_refresh:
            label.configure(text=f"{provider_name} OAuth2 authorized.", text_color=COLOURS["safe"])
            return

        if has_client_id:
            label.configure(text=f"{provider_name} OAuth2 not authorized yet.", text_color=COLOURS["caution"])
            return

        label.configure(
            text=f"Enter a {provider_name} OAuth Client ID, then authorize.",
            text_color=COLOURS["subtext"],
        )

    def _authorize_oauth(self):
        raw_mode = self._email_auth_mode_var.get().strip().lower() or AUTH_PASSWORD
        provider_hint = str(getattr(self.config, "email_oauth_provider", "")).strip().lower()
        provider, auth_mode = normalize_oauth_selection(raw_mode, provider_hint)
        if auth_mode not in (set(oauth_auth_modes()) | {AUTH_PASSWORD}):
            auth_mode = AUTH_PASSWORD
            provider = None
        oauth_adapter = self._oauth_adapter_for_mode(auth_mode)
        provider_name = self._oauth_provider_display_for_mode(auth_mode)
        addr = self._email_addr_var.get().strip()
        client_id = self._email_oauth_client_id_var.get().strip()
        client_secret = self._email_oauth_client_secret_var.get().strip()

        if not provider:
            self._email_save_label.configure(
                text="Select an OAuth2 authentication mode first.",
                text_color=COLOURS["caution"],
            )
            return
        if not addr:
            self._email_save_label.configure(
                text="Warning: enter your email address first.", text_color=COLOURS["caution"]
            )
            return
        if not client_id:
            self._email_save_label.configure(
                text=f"Warning: enter {provider_name} OAuth Client ID first.",
                text_color=COLOURS["caution"],
            )
            return
        if oauth_adapter and oauth_adapter.require_client_secret and not client_secret:
            self._email_save_label.configure(
                text=f"Warning: {provider_name} OAuth Client Secret is required.",
                text_color=COLOURS["caution"],
            )
            return

        self._email_save_label.configure(text="Authorizing...", text_color=COLOURS["coast"])
        self._set_status(f"Opening browser for {provider_name} OAuth2 authorization...")

        def worker():
            try:
                token_data = run_oauth_flow(
                    provider=provider,
                    client_id=client_id,
                    client_secret=client_secret,
                )
                refresh_token = str(token_data.get("refresh_token", "")).strip()
                if not refresh_token:
                    raise OAuthError(
                        f"{provider_name} OAuth succeeded but no refresh token was returned."
                    )

                with self.config.batch_update():
                    self.config.email_address = addr
                    self.config.email_auth_mode = auth_mode
                    self.config.email_oauth_provider = provider or ""
                    self.config.email_oauth_client_id = client_id
                    self.config.email_oauth_client_secret = client_secret
                    self.config.email_oauth_refresh_token = refresh_token

                self._safe_after(lambda: self._email_save_label.configure(
                    text=f"Success: {provider_name} OAuth2 authorized.", text_color=COLOURS["safe"]
                ))
                self._safe_after(self._update_oauth_status_label)
                self._safe_after(self._update_email_status_label)
                self._safe_after(
                    lambda: self._set_status_temp(f"{provider_name} OAuth2 authorization saved.")
                )
            except OAuthError as exc:
                self._safe_after(lambda e=str(exc): self._email_save_label.configure(
                    text=f"Error: {e}", text_color=COLOURS["danger"]
                ))
                self._safe_after(self._update_oauth_status_label)
                self._safe_after(
                    lambda: self._set_status_temp(f"{provider_name} OAuth2 authorization failed")
                )
            except Exception as exc:
                log.exception("%s OAuth authorization failed", provider_name)
                self._safe_after(lambda e=str(exc): self._email_save_label.configure(
                    text=f"Error: authorization failed: {e}", text_color=COLOURS["danger"]
                ))
                self._safe_after(self._update_oauth_status_label)
                self._safe_after(
                    lambda: self._set_status_temp(f"{provider_name} OAuth2 authorization failed")
                )

        threading.Thread(target=worker, daemon=True).start()

    def _clear_oauth_token(self):
        auth_mode = self._email_auth_mode_var.get().strip().lower() or AUTH_PASSWORD
        provider_name = self._oauth_provider_display_for_mode(auth_mode)

        if not self.config.email_oauth_refresh_token:
            self._email_save_label.configure(
                text="No OAuth token is currently saved.", text_color=COLOURS["subtext"]
            )
            self._update_oauth_status_label()
            return

        if not messagebox.askyesno(
            "Clear OAuth token",
            "This removes the saved OAuth token. You will need to authorize again.\n\nContinue?",
            parent=self.root,
        ):
            return

        self.config.email_oauth_refresh_token = ""
        self._email_save_label.configure(text="OAuth token cleared.", text_color=COLOURS["caution"])
        self._update_oauth_status_label()
        self._update_email_status_label()
        self._set_status_temp(f"{provider_name} OAuth token cleared")

    def _save_email_settings(self):
        addr = self._email_addr_var.get().strip()
        raw_mode = self._email_auth_mode_var.get().strip().lower() or AUTH_PASSWORD
        provider_hint = str(getattr(self.config, "email_oauth_provider", "")).strip().lower()
        oauth_provider, auth_mode = normalize_oauth_selection(raw_mode, provider_hint)
        if auth_mode not in (OAUTH_AUTH_MODES | {AUTH_PASSWORD}):
            auth_mode = AUTH_PASSWORD
            oauth_provider = None
        password = self._email_pass_var.get().strip()
        oauth_client_id = self._email_oauth_client_id_var.get().strip()
        oauth_client_secret = self._email_oauth_client_secret_var.get().strip()
        imap_server = self._email_imap_var.get().strip()
        previous_provider, previous_mode = normalize_oauth_selection(
            str(getattr(self.config, "email_auth_mode", AUTH_PASSWORD)).strip().lower(),
            str(getattr(self.config, "email_oauth_provider", "")).strip().lower(),
        )
        if previous_mode not in (OAUTH_AUTH_MODES | {AUTH_PASSWORD}):
            previous_mode = AUTH_PASSWORD
            previous_provider = None
        previous_client_id = str(getattr(self.config, "email_oauth_client_id", "")).strip()
        try:
            imap_port = int(self._email_port_var.get().strip())
        except ValueError:
            imap_port = 993

        clear_refresh_token = (
            auth_mode in OAUTH_AUTH_MODES
            and (
                auth_mode != previous_mode
                or oauth_provider != previous_provider
                or oauth_client_id != previous_client_id
            )
        )

        with self.config.batch_update():
            self.config.email_address = addr
            self.config.email_auth_mode = auth_mode
            self.config.email_oauth_provider = oauth_provider or ""
            self.config.email_password = password
            self.config.email_oauth_client_id = oauth_client_id
            self.config.email_oauth_client_secret = oauth_client_secret
            if clear_refresh_token:
                self.config.email_oauth_refresh_token = ""
            self.config.email_imap_server = imap_server
            self.config.email_imap_port = imap_port

        self._flash_save_confirmation(self._email_save_label, "✅  Email settings saved!")
        self._set_status_temp("Email settings saved ✓")
        self._update_email_status_label()
        self._update_oauth_status_label()

    def _test_email_connection(self):
        addr = self._email_addr_var.get().strip()
        raw_mode = self._email_auth_mode_var.get().strip().lower() or AUTH_PASSWORD
        provider_hint = str(getattr(self.config, "email_oauth_provider", "")).strip().lower()
        oauth_provider, auth_mode = normalize_oauth_selection(raw_mode, provider_hint)
        if auth_mode not in (OAUTH_AUTH_MODES | {AUTH_PASSWORD}):
            auth_mode = AUTH_PASSWORD
            oauth_provider = None
        oauth_adapter = self._oauth_adapter_for_mode(auth_mode)
        password = self._email_pass_var.get().strip()
        oauth_client_id = self._email_oauth_client_id_var.get().strip()
        oauth_client_secret = self._email_oauth_client_secret_var.get().strip()
        oauth_refresh_token = self.config.email_oauth_refresh_token
        imap_server = self._email_imap_var.get().strip()
        try:
            imap_port = int(self._email_port_var.get().strip())
        except ValueError:
            imap_port = 993

        if not addr:
            self._email_save_label.configure(
                text="Warning: enter an email address first.", text_color=COLOURS["caution"]
            )
            return
        if auth_mode in OAUTH_AUTH_MODES:
            provider_name = self._oauth_provider_display_for_mode(auth_mode)
            if not oauth_client_id or not oauth_refresh_token:
                self._email_save_label.configure(
                    text=f"Warning: authorize {provider_name} OAuth2 first.",
                    text_color=COLOURS["caution"],
                )
                return
            if oauth_adapter and oauth_adapter.require_client_secret and not oauth_client_secret:
                self._email_save_label.configure(
                    text=f"Warning: {provider_name} OAuth Client Secret is required.",
                    text_color=COLOURS["caution"],
                )
                return
        elif not password:
            self._email_save_label.configure(
                text="Warning: enter password/app password first.",
                text_color=COLOURS["caution"],
            )
            return

        self._email_save_label.configure(text="Testing...", text_color=COLOURS["coast"])
        self._set_status("Testing email connection...")

        def worker():
            monitor = EmailMonitor(
                email_address=addr,
                email_password=password,
                imap_server=imap_server,
                imap_port=imap_port,
                auth_mode=auth_mode,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
                oauth_refresh_token=oauth_refresh_token,
                oauth_provider=oauth_provider or "",
            )
            conn = monitor._connect()
            if conn:
                try:
                    conn.close()
                    conn.logout()
                except Exception:
                    pass
                self._safe_after(lambda: self._email_save_label.configure(
                    text="Connection successful.", text_color=COLOURS["safe"]
                ))
                self._safe_after(lambda: self._set_status_temp("Email connection test passed"))
            else:
                err = monitor.last_error
                self._safe_after(lambda e=err: self._email_save_label.configure(
                    text=f"Error: {e}", text_color=COLOURS["danger"]
                ))
                self._safe_after(lambda: self._set_status_temp("Email connection test failed"))

        threading.Thread(target=worker, daemon=True).start()

    def _update_db_status_label(self):
        db = get_domain_db()
        if db.is_loaded:
            updated = db.last_updated or "unknown"
            if "T" in updated:
                updated = updated[:16].replace("T", " ")
            self._db_status_label.configure(
                text=f"✅  Database loaded: {db.domain_count:,} websites  •  Last updated: {updated}",
                text_color=COLOURS["safe"],
            )
        else:
            self._db_status_label.configure(
                text="⚠️  No database downloaded yet. Click the button below to set it up.",
                text_color=COLOURS["caution"],
            )

    def _download_domain_db(self):
        self._show_db_progress("Downloading…")
        self._set_status("Downloading website database, please wait…")

        def worker():
            db = get_domain_db()
            def on_progress(msg):
                self.root.after(0, lambda m=msg: self._db_progress_label.configure(text=m))

            success = db.download(progress_callback=on_progress)
            if success:
                self.root.after(0, lambda: self._show_db_progress(
                    f"✅  Done — {db.domain_count:,} sites loaded!", COLOURS["safe"]))
                self.root.after(0, self._update_db_status_label)
                self.root.after(0, lambda: self._set_status_temp(
                    f"Website database updated — {db.domain_count:,} domains loaded ✓"))
            else:
                self.root.after(0, lambda: self._show_db_progress(
                    "❌  Download failed. Check your internet connection.", COLOURS["danger"]))
                self.root.after(0, lambda: self._set_status_temp("Database download failed"))

        threading.Thread(target=worker, daemon=True).start()

    def _dismiss_db_progress(self):
        """Clear the progress message and hide the dismiss X button."""
        self._db_progress_label.configure(text="")
        self._db_dismiss_btn.pack_forget()

    def _show_db_progress(self, text: str, fg: str = None):
        """Update the inline progress label and show the dismiss X button."""
        self._db_progress_label.configure(text=text, text_color=fg or COLOURS["coast"])
        self._db_dismiss_btn.pack(side="left", padx=(4, 0))

    def _delete_domain_db(self):
        """Swap the action row for an inline confirmation bar."""
        self._db_btn_row.pack_forget()
        self._db_confirm_row.pack(fill="x", pady=(6, 0))

    def _cancel_delete_domain_db(self):
        """User cancelled — restore the normal action row."""
        self._db_confirm_row.pack_forget()
        self._db_btn_row.pack(fill="x", pady=(4, 0))

    def _confirm_delete_domain_db(self):
        """User confirmed — delete the database and restore the normal action row."""
        self._db_confirm_row.pack_forget()
        self._db_btn_row.pack(fill="x", pady=(4, 0))
        db = get_domain_db()
        success = db.clear()
        if success:
            self._show_db_progress("Database deleted.", COLOURS["subtext"])
            self._set_status_temp("Website safety database deleted ✓")
        else:
            self._show_db_progress("⚠️  Could not fully delete database files.", COLOURS["caution"])
            self._set_status_temp("Database deletion had errors — check logs")
        self._update_db_status_label()

    # ------------------------------------------------------------------
    # Result display
    # ------------------------------------------------------------------
    def _display_result(self, result: dict, container):
        self._clear(container)

        risk = result.get("overall_risk", RISK_CAUTION)
        fg_colour, bg_colour, risk_label = RISK_COLOURS.get(risk, (COLOURS["caution"], COLOURS["caution_bg"], "⚠️ CAUTION"))

        banner = ctk.CTkFrame(container, fg_color=bg_colour, corner_radius=10)
        banner.pack(fill="x", pady=(6, 4))
        ctk.CTkLabel(
            banner, text=risk_label,
            font=self.font_risk, text_color=fg_colour,
        ).pack(side="left", padx=(20, 0), pady=14)

        scan_type = result.get("type", "")
        if scan_type == "email":
            name = f"📧 {result.get('sender', '')} — {result.get('subject', '(no subject)')}"
        else:
            name = result.get("filename") or result.get("url", "")
        file_size = result.get("file_size")
        display_name = f"{name}  ({file_size})" if file_size else name

        verdict = coerce_verdict_fields(result)
        score = verdict.get("risk_score")
        confidence = str(verdict.get("confidence", "")).strip().title()
        summary = str(verdict.get("verdict_summary", "")).strip()
        verdict_parts = []
        if isinstance(score, int):
            verdict_parts.append(f"Risk score: {score}/100")
        if confidence:
            verdict_parts.append(f"Confidence: {confidence}")
        if verdict_parts:
            display_name = f"{display_name}\n{' | '.join(verdict_parts)}"
        if summary:
            display_name = f"{display_name}\n{summary}"

        name_lbl = ctk.CTkLabel(
            banner, text=display_name,
            font=self.font_body, text_color=COLOURS["subtext"], justify="left",
        )
        name_lbl.bind("<Configure>", lambda e, l=name_lbl: l.configure(wraplength=max(100, e.width - 20)))
        name_lbl.pack(side="left", padx=20, fill="x", expand=True, pady=14)

        scroll_frame = ctk.CTkScrollableFrame(container, fg_color=COLOURS["bg"])
        scroll_frame.pack(fill="both", expand=True, pady=4)

        for finding in result.get("findings", []):
            frisk = finding.get("risk", RISK_CAUTION)
            ffg, fbg, _ = RISK_COLOURS.get(frisk, (COLOURS["caution"], COLOURS["caution_bg"], ""))
            card = ctk.CTkFrame(
                scroll_frame, fg_color=fbg, corner_radius=8,
                border_width=1, border_color=COLOURS["industrial_light"],
            )
            card.pack(fill="x", pady=4, padx=4)
            self._wrap_label(
                card, text=finding["title"],
                font=self.font_heading, fg=ffg,
            ).pack(fill="x", padx=16, pady=(12, 0))
            self._wrap_label(
                card, text=finding["detail"],
                font=self.font_body, fg=COLOURS["text"],
            ).pack(fill="x", padx=16, pady=(6, 12))

        has_vt = bool(self.config.virustotal_api_key)
        has_gsb = bool(self.config.google_safe_browsing_key)

        badges: list[str] = []
        if has_vt and scan_type == "file":
            badges.append("\u2705  Checked by VirusTotal (70+ antivirus engines)")
        if has_gsb and scan_type in {"url", "email"}:
            badges.append("\u2705  Checked by Google Safe Browsing")

        for badge_text in badges:
            badge = ctk.CTkFrame(
                scroll_frame, fg_color=COLOURS["safe_bg"], corner_radius=8,
                border_width=1, border_color=COLOURS["industrial_light"],
            )
            badge.pack(fill="x", pady=4, padx=4)
            ctk.CTkLabel(
                badge, text=badge_text,
                font=self.font_body, text_color=COLOURS["safe"], anchor="w",
            ).pack(fill="x", padx=14, pady=8)

        tips: list[str] = []
        if not has_vt and scan_type == "file":
            tips.append(
                "Tip: Add a free VirusTotal key to check this file against "
                "70+ antivirus engines."
            )
        if not has_gsb and scan_type in {"url", "email"}:
            tips.append(
                "Tip: Add a free Google Safe Browsing key to check websites "
                "against Google's threat database."
            )
        if tips:
            nudge = ctk.CTkFrame(
                scroll_frame, fg_color=COLOURS["caution_bg"], corner_radius=8,
                border_width=1, border_color=COLOURS["industrial_light"],
            )
            nudge.pack(fill="x", pady=4, padx=4)
            for tip in tips:
                ctk.CTkLabel(
                    nudge, text=tip,
                    font=self.font_body, text_color=COLOURS["caution"], anchor="w",
                ).pack(fill="x", padx=14, pady=(8, 0))
            ctk.CTkButton(
                nudge, text="Set Up Now \u2192",
                font=self.font_small, text_color=COLOURS["accent"],
                fg_color="transparent", hover_color=COLOURS["accent_light"],
                cursor="hand2", width=0, height=24, anchor="w",
                command=lambda: self._show_tab("settings"),
            ).pack(fill="x", padx=14, pady=(4, 8))

        if tips and not self._api_nudge_shown:
            self._api_nudge_shown = True
            self.root.after(600, self._show_api_nudge_popup)

        action_card = self._prompt_card(container, "What would you like to do next?")
        action_frame = ctk.CTkFrame(action_card, fg_color="transparent")
        action_frame.pack(fill="x", padx=16, pady=(4, 12))

        self._make_button(
            action_frame,
            "📄  View Report",
            lambda r=result: self._show_risk_report_popup(r),
            tone="industrial",
        ).pack(side="left", padx=(0, 8))
        self._make_button(
            action_frame,
            "Copy Report",
            lambda r=result: self._copy_risk_report_to_clipboard(r),
            tone="industrial",
        ).pack(side="left", padx=(0, 8))

        filepath = result.get("filepath")
        if risk == RISK_DANGER and filepath and os.path.isfile(filepath):
            delete_label = "🗑️  Move to Recycle Bin" if _SEND2TRASH_AVAILABLE else "🗑️  Delete File"
            self._make_button(
                action_frame,
                delete_label,
                lambda fp=filepath, c=container: self._delete_file(fp, c),
                tone="industrial",
            ).pack(side="left", padx=(0, 8))

        if self.config.trusted_contact_email:
            self._make_button(
                action_frame,
                f"📨  Ask {self.config.trusted_contact_name or 'My Trusted Contact'} for Help",
                lambda r=result: self._ask_for_help(r),
                tone="industrial",
            ).pack(side="left", padx=(0, 8))

        self._make_button(
            action_frame, "🔄  Check Another",
            lambda: self._clear(container),
            tone="coast",
        ).pack(side="left")

    def _show_api_nudge_popup(self):
        """One-time popup encouraging the user to set up API keys."""
        popup = self._popup("Make Your Scans Stronger", "560x320", resizable=False)
        popup.configure(fg_color=COLOURS["bg"])

        shell = ctk.CTkFrame(popup, fg_color=COLOURS["accent"], corner_radius=10)
        shell.pack(fill="both", expand=True, padx=20, pady=20)
        body = ctk.CTkFrame(shell, fg_color=COLOURS["panel"], corner_radius=8)
        body.pack(fill="both", expand=True, padx=2, pady=2)

        ctk.CTkLabel(
            body, text="🛡  Make your scans even stronger",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", padx=24, pady=(20, 10))
        self._wrap_label(
            body,
            text=(
                "Your scan is complete! Did you know you can make it much more "
                "powerful by adding free API keys?\n\n"
                "VirusTotal checks files against 70+ antivirus engines.\n"
                "Google Safe Browsing checks websites against Google's own "
                "threat database.\n\n"
                "Both are free and take about 5 minutes to set up."
            ),
            font=self.font_body, fg=COLOURS["text"],
        ).pack(fill="x", padx=24)

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(14, 20))

        def go_settings():
            popup.destroy()
            self._show_tab("settings")

        self._make_button(btn_row, "\u2699\ufe0f  Set Up Now", go_settings).pack(side="left", padx=(0, 10))
        self._make_button(btn_row, "Maybe Later", popup.destroy, tone="industrial").pack(side="left")

    def _ask_for_help(self, result: dict):
        email = self.config.trusted_contact_email
        if not email:
            self._set_status("Please add a trusted contact email in Settings first.")
            return
        subject, body = compose_message(result)
        if open_mailto(email, subject, body):
            self._set_status_temp(f"Opening your email app to contact {self.config.trusted_contact_name or email}…")
        else:
            self._set_status_temp(f"The email address '{email}' doesn't look valid. Please check it in Settings.")

    def _delete_file(self, filepath: str, container):
        filename = os.path.basename(filepath)
        if _SEND2TRASH_AVAILABLE:
            action_verb = "send this file to the Recycle Bin"
            undo_note = "You can restore it from the Recycle Bin later if needed."
        else:
            action_verb = "permanently delete this file"
            undo_note = "Warning: this cannot be undone (send2trash is not installed)."
        confirmed = messagebox.askyesno(
            "Delete File?",
            f"Are you sure you want to {action_verb}?\n\n"
            f"File: {filename}\n\n{undo_note}",
            parent=self.root,
        )
        if not confirmed:
            return
        try:
            if _SEND2TRASH_AVAILABLE:
                _send2trash.send2trash(filepath)
                done_msg = f"'{filename}' has been moved to the Recycle Bin. ✓"
            else:
                os.remove(filepath)
                done_msg = f"'{filename}' has been permanently deleted. ✓"
            self._clear(container)
            self._show_message(container, done_msg, RISK_SAFE)
            self._set_status_temp(done_msg)
        except Exception as exc:
            log.warning("Could not delete %s: %s", filepath, exc)
            self._set_status_temp(f"Could not delete '{filename}' — {exc}")

    def _get_risk_report_text(self, result: dict) -> str:
        """Return the plain-text report for a scan result."""
        report = result.get("risk_report")
        if isinstance(report, dict):
            text = str(report.get("text", "")).strip()
            if text:
                return text
        try:
            from modules.reporting import build_risk_report
            generated = build_risk_report(result)
            if isinstance(generated, dict):
                return str(generated.get("text", "")).strip()
        except Exception:
            log.exception("Could not generate risk report")
        return ""

    def _copy_risk_report_to_clipboard(self, result: dict):
        text = self._get_risk_report_text(result)
        if not text:
            self._set_status_temp("No report available to copy.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            self._set_status_temp("Report copied to clipboard ✓")
        except tk.TclError:
            self._set_status_temp("Could not copy report to clipboard.")

    def _show_risk_report_popup(self, result: dict):
        text = self._get_risk_report_text(result)
        if not text:
            messagebox.showinfo("Risk Report", "No report is available for this scan.", parent=self.root)
            return

        popup = self._popup("Risk Report", "760x620")
        popup.configure(fg_color=COLOURS["bg"])

        hdr_card, hdr_content = self._card(popup)
        ctk.CTkLabel(
            hdr_content, text="📄  Risk Report (shareable)",
            font=self.font_heading, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x")
        self._wrap_label(
            hdr_content,
            text="This report summarizes what was checked, what was observed, and recommended next steps.",
            font=self.font_small, fg=COLOURS["subtext"],
        ).pack(fill="x", pady=(4, 0))
        hdr_card.pack(fill="x", padx=16, pady=(16, 8))

        body = ctk.CTkFrame(popup, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        text_widget = ctk.CTkTextbox(
            body, font=self.font_small,
            fg_color=COLOURS["panel_warm"], text_color=COLOURS["text"],
            corner_radius=8, wrap="word",
        )
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", text)
        text_widget.configure(state="disabled")

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        self._make_button(btn_row, "Copy Report", lambda r=result: self._copy_risk_report_to_clipboard(r), tone="industrial").pack(side="left", padx=(0, 8))
        self._make_button(btn_row, "Close", popup.destroy, tone="coast").pack(side="right")

    # ------------------------------------------------------------------
    # Download monitor callback (called from background thread)
    # ------------------------------------------------------------------
    def on_new_download_detected(self, filepath: str):
        """Called by the DownloadMonitor when a new file appears."""
        self._safe_after(lambda fp=filepath: self._auto_scan_popup(fp))

    def _auto_scan_popup(self, filepath: str):
        filename = os.path.basename(filepath)
        popup = self._popup("New File Detected!", "620x320", resizable=False)
        popup.configure(fg_color=COLOURS["prompt_bg"])

        shell = ctk.CTkFrame(popup, fg_color=COLOURS["industrial"], corner_radius=10)
        shell.pack(fill="both", expand=True, padx=18, pady=18)
        body = ctk.CTkFrame(shell, fg_color=COLOURS["prompt_bg"], corner_radius=8)
        body.pack(fill="both", expand=True, padx=2, pady=2)

        ctk.CTkLabel(
            body, text="Prompt: New download detected",
            font=self.font_small, text_color=COLOURS["industrial"], anchor="w",
        ).pack(fill="x", padx=18, pady=(16, 0))
        self._wrap_label(
            body,
            text="⚠️  A new file just appeared in your Downloads!",
            font=self.font_heading, fg=COLOURS["caution"],
        ).pack(fill="x", padx=18, pady=(6, 6))
        ctk.CTkLabel(
            body, text=f"File: {filename}",
            font=self.font_body, text_color=COLOURS["text"], anchor="w",
        ).pack(fill="x", padx=18, pady=2)
        self._wrap_label(
            body,
            text="Would you like us to check if it's safe before you open it?",
            font=self.font_body, fg=COLOURS["subtext"],
        ).pack(fill="x", padx=18, pady=(4, 10))

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(anchor="w", padx=18, pady=(0, 16))

        def yes():
            popup.destroy()
            self._show_tab("file")
            self._run_file_scan(filepath)

        def no():
            popup.destroy()

        self._make_button(btn_row, "✅  Yes, check it for me!", yes, tone="coast").pack(side="left", padx=(0, 10))
        self._make_button(btn_row, "No thanks", no, tone="industrial").pack(side="left")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _safe_after(self, callback) -> bool:
        """Schedule a UI callback only while Tk is alive."""
        try:
            if not self.root.winfo_exists():
                return False
            self.root.after(0, callback)
            return True
        except tk.TclError:
            return False

    def _popup(self, title: str, geometry: str, *, resizable: bool = True,
               grab: bool = True) -> ctk.CTkToplevel:
        """Create a CTkToplevel with the Windows extra-window workaround."""
        popup = ctk.CTkToplevel(self.root)
        popup.title(title)
        popup.geometry(geometry)
        popup.resizable(resizable, resizable)
        if grab:
            popup.grab_set()
        popup.after(10, popup.lift)
        popup.after(10, popup.focus)
        return popup

    def _wrap_label(self, parent, text: str, font, fg: str,
                    anchor="w", justify="left", padding: int = 40, **kwargs) -> ctk.CTkLabel:
        """Create a Label whose wraplength tracks the widget's actual width."""
        lbl = ctk.CTkLabel(
            parent, text=text, font=font, text_color=fg,
            anchor=anchor, justify=justify, **kwargs
        )
        lbl.bind(
            "<Configure>",
            lambda e, l=lbl, p=padding: l.configure(wraplength=max(100, e.width - p))
        )
        return lbl

    def _make_secret_entry(self, parent, textvariable: tk.StringVar) -> ctk.CTkEntry:
        """Create a password-style Entry with an inline show/hide toggle button."""
        row = ctk.CTkFrame(parent, fg_color="transparent")
        entry = ctk.CTkEntry(
            row, textvariable=textvariable, font=self.font_body, show="•",
            fg_color=COLOURS["input_bg"], text_color=COLOURS["text"],
            border_color=COLOURS["input_border"], corner_radius=6, height=36,
        )
        entry.pack(side="left", fill="x", expand=True)

        hidden = [True]

        def _toggle():
            if hidden[0]:
                entry.configure(show="")
                toggle_btn.configure(text="🙈")
            else:
                entry.configure(show="•")
                toggle_btn.configure(text="👁")
            hidden[0] = not hidden[0]

        toggle_btn = ctk.CTkButton(
            row, text="👁", font=self.font_small,
            fg_color=COLOURS["button"], text_color=COLOURS["button_text"],
            hover_color=COLOURS["button_hover"],
            corner_radius=6, width=40, height=36, cursor="hand2",
            command=_toggle,
        )
        toggle_btn.pack(side="left", padx=(4, 0))
        row.pack(side="left", fill="x", expand=True)
        return entry

    def _make_info_button(self, parent, title: str, message: str) -> ctk.CTkButton:
        """Create a 'Securious The Saviour' help button that shows a friendly popup."""
        return ctk.CTkButton(
            parent,
            text="🛡 Securious The Saviour",
            font=self.font_button,
            fg_color=COLOURS["coast"], text_color=COLOURS["button_text"],
            hover_color=COLOURS["accent"],
            corner_radius=8, height=36, cursor="hand2",
            command=lambda: self._show_info_popup(title, message),
        )

    def _show_info_popup(self, title: str, message: str):
        """Show a friendly help popup with a title and plain-English explanation."""
        popup = self._popup(f"Securious The Saviour — {title}", "620x500")
        popup.configure(fg_color=COLOURS["bg"])

        hdr_card, hdr_content = self._card(popup)
        ctk.CTkLabel(
            hdr_content, text="🛡  Securious The Saviour",
            font=self.font_heading, text_color=COLOURS["coast"], anchor="w",
        ).pack(fill="x")
        ctk.CTkLabel(
            hdr_content, text=title,
            font=self.font_body, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", pady=(2, 0))
        hdr_card.pack(fill="x", padx=16, pady=(16, 8))

        body = ctk.CTkFrame(popup, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        text_widget = ctk.CTkTextbox(
            body, font=self.font_body,
            fg_color=COLOURS["panel_warm"], text_color=COLOURS["text"],
            corner_radius=8, wrap="word",
        )
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", message)
        text_widget.configure(state="disabled")

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        self._make_button(btn_row, "Got it, thanks Securious!", popup.destroy, tone="coast").pack(side="right")

    def _show_api_key_guide(self, service: str):
        """Step-by-step popup with clickable links for obtaining an API key."""
        if service == "virustotal":
            title = "How to get your free VirusTotal API key"
            size = "640x420"
            steps = [
                ("text", "VirusTotal checks files against 70+ antivirus engines at once.\nGetting a key is free and takes about 2 minutes.\n\n"),
                ("text", "Step 1.  Create a free account (skip this if you already have one):\n        "),
                ("link", "👉  Open VirusTotal sign-up page", "https://www.virustotal.com/gui/join-us"),
                ("text", "\n\nStep 2.  After signing in, click your "),
                ("bold", "profile picture"),
                ("text", " in the top-right corner\n        and choose "),
                ("bold", "\"API key\""),
                ("text", ".  Or use this direct shortcut:\n        "),
                ("link", "👉  Go straight to your API key", "https://www.virustotal.com/gui/my-apikey"),
                ("text", "\n\nStep 3.  You'll see a long string of letters and numbers — that's your key.\n        Click it to select all of it, then copy it (Ctrl+C on Windows).\n\nStep 4.  Come back here and paste it (Ctrl+V) into the VirusTotal key box.\n\nStep 5.  Click "),
                ("bold", "\"Save Keys\""),
                ("text", ".\n\n✅  Done!"),
            ]
        else:
            title = "How to get your free Google Safe Browsing API key"
            size = "680x580"
            steps = [
                ("text", "Google Safe Browsing checks every website against Google's own\ndatabase of dangerous sites. The key is completely free.\n\nThe Google Cloud website can look complicated — follow these\nexact steps and it should only take about 5 minutes.\n\n"),
                ("text", "Step 1.  Open Google Cloud Console and sign in with your Google account:\n        "),
                ("link", "👉  Open Google Cloud Console", "https://console.cloud.google.com/"),
                ("text", "\n\nStep 2.  You need a \"project\" (like a folder for your settings).\n        If you haven't used this before, click "),
                ("bold", "\"Select a project\""),
                ("text", " at the top,\n        then "),
                ("bold", "\"New Project\""),
                ("text", ".  Give it any name (e.g. \"Safety App\") and click "),
                ("bold", "\"Create\""),
                ("text", ".\n\nStep 3.  Enable the Safe Browsing API — click the link below, make\n        sure your project name shows at the top, then click "),
                ("bold", "\"Enable\""),
                ("text", ":\n        "),
                ("link", "👉  Enable Safe Browsing API", "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"),
                ("text", "\n\nStep 4.  Create your API key — click the link below:\n        "),
                ("link", "👉  Go to API Credentials page", "https://console.cloud.google.com/apis/credentials"),
                ("text", "\n        Click "),
                ("bold", "\"+ Create Credentials\""),
                ("text", " near the top, then choose "),
                ("bold", "\"API key\""),
                ("text", ".\n        A box appears showing your new key — copy it.\n\nStep 5.  Paste it (Ctrl+V) into the Google Safe Browsing key box here.\n\nStep 6.  Click "),
                ("bold", "\"Save Keys\""),
                ("text", ".\n\n✅  Done!  If anything looks different, ask your trusted contact to help."),
            ]

        popup = self._popup(f"Securious The Saviour — {title}", size)
        popup.configure(fg_color=COLOURS["bg"])

        hdr_card, hdr_content = self._card(popup)
        ctk.CTkLabel(
            hdr_content, text="🛡  Securious The Saviour",
            font=self.font_heading, text_color=COLOURS["coast"], anchor="w",
        ).pack(fill="x")
        ctk.CTkLabel(
            hdr_content, text=title,
            font=self.font_body, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", pady=(2, 0))
        hdr_card.pack(fill="x", padx=16, pady=(16, 8))

        body = ctk.CTkFrame(popup, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        txt = ctk.CTkTextbox(
            body, font=self.font_body,
            fg_color=COLOURS["panel_warm"], text_color=COLOURS["text"],
            corner_radius=8, wrap="word",
        )
        txt.pack(fill="both", expand=True)

        txt.tag_configure("link", foreground=COLOURS["accent"], underline=True)
        txt.tag_configure("bold", font=(self._ui_family, self.font_body[1], "bold"))

        link_idx = 0
        for kind, content, *rest in steps:
            if kind == "text":
                txt.insert("end", content)
            elif kind == "bold":
                txt.insert("end", content, "bold")
            elif kind == "link":
                url = rest[0]
                tag = f"link_{link_idx}"
                link_idx += 1
                txt.tag_configure(tag, foreground=COLOURS["accent"], underline=True)
                txt.tag_bind(tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
                txt.tag_bind(tag, "<Enter>", lambda e: txt.configure(cursor="hand2"))
                txt.tag_bind(tag, "<Leave>", lambda e: txt.configure(cursor="arrow"))
                txt.insert("end", content, (tag, "link"))

        txt.configure(state="disabled")

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        self._make_button(btn_row, "Got it, thanks Securious!", popup.destroy, tone="coast").pack(side="right")

    def _card(self, parent) -> tuple[ctk.CTkFrame, ctk.CTkFrame]:
        """Return (outer_card, inner_content) — pack children into inner, pack outer into layout."""
        outer = ctk.CTkFrame(
            parent, fg_color=COLOURS["panel"], corner_radius=12,
            border_width=1, border_color=COLOURS["border"],
        )
        inner = ctk.CTkFrame(outer, fg_color="transparent", corner_radius=0)
        inner.pack(fill="both", expand=True, padx=18, pady=14)
        return outer, inner

    def _hero_card(self, parent) -> tuple[ctk.CTkFrame, ctk.CTkFrame]:
        """Prominent section card — white background, bold accent border, coloured top strip."""
        outer = ctk.CTkFrame(
            parent, fg_color=COLOURS["panel"], corner_radius=12,
            border_width=2, border_color=COLOURS["accent"],
        )
        strip = ctk.CTkFrame(outer, fg_color=COLOURS["accent_light"], corner_radius=0, height=6)
        strip.pack(fill="x")
        strip.pack_propagate(False)
        inner = ctk.CTkFrame(outer, fg_color="transparent", corner_radius=0)
        inner.pack(fill="both", expand=True, padx=18, pady=14)
        return outer, inner

    def _prompt_card(self, parent, title: str) -> ctk.CTkFrame:
        shell = ctk.CTkFrame(parent, fg_color=COLOURS["industrial"], corner_radius=10)
        shell.pack(fill="x", pady=(6, 4))
        card = ctk.CTkFrame(shell, fg_color=COLOURS["prompt_bg"], corner_radius=8)
        card.pack(fill="x", padx=2, pady=2)
        ctk.CTkLabel(
            card, text=title,
            font=self.font_heading, text_color=COLOURS["industrial"],
            anchor="w", justify="left",
        ).pack(fill="x", padx=16, pady=(12, 4))
        return card

    def _resolve_button_tone(self, tone: str) -> tuple[str, str]:
        if tone == "coast":
            return COLOURS["coast"], COLOURS["accent"]
        if tone == "industrial":
            return COLOURS["industrial"], "#4B565E"
        return COLOURS["button"], COLOURS["button_hover"]

    def _make_big_button(self, parent, text: str, command, width: int = 280, tone: str = "primary") -> ctk.CTkButton:
        base_bg, hover_bg = self._resolve_button_tone(tone)
        return ctk.CTkButton(
            parent, text=text,
            font=self.font_button,
            fg_color=base_bg, text_color=COLOURS["button_text"],
            hover_color=hover_bg,
            corner_radius=8, width=width, height=48,
            cursor="hand2", command=command,
        )

    def _make_button(self, parent, text: str, command, tone: str = "primary") -> ctk.CTkButton:
        base_bg, hover_bg = self._resolve_button_tone(tone)
        return ctk.CTkButton(
            parent, text=text,
            font=self.font_button,
            fg_color=base_bg, text_color=COLOURS["button_text"],
            hover_color=hover_bg,
            corner_radius=8, height=36,
            cursor="hand2", command=command,
        )

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="Ready - select a file or website to check")
        bar = ctk.CTkFrame(self.root, fg_color=COLOURS["status_bg"], corner_radius=0)
        bar.pack(fill="x", side="bottom")

        self._protection_indicator = ctk.CTkLabel(
            bar, text="", font=self.font_small,
            anchor="e",
        )
        self._protection_indicator.pack(side="right", padx=12, pady=4)
        self._update_protection_indicator()

        ctk.CTkLabel(
            bar, textvariable=self.status_var,
            font=self.font_small, text_color=COLOURS["subtext"],
            anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=12, pady=4)

    def _update_protection_indicator(self):
        """Refresh the status-bar protection-level label."""
        level, _, fg = self._protection_status()
        labels = {
            "full": "🛡 Full Protection",
            "partial": "\u26a0\ufe0f Partial Protection",
            "basic": "\u26a0\ufe0f Basic Protection",
        }
        self._protection_indicator.configure(text=labels.get(level, ""), text_color=fg)

    def _is_first_run(self) -> bool:
        """Return True when no trusted contact and no API keys have been configured."""
        has_contact = bool(self.config.trusted_contact_name or self.config.trusted_contact_email)
        has_api_keys = bool(self.config.virustotal_api_key or self.config.google_safe_browsing_key)
        has_email = bool(self.config.email_address)
        return not (has_contact or has_api_keys or has_email)

    def _show_welcome_prompt(self):
        popup = self._popup("Welcome!", "640x520", resizable=False)
        popup.configure(fg_color=COLOURS["bg"])

        shell = ctk.CTkFrame(popup, fg_color=COLOURS["accent"], corner_radius=10)
        shell.pack(fill="both", expand=True, padx=20, pady=20)
        body = ctk.CTkFrame(shell, fg_color=COLOURS["panel"], corner_radius=8)
        body.pack(fill="both", expand=True, padx=2, pady=2)

        ctk.CTkLabel(
            body, text="👋  Welcome to Securious: Security Advisor!",
            font=self.font_title, text_color=COLOURS["accent"], anchor="w",
        ).pack(fill="x", padx=24, pady=(20, 6))

        self._wrap_label(
            body,
            text=(
                "This app helps you stay safe by checking files, websites, "
                "and emails before you open them."
            ),
            font=self.font_body, fg=COLOURS["text"],
        ).pack(fill="x", padx=24, pady=(0, 10))

        ctk.CTkLabel(
            body, text="To get started, we recommend setting up a few things:",
            font=self.font_body, text_color=COLOURS["text"], anchor="w",
        ).pack(fill="x", padx=24, pady=(0, 8))

        steps = [
            ("1.", "Add a trusted contact", "Someone you trust to help you if something looks suspicious."),
            ("2.", "Choose your Downloads folder", "The app watches this folder and alerts you about new files."),
            ("3.", "Connect your email (your choice!)",
             "If you want, the app can check your inbox for scams and phishing. "
             "This is completely optional — skip it if you prefer."),
            ("4.", "Add API keys (strongly recommended)",
             "These free keys let the app check files against 70+ antivirus "
             "engines (VirusTotal) and websites against Google's threat database "
             "(Google Safe Browsing). Setup takes about 5 minutes — look for the "
             "\"How to get this key\" buttons in Settings."),
        ]
        for num, title, desc in steps:
            step_row = ctk.CTkFrame(body, fg_color="transparent")
            step_row.pack(fill="x", padx=24, pady=3)
            ctk.CTkLabel(
                step_row, text=num, font=self.font_heading,
                text_color=COLOURS["coast"], width=30, anchor="ne",
            ).pack(side="left", padx=(0, 6))
            step_text = ctk.CTkFrame(step_row, fg_color="transparent")
            step_text.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(
                step_text, text=title, font=self.font_heading,
                text_color=COLOURS["accent"], anchor="w",
            ).pack(fill="x")
            self._wrap_label(
                step_text, text=desc, font=self.font_small, fg=COLOURS["subtext"],
            ).pack(fill="x")

        self._wrap_label(
            body,
            text=(
                "Need help? Click the \"🛡 Securious The Saviour\" button "
                "next to any section in Settings — it explains everything step by step!"
            ),
            font=self.font_body, fg=COLOURS["coast"],
        ).pack(fill="x", padx=24, pady=(14, 10))

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(0, 20))

        def go_to_settings():
            popup.destroy()
            self._show_tab("settings")

        self._make_button(
            btn_row, "⚙️  Take Me to Settings", go_to_settings,
        ).pack(side="left", padx=(0, 10))
        self._make_button(
            btn_row, "Skip for Now", popup.destroy, tone="industrial",
        ).pack(side="left")

    def _set_status(self, msg: str, auto_clear_ms: int = 0):
        if self._status_clear_id is not None:
            self.root.after_cancel(self._status_clear_id)
            self._status_clear_id = None
        self.status_var.set(msg)
        if auto_clear_ms > 0:
            self._status_clear_id = self.root.after(
                auto_clear_ms,
                lambda: self.status_var.set("Ready"),
            )

    def _set_status_temp(self, msg: str):
        """Show a transient status message that auto-clears after 5 seconds."""
        self._set_status(msg, auto_clear_ms=5000)

    def _clear(self, frame):
        for w in frame.winfo_children():
            w.destroy()

    def _show_scanning(self, container):
        self._clear(container)
        ctk.CTkLabel(
            container, text="🔍  Checking… please wait",
            font=self.font_heading, text_color=COLOURS["coast"],
        ).pack(pady=40)

    def _show_message(self, container, msg: str, risk: str):
        self._clear(container)
        fg, bg, _ = RISK_COLOURS.get(risk, (COLOURS["caution"], COLOURS["caution_bg"], ""))
        shell = ctk.CTkFrame(container, fg_color=COLOURS["industrial"], corner_radius=10)
        shell.pack(fill="x", pady=10)
        card = ctk.CTkFrame(shell, fg_color=bg, corner_radius=8)
        card.pack(fill="x", padx=2, pady=2)
        self._wrap_label(card, text=msg, font=self.font_body, fg=fg).pack(fill="x", padx=20, pady=20)
