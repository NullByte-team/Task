"""
NullByte Tool - Main Application Window
Full-featured pen-testing GUI: scan configuration, live results,
CVE details, severity dashboard, and remediation controls.
"""

import os
import sys
import json
import csv
import time
import socket
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from typing import List, Dict, Optional, Any
from datetime import datetime

import ui.styles as st
from core.scanner       import Scanner, ScanResult, ServiceInfo
from core.cve_lookup    import lookup_cves, CVEEntry
from core.exploit_matcher import match_service, ServiceRisk, score_summary
from core.remediation   import RemediationEngine
from core.ip_loader     import load_ips_from_file, validate_target


# ══════════════════════════════════════════════════════════════════════════════
#  Helper widgets
# ══════════════════════════════════════════════════════════════════════════════

class DarkButton(tk.Frame):
    """Custom styled button."""

    def __init__(self, parent, text, command=None, color=st.BLUE,
                 width=14, **kwargs):
        super().__init__(parent, bg=st.BG_MEDIUM, **kwargs)
        self._cmd   = command
        self._color = color
        self._hover = self._lighten(color)

        self._lbl = tk.Label(
            self, text=text, font=st.FONT_UI_BOLD,
            fg=color, bg=st.BG_LIGHT,
            padx=12, pady=6, cursor="hand2",
            width=width,
        )
        self._lbl.pack(padx=1, pady=1)
        self._lbl.bind("<Button-1>",  lambda e: command() if command else None)
        self._lbl.bind("<Enter>",     lambda e: self._lbl.config(bg=st.BG_BORDER))
        self._lbl.bind("<Leave>",     lambda e: self._lbl.config(bg=st.BG_LIGHT))

    @staticmethod
    def _lighten(hex_color: str) -> str:
        return hex_color   # simplified


class SeverityBar(tk.Canvas):
    """Horizontal bar showing a CVSS score 0-10."""

    def __init__(self, parent, cvss: float, width=120, height=14, **kw):
        super().__init__(parent, width=width, height=height,
                         bg=st.BG_MEDIUM, highlightthickness=0, **kw)
        self._draw(cvss, width, height)

    def _draw(self, cvss: float, w, h):
        # Background
        self.create_rectangle(0, 0, w, h, fill=st.BG_BORDER, outline="")
        # Filled portion
        fill_w = int((cvss / 10.0) * w)
        color  = st.severity_color(cvss)
        if fill_w > 0:
            self.create_rectangle(0, 0, fill_w, h, fill=color, outline="")
        # Score text
        self.create_text(w // 2, h // 2, text=f"{cvss:.1f}",
                         font=("Consolas", 8, "bold"),
                         fill=st.TEXT_PRIMARY)


# ══════════════════════════════════════════════════════════════════════════════
#  Main Application
# ══════════════════════════════════════════════════════════════════════════════

class NullByteApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self._scanner    = Scanner()
        self._remediation = RemediationEngine()

        # State
        self._scan_results:  List[ScanResult]  = []
        self._service_risks: List[ServiceRisk] = []
        self._shutdown_log:  Dict[str, dict]   = {}   # host+port → info
        self._selected_risk: Optional[ServiceRisk] = None

        self._configure_root()
        self._apply_ttk_theme()
        self._build_layout()
        self._update_status("Ready — configure a scan and press Start Scan")

    # ──────────────────────────────────────────────────────── Root config ──

    def _configure_root(self):
        self.root.title("NullByte — Penetration Testing Tool")
        self.root.configure(bg=st.BG_ROOT)
        self.root.minsize(1100, 700)

        # Try to maximize
        try:
            self.root.state("zoomed")
        except tk.TclError:
            self.root.geometry("1280x800")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _apply_ttk_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".",
            background=st.BG_DARK, foreground=st.TEXT_PRIMARY,
            fieldbackground=st.BG_MEDIUM, troughcolor=st.BG_BORDER,
            selectbackground=st.BLUE, selectforeground=st.BG_ROOT,
            bordercolor=st.BG_BORDER, lightcolor=st.BG_MEDIUM,
            darkcolor=st.BG_MEDIUM, relief="flat",
        )
        style.configure("TFrame",       background=st.BG_DARK)
        style.configure("TLabel",       background=st.BG_DARK, foreground=st.TEXT_PRIMARY)
        style.configure("TEntry",       fieldbackground=st.BG_MEDIUM, foreground=st.TEXT_PRIMARY,
                        insertcolor=st.GREEN_BRIGHT, borderwidth=1)
        style.configure("TRadiobutton", background=st.BG_DARK, foreground=st.TEXT_SECONDARY)
        style.configure("TCheckbutton", background=st.BG_DARK, foreground=st.TEXT_SECONDARY)
        style.configure("TNotebook",    background=st.BG_DARK, tabmargins=[2, 4, 0, 0])
        style.configure("TNotebook.Tab",
            background=st.BG_MEDIUM, foreground=st.TEXT_SECONDARY,
            padding=[14, 6], font=st.FONT_UI_BOLD,
        )
        style.map("TNotebook.Tab",
            background=[("selected", st.BG_DARK)],
            foreground=[("selected", st.CYAN)],
        )
        style.configure("Treeview",
            background=st.BG_MEDIUM, fieldbackground=st.BG_MEDIUM,
            foreground=st.TEXT_PRIMARY, rowheight=26,
            font=st.FONT_MONO,
        )
        style.configure("Treeview.Heading",
            background=st.BG_LIGHT, foreground=st.TEXT_SECONDARY,
            font=st.FONT_UI_BOLD, relief="flat",
        )
        style.map("Treeview",
            background=[("selected", st.BLUE)],
            foreground=[("selected", st.BG_ROOT)],
        )
        style.configure("TScrollbar",
            troughcolor=st.BG_DARK, background=st.BG_BORDER,
            arrowcolor=st.TEXT_MUTED,
        )
        style.configure("TProgressbar",
            troughcolor=st.BG_BORDER, background=st.GREEN,
        )
        style.configure("Vertical.TScrollbar",  width=8)
        style.configure("Horizontal.TScrollbar", width=8)

    # ──────────────────────────────────────────────────────── Layout ──

    def _build_layout(self):
        # ── Top bar ──────────────────────────────────────────────────────────
        self._build_topbar()

        # ── Main pane ────────────────────────────────────────────────────────
        main = tk.PanedWindow(
            self.root, orient="horizontal",
            bg=st.BG_ROOT, sashwidth=4, sashrelief="flat",
        )
        main.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # Left sidebar
        left = tk.Frame(main, bg=st.BG_DARK, width=280)
        left.pack_propagate(False)
        main.add(left, minsize=240)
        self._build_sidebar(left)

        # Right content
        right = tk.Frame(main, bg=st.BG_DARK)
        main.add(right, minsize=600)
        self._build_content(right)

        # ── Status bar ────────────────────────────────────────────────────────
        self._build_statusbar()

    # ── Top bar ──

    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=st.BG_ROOT, height=54)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        bar.pack_propagate(False)

        # Logo / title
        title = tk.Label(
            bar,
            text="⬡  NULLBYTE",
            font=("Consolas", 20, "bold"),
            fg=st.RED_GLOW, bg=st.BG_ROOT,
        )
        title.pack(side="left", padx=16)

        subtitle = tk.Label(
            bar,
            text="Penetration Testing Tool",
            font=("Consolas", 10),
            fg=st.TEXT_MUTED, bg=st.BG_ROOT,
        )
        subtitle.pack(side="left", padx=0, pady=(8, 0))

        # Separator
        sep = tk.Frame(self.root, bg=st.RED_GLOW, height=1)
        sep.pack(fill="x", padx=6)

    # ── Sidebar ──

    def _build_sidebar(self, parent):
        canvas = tk.Canvas(parent, bg=st.BG_DARK, highlightthickness=0)
        sb     = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        frame  = tk.Frame(canvas, bg=st.BG_DARK)

        frame.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._build_scan_config(frame)

    def _build_scan_config(self, parent):
        pad = {"padx": 14, "pady": 4}

        def section_label(text):
            f = tk.Frame(parent, bg=st.BG_DARK)
            f.pack(fill="x", padx=10, pady=(16, 4))
            tk.Label(f, text=text, font=st.FONT_UI_BOLD,
                     fg=st.CYAN, bg=st.BG_DARK).pack(side="left")
            tk.Frame(f, bg=st.BG_BORDER, height=1).pack(
                side="left", fill="x", expand=True, padx=(8, 0), pady=6)

        # ── Target ──────────────────────────────────────────────────────────
        section_label("TARGET")

        tk.Label(parent, text="IP Address / Domain:", font=st.FONT_UI_SM,
                 fg=st.TEXT_SECONDARY, bg=st.BG_DARK).pack(anchor="w", **pad)

        self._target_var = tk.StringVar()
        entry = tk.Entry(
            parent, textvariable=self._target_var,
            font=st.FONT_MONO_MD,
            bg=st.BG_MEDIUM, fg=st.GREEN_BRIGHT,
            insertbackground=st.GREEN_BRIGHT,
            relief="flat", bd=4,
        )
        entry.pack(fill="x", padx=14, pady=2)
        entry.bind("<Return>", lambda e: self._start_scan())

        # IP File upload
        file_frame = tk.Frame(parent, bg=st.BG_DARK)
        file_frame.pack(fill="x", **pad)

        self._file_var = tk.StringVar(value="No file selected")
        tk.Label(parent, textvariable=self._file_var, font=st.FONT_UI_SM,
                 fg=st.TEXT_MUTED, bg=st.BG_DARK,
                 wraplength=230, justify="left").pack(anchor="w", padx=14)

        DarkButton(parent, "📁  Upload IP File", self._browse_file,
                   color=st.TEXT_SECONDARY, width=20).pack(padx=14, pady=4)

        self._ip_file_path: Optional[str] = None

        # ── Port Mode ────────────────────────────────────────────────────────
        section_label("PORT SELECTION")

        self._port_mode = tk.StringVar(value="top1000")

        modes = [
            ("⚡  Top 1000 Ports (Recommended)", "top1000"),
            ("🔍  All Ports (1–65535)",           "all"),
            ("✏️   Custom Ports",                  "custom"),
        ]
        for text, val in modes:
            rb = tk.Radiobutton(
                parent, text=text, variable=self._port_mode, value=val,
                font=st.FONT_UI_SM, fg=st.TEXT_SECONDARY, bg=st.BG_DARK,
                activebackground=st.BG_DARK, activeforeground=st.CYAN,
                selectcolor=st.BG_MEDIUM,
                command=self._on_port_mode_change,
            )
            rb.pack(anchor="w", padx=14, pady=2)

        tk.Label(parent, text="Custom ports (e.g. 22,80,443-8080):",
                 font=st.FONT_UI_SM, fg=st.TEXT_MUTED, bg=st.BG_DARK
                 ).pack(anchor="w", padx=14, pady=(6, 2))

        self._custom_ports_var = tk.StringVar()
        self._custom_entry = tk.Entry(
            parent, textvariable=self._custom_ports_var,
            font=st.FONT_MONO, bg=st.BG_MEDIUM, fg=st.TEXT_PRIMARY,
            insertbackground=st.GREEN_BRIGHT,
            relief="flat", bd=4, state="disabled",
        )
        self._custom_entry.pack(fill="x", padx=14, pady=2)

        # ── Scan Controls ────────────────────────────────────────────────────
        section_label("CONTROLS")

        self._scan_btn = DarkButton(
            parent, "▶  START SCAN", self._start_scan,
            color=st.GREEN_BRIGHT, width=20,
        )
        self._scan_btn.pack(padx=14, pady=4)

        self._stop_btn = DarkButton(
            parent, "■  STOP SCAN", self._stop_scan,
            color=st.RED, width=20,
        )
        self._stop_btn.pack(padx=14, pady=2)

        # ── Export ───────────────────────────────────────────────────────────
        section_label("EXPORT RESULTS")

        for label, fmt in [("Export JSON", "json"), ("Export HTML", "html"), ("Export CSV", "csv")]:
            DarkButton(
                parent, label,
                command=lambda f=fmt: self._export(f),
                color=st.PURPLE, width=20,
            ).pack(padx=14, pady=2)

        # ── Stats ────────────────────────────────────────────────────────────
        section_label("SCAN STATS")
        self._stats_frame = tk.Frame(parent, bg=st.BG_DARK)
        self._stats_frame.pack(fill="x", padx=14, pady=4)
        self._stats_labels: Dict[str, tk.Label] = {}
        for key, label in [
            ("hosts",     "Hosts scanned:"),
            ("ports",     "Open ports:"),
            ("vulns",     "Vulnerabilities:"),
            ("critical",  "Critical:"),
            ("exploits",  "Exploitable:"),
        ]:
            row = tk.Frame(self._stats_frame, bg=st.BG_DARK)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, font=st.FONT_UI_SM,
                     fg=st.TEXT_MUTED, bg=st.BG_DARK).pack(side="left")
            lbl = tk.Label(row, text="0", font=st.FONT_MONO_SM,
                           fg=st.TEXT_PRIMARY, bg=st.BG_DARK)
            lbl.pack(side="right")
            self._stats_labels[key] = lbl

        # Progress bar
        self._progress = ttk.Progressbar(parent, mode="indeterminate",
                                          style="TProgressbar")
        self._progress.pack(fill="x", padx=14, pady=8)

    # ── Content (right panel) ──

    def _build_content(self, parent):
        self._notebook = ttk.Notebook(parent)
        self._notebook.pack(fill="both", expand=True, padx=6, pady=6)

        self._build_results_tab()
        self._build_dashboard_tab()
        self._build_cve_tab()
        self._build_remediation_tab()
        self._build_log_tab()

    # ── Results Tab ──

    def _build_results_tab(self):
        frame = tk.Frame(self._notebook, bg=st.BG_DARK)
        self._notebook.add(frame, text="  📡  Live Results  ")

        # Toolbar
        tb = tk.Frame(frame, bg=st.BG_DARK, height=36)
        tb.pack(fill="x", padx=8, pady=(8, 4))
        tb.pack_propagate(False)

        tk.Label(tb, text="Filter:", font=st.FONT_UI_SM,
                 fg=st.TEXT_MUTED, bg=st.BG_DARK).pack(side="left", padx=4)
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *a: self._apply_filter())
        filt = tk.Entry(tb, textvariable=self._filter_var,
                        font=st.FONT_MONO, bg=st.BG_MEDIUM, fg=st.TEXT_PRIMARY,
                        insertbackground=st.GREEN_BRIGHT, relief="flat", bd=4,
                        width=25)
        filt.pack(side="left", padx=4)

        tk.Label(tb, text="Severity:", font=st.FONT_UI_SM,
                 fg=st.TEXT_MUTED, bg=st.BG_DARK).pack(side="left", padx=(16, 4))
        self._sev_filter = tk.StringVar(value="ALL")
        sev_cb = ttk.Combobox(tb, textvariable=self._sev_filter,
                               values=["ALL","CRITICAL","HIGH","MEDIUM","LOW","NONE"],
                               state="readonly", width=10, font=st.FONT_UI_SM)
        sev_cb.pack(side="left", padx=4)
        sev_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        DarkButton(tb, "Clear", self._clear_results, color=st.TEXT_MUTED, width=8).pack(side="right", padx=4)

        # Treeview
        cols = ("host", "port", "proto", "service", "version", "cve_count", "cvss", "severity", "exploit")
        hdrs = ("Host", "Port", "Proto", "Service", "Version", "CVEs", "CVSS", "Severity", "Exploit")

        tree_frame = tk.Frame(frame, bg=st.BG_DARK)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=4)

        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                   selectmode="browse")
        widths = [130, 60, 55, 100, 200, 50, 60, 80, 70]
        for col, hdr, w in zip(cols, hdrs, widths):
            self._tree.heading(col, text=hdr,
                               command=lambda c=col: self._sort_tree(c))
            self._tree.column(col, width=w, minwidth=40, anchor="w")

        # Tags for coloring
        for sev, color in [("CRITICAL", st.SEV_CRITICAL), ("HIGH", st.SEV_HIGH),
                             ("MEDIUM", st.SEV_MEDIUM), ("LOW", st.SEV_LOW),
                             ("NONE", st.SEV_NONE)]:
            self._tree.tag_configure(sev, foreground=color)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._tree.bind("<Double-1>",         self._on_tree_double_click)

        # Row data storage (iid → ServiceRisk)
        self._tree_data: Dict[str, ServiceRisk] = {}
        self._sort_reverse: Dict[str, bool] = {}

    # ── Dashboard Tab ──

    def _build_dashboard_tab(self):
        frame = tk.Frame(self._notebook, bg=st.BG_DARK)
        self._notebook.add(frame, text="  📊  Dashboard  ")

        # Summary cards row
        cards_row = tk.Frame(frame, bg=st.BG_DARK)
        cards_row.pack(fill="x", padx=16, pady=16)

        self._dash_cards: Dict[str, dict] = {}
        card_defs = [
            ("total",      "TOTAL",      st.CYAN,         "0"),
            ("critical",   "CRITICAL",   st.SEV_CRITICAL, "0"),
            ("high",       "HIGH",       st.SEV_HIGH,     "0"),
            ("medium",     "MEDIUM",     st.SEV_MEDIUM,   "0"),
            ("exploitable","EXPLOITABLE",st.PURPLE,       "0"),
        ]
        for key, label, color, init in card_defs:
            card = tk.Frame(cards_row, bg=st.BG_MEDIUM,
                            padx=20, pady=12, bd=0)
            card.pack(side="left", expand=True, fill="both", padx=6)

            num_lbl = tk.Label(card, text=init, font=("Consolas", 36, "bold"),
                               fg=color, bg=st.BG_MEDIUM)
            num_lbl.pack()
            tk.Label(card, text=label, font=st.FONT_UI_SM,
                     fg=st.TEXT_MUTED, bg=st.BG_MEDIUM).pack()
            self._dash_cards[key] = {"frame": card, "num": num_lbl, "color": color}

        # Services risk list
        tk.Frame(frame, bg=st.BG_BORDER, height=1).pack(fill="x", padx=16, pady=8)
        tk.Label(frame, text="Service Risk Overview",
                 font=st.FONT_UI_TITLE, fg=st.TEXT_PRIMARY, bg=st.BG_DARK
                 ).pack(anchor="w", padx=16)

        dash_scroll = tk.Frame(frame, bg=st.BG_DARK)
        dash_scroll.pack(fill="both", expand=True, padx=16, pady=8)

        self._dash_canvas = tk.Canvas(dash_scroll, bg=st.BG_DARK, highlightthickness=0)
        dash_vsb = ttk.Scrollbar(dash_scroll, orient="vertical",
                                  command=self._dash_canvas.yview)
        self._dash_inner = tk.Frame(self._dash_canvas, bg=st.BG_DARK)
        self._dash_inner.bind(
            "<Configure>",
            lambda e: self._dash_canvas.configure(
                scrollregion=self._dash_canvas.bbox("all"))
        )
        self._dash_canvas.create_window((0, 0), window=self._dash_inner, anchor="nw")
        self._dash_canvas.configure(yscrollcommand=dash_vsb.set)
        self._dash_canvas.pack(side="left", fill="both", expand=True)
        dash_vsb.pack(side="right", fill="y")

    # ── CVE Detail Tab ──

    def _build_cve_tab(self):
        frame = tk.Frame(self._notebook, bg=st.BG_DARK)
        self._notebook.add(frame, text="  🔍  CVE Details  ")

        tk.Label(frame, text="Select a service from Live Results to view CVE details.",
                 font=st.FONT_UI_SM, fg=st.TEXT_MUTED, bg=st.BG_DARK
                 ).pack(pady=10)

        self._cve_frame = tk.Frame(frame, bg=st.BG_DARK)
        self._cve_frame.pack(fill="both", expand=True, padx=8, pady=4)

        # Service info header
        self._cve_header_var = tk.StringVar()
        tk.Label(self._cve_frame, textvariable=self._cve_header_var,
                 font=st.FONT_MONO_LG, fg=st.CYAN, bg=st.BG_DARK
                 ).pack(anchor="w", padx=8, pady=4)

        # CVE list
        cve_tree_frame = tk.Frame(self._cve_frame, bg=st.BG_DARK)
        cve_tree_frame.pack(fill="both", expand=True, padx=8)

        cve_cols = ("cve_id", "cvss", "severity", "published", "exploit", "description")
        cve_hdrs = ("CVE ID", "CVSS", "Severity", "Published", "Exploit?", "Description")

        self._cve_tree = ttk.Treeview(cve_tree_frame, columns=cve_cols,
                                       show="headings", selectmode="browse", height=8)
        cve_widths = [130, 55, 75, 90, 70, 500]
        for col, hdr, w in zip(cve_cols, cve_hdrs, cve_widths):
            self._cve_tree.heading(col, text=hdr)
            self._cve_tree.column(col, width=w, minwidth=40)

        for sev, color in [("CRITICAL", st.SEV_CRITICAL), ("HIGH", st.SEV_HIGH),
                             ("MEDIUM", st.SEV_MEDIUM), ("LOW", st.SEV_LOW)]:
            self._cve_tree.tag_configure(sev, foreground=color)
        self._cve_tree.tag_configure("EXPLOIT", foreground=st.ORANGE)

        cve_vsb = ttk.Scrollbar(cve_tree_frame, orient="vertical",  command=self._cve_tree.yview)
        cve_hsb = ttk.Scrollbar(cve_tree_frame, orient="horizontal", command=self._cve_tree.xview)
        self._cve_tree.configure(yscrollcommand=cve_vsb.set, xscrollcommand=cve_hsb.set)
        self._cve_tree.grid(row=0, column=0, sticky="nsew")
        cve_vsb.grid(row=0, column=1, sticky="ns")
        cve_hsb.grid(row=1, column=0, sticky="ew")
        cve_tree_frame.rowconfigure(0, weight=1)
        cve_tree_frame.columnconfigure(0, weight=1)

        self._cve_tree.bind("<<TreeviewSelect>>", self._on_cve_select)

        # CVE Description detail
        tk.Frame(self._cve_frame, bg=st.BG_BORDER, height=1).pack(fill="x", padx=8, pady=6)
        self._cve_detail = scrolledtext.ScrolledText(
            self._cve_frame, font=st.FONT_MONO_SM,
            bg=st.BG_MEDIUM, fg=st.TEXT_PRIMARY,
            insertbackground=st.GREEN_BRIGHT,
            relief="flat", bd=0, height=8,
            wrap="word", state="disabled",
        )
        self._cve_detail.pack(fill="both", expand=True, padx=8, pady=4)

    # ── Remediation Tab ──

    def _build_remediation_tab(self):
        frame = tk.Frame(self._notebook, bg=st.BG_DARK)
        self._notebook.add(frame, text="  🔧  Remediation  ")

        # Instruction banner
        banner = tk.Frame(frame, bg="#1a0d00", padx=12, pady=10)
        banner.pack(fill="x", padx=10, pady=10)
        tk.Label(banner,
                 text="⚠️  Remediation actions are REAL — they will upgrade or stop services on the target machine.",
                 font=st.FONT_UI_BOLD, fg=st.ORANGE, bg="#1a0d00", wraplength=900
                 ).pack(anchor="w")
        tk.Label(banner,
                 text="   For remote targets, instructions will be shown. For local targets, commands execute directly.",
                 font=st.FONT_UI_SM, fg=st.TEXT_SECONDARY, bg="#1a0d00", wraplength=900
                 ).pack(anchor="w")

        # Service selector
        sel_frame = tk.Frame(frame, bg=st.BG_DARK)
        sel_frame.pack(fill="x", padx=10, pady=4)

        tk.Label(sel_frame, text="Select vulnerable service:",
                 font=st.FONT_UI_BOLD, fg=st.TEXT_PRIMARY, bg=st.BG_DARK
                 ).pack(side="left", padx=4)

        self._rem_svc_var = tk.StringVar()
        self._rem_combo = ttk.Combobox(sel_frame, textvariable=self._rem_svc_var,
                                        state="readonly", width=45, font=st.FONT_MONO)
        self._rem_combo.pack(side="left", padx=8)
        self._rem_combo.bind("<<ComboboxSelected>>", self._on_rem_select)

        # Action buttons
        btn_row = tk.Frame(frame, bg=st.BG_DARK)
        btn_row.pack(fill="x", padx=10, pady=8)

        DarkButton(btn_row, "⬆  UPGRADE SERVICE",
                   self._do_upgrade, color=st.GREEN, width=22).pack(side="left", padx=6)
        DarkButton(btn_row, "🛑  SHUTDOWN SERVICE",
                   self._do_shutdown, color=st.RED, width=22).pack(side="left", padx=6)

        # Shutdown services list
        sd_frame = tk.Frame(frame, bg=st.BG_DARK)
        sd_frame.pack(fill="x", padx=10, pady=4)

        tk.Label(sd_frame, text="Disabled Services:",
                 font=st.FONT_UI_BOLD, fg=st.ORANGE, bg=st.BG_DARK
                 ).pack(side="left", padx=4)

        self._disabled_var = tk.StringVar(value="None")
        tk.Label(sd_frame, textvariable=self._disabled_var,
                 font=st.FONT_MONO_SM, fg=st.TEXT_SECONDARY, bg=st.BG_DARK
                 ).pack(side="left", padx=8)

        DarkButton(sd_frame, "▶ Re-enable",
                   self._do_restart, color=st.CYAN, width=14).pack(side="right", padx=6)

        # Output console
        tk.Frame(frame, bg=st.BG_BORDER, height=1).pack(fill="x", padx=10, pady=4)
        tk.Label(frame, text="Output:", font=st.FONT_UI_BOLD,
                 fg=st.TEXT_SECONDARY, bg=st.BG_DARK).pack(anchor="w", padx=14)

        self._rem_output = scrolledtext.ScrolledText(
            frame, font=st.FONT_MONO_SM,
            bg=st.BG_ROOT, fg=st.GREEN_BRIGHT,
            insertbackground=st.GREEN_BRIGHT,
            relief="flat", bd=0, height=14,
            wrap="word", state="disabled",
        )
        self._rem_output.pack(fill="both", expand=True, padx=10, pady=4)

    # ── Log Tab ──

    def _build_log_tab(self):
        frame = tk.Frame(self._notebook, bg=st.BG_DARK)
        self._notebook.add(frame, text="  📋  Scan Log  ")

        toolbar = tk.Frame(frame, bg=st.BG_DARK)
        toolbar.pack(fill="x", padx=8, pady=6)
        DarkButton(toolbar, "Clear Log", self._clear_log, color=st.TEXT_MUTED, width=10).pack(side="right")

        self._log_text = scrolledtext.ScrolledText(
            frame, font=st.FONT_MONO_SM,
            bg=st.BG_ROOT, fg=st.TEXT_SECONDARY,
            insertbackground=st.GREEN_BRIGHT,
            relief="flat", bd=0,
            wrap="word", state="disabled",
        )
        self._log_text.pack(fill="both", expand=True, padx=8, pady=4)
        self._log_text.tag_configure("info",    foreground=st.CYAN)
        self._log_text.tag_configure("ok",      foreground=st.GREEN)
        self._log_text.tag_configure("warn",    foreground=st.ORANGE)
        self._log_text.tag_configure("error",   foreground=st.RED)
        self._log_text.tag_configure("section", foreground=st.PURPLE, font=st.FONT_MONO_MD)

    # ── Status bar ──

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg="#0a0a0a", height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="Ready")
        tk.Label(bar, textvariable=self._status_var, font=st.FONT_UI_SM,
                 fg=st.TEXT_MUTED, bg="#0a0a0a", anchor="w"
                 ).pack(side="left", padx=12, fill="y")

        # NullByte badge (red glowing)
        badge_outer = tk.Frame(bar, bg="#300000", padx=10, pady=3)
        badge_outer.pack(side="right", padx=8, pady=2)
        self._badge_lbl = tk.Label(
            badge_outer, text="● NullByte Team",
            font=("Consolas", 9, "bold"),
            fg=st.RED_GLOW, bg="#300000",
        )
        self._badge_lbl.pack()
        self._badge_state = False
        self._pulse_badge()

    def _pulse_badge(self):
        self._badge_state = not self._badge_state
        try:
            self._badge_lbl.configure(
                fg=st.RED_GLOW if self._badge_state else "#880000"
            )
            self.root.after(700, self._pulse_badge)
        except tk.TclError:
            pass

    # ══════════════════════════════════════════════════════ Scan Logic ══════

    def _on_port_mode_change(self):
        mode = self._port_mode.get()
        if mode == "custom":
            self._custom_entry.configure(state="normal")
        else:
            self._custom_entry.configure(state="disabled")

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select IP file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self._ip_file_path = path
            name = os.path.basename(path)
            self._file_var.set(f"📄 {name}")
            self._log(f"IP file loaded: {path}", "info")

    def _start_scan(self):
        if self._scanner.is_running():
            messagebox.showwarning("Scan Running", "A scan is already in progress.")
            return

        # Collect targets
        targets: List[str] = []

        manual_target = self._target_var.get().strip()
        if manual_target:
            targets.append(manual_target)

        if self._ip_file_path:
            try:
                file_targets = load_ips_from_file(self._ip_file_path)
                targets.extend(file_targets)
                self._log(f"Loaded {len(file_targets)} targets from file.", "info")
            except Exception as exc:
                messagebox.showerror("File Error", str(exc))
                return

        if not targets:
            messagebox.showwarning("No Target", "Enter an IP / domain or upload a file.")
            return

        # De-duplicate
        seen = set()
        unique_targets = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)
        targets = unique_targets

        self._scan_results.clear()
        self._service_risks.clear()

        self._log("=" * 60, "section")
        self._log(f"Starting scan of {len(targets)} target(s)   [{datetime.now():%Y-%m-%d %H:%M:%S}]", "info")
        for t in targets:
            self._log(f"  Target: {t}", "info")
        self._log("=" * 60, "section")

        self._progress.start(12)
        self._update_status(f"Scanning {len(targets)} target(s) ...")

        self._scanner.scan(
            targets=targets,
            port_mode=self._port_mode.get(),
            custom_ports=self._custom_ports_var.get(),
            on_host=self._on_host_result,
            on_progress=self._on_progress_msg,
            on_done=self._on_scan_done,
        )

    def _stop_scan(self):
        self._scanner.stop()
        self._log("Scan stopped by user.", "warn")
        self._update_status("Scan stopped.")
        self._progress.stop()

    # ══════════════════════════════════════════════════ Scan Callbacks ══════

    def _on_host_result(self, result: ScanResult):
        """Called from scanner thread — marshal to main thread."""
        self.root.after(0, self._process_host_result, result)

    def _on_progress_msg(self, msg: str):
        self.root.after(0, self._update_status, msg)
        self.root.after(0, self._log, msg, "info")

    def _on_scan_done(self, results: List[ScanResult]):
        self.root.after(0, self._finish_scan, results)

    def _process_host_result(self, result: ScanResult):
        self._scan_results.append(result)
        self._log(f"\nHost: {result.host} ({result.hostname})  [{result.state}]", "ok")

        if result.state == "error":
            self._log(f"  Error: {result.raw_output}", "error")
            return

        if result.state != "up" or not result.services:
            self._log("  No open ports found.", "warn")
            return

        self._log(f"  OS: {result.os_guess or 'Unknown'}", "info")
        self._log(f"  Open ports: {len(result.services)}", "info")

        # Start CVE lookup for each service in background
        for svc in result.services:
            self._log(f"  [{svc.port}/{svc.protocol}] {svc.service} — {svc.display_version}", "info")
            threading.Thread(
                target=self._lookup_and_show_service,
                args=(svc,), daemon=True
            ).start()

    def _lookup_and_show_service(self, svc: ServiceInfo):
        """Look up CVEs for a service and add to results (from thread)."""
        try:
            cves = lookup_cves(svc.product, svc.version, svc.service)
        except Exception as exc:
            cves = []
            self.root.after(0, self._log, f"  CVE lookup error for {svc.display_version}: {exc}", "warn")

        risk = match_service(svc, cves)
        self._service_risks.append(risk)

        # Marshal UI update to main thread
        self.root.after(0, self._add_tree_row, risk)
        self.root.after(0, self._update_dashboard)
        self.root.after(0, self._update_stats)
        self.root.after(0, self._update_remediation_list)

        if cves:
            top = max(cves, key=lambda c: c.cvss)
            self.root.after(0, self._log,
                f"  CVE: {top.cve_id} CVSS={top.cvss:.1f} [{risk.severity}]"
                + (" ⚡ EXPLOIT AVAILABLE" if risk.is_exploitable else ""),
                "warn" if top.cvss >= 7 else "info"
            )

    def _finish_scan(self, results):
        self._progress.stop()
        total = len(results)
        total_open = sum(len(r.services) for r in results if r.state == "up")
        self._log("=" * 60, "section")
        self._log(f"Scan complete. {total} host(s), {total_open} open port(s).", "ok")
        self._log("=" * 60, "section")
        self._update_status(
            f"Scan complete — {total} host(s), {total_open} port(s), "
            f"{len(self._service_risks)} service(s) analysed."
        )
        self._notebook.select(0)

    # ══════════════════════════════════════════════════ Tree Management ══════

    def _add_tree_row(self, risk: ServiceRisk):
        svc = risk.service
        key = f"{svc.host}:{svc.port}"

        # Skip if service is in shutdown log
        if key in self._shutdown_log:
            return

        exploit_icon = "⚡ Yes" if risk.is_exploitable else "No"
        cve_count    = len(risk.cves)
        cvss_str     = f"{risk.max_cvss:.1f}" if risk.max_cvss > 0 else "—"

        iid = self._tree.insert("", "end", values=(
            svc.host,
            str(svc.port),
            svc.protocol,
            svc.service or "—",
            svc.display_version[:35] or "—",
            str(cve_count),
            cvss_str,
            risk.severity,
            exploit_icon,
        ), tags=(risk.severity,))

        self._tree_data[iid] = risk

    def _apply_filter(self):
        """Re-draw tree with current filter settings."""
        text_filter = self._filter_var.get().lower()
        sev_filter  = self._sev_filter.get()

        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._tree_data.clear()

        for risk in self._service_risks:
            svc = risk.service
            key = f"{svc.host}:{svc.port}"
            if key in self._shutdown_log:
                continue
            if sev_filter != "ALL" and risk.severity != sev_filter:
                continue
            search_str = (
                f"{svc.host} {svc.port} {svc.service} "
                f"{svc.display_version} {risk.severity} {risk.cve_ids}"
            ).lower()
            if text_filter and text_filter not in search_str:
                continue
            self._add_tree_row(risk)

    def _sort_tree(self, col: str):
        rev = self._sort_reverse.get(col, False)
        risks = list(self._tree_data.values())

        def key_fn(r):
            svc = r.service
            mapping = {
                "host": svc.host, "port": svc.port, "proto": svc.protocol,
                "service": svc.service, "version": svc.display_version,
                "cve_count": len(r.cves), "cvss": r.max_cvss,
                "severity": r.max_cvss, "exploit": r.is_exploitable,
            }
            return mapping.get(col, "")

        risks.sort(key=key_fn, reverse=rev)
        self._sort_reverse[col] = not rev

        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._tree_data.clear()
        for risk in risks:
            self._add_tree_row(risk)

    def _clear_results(self):
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._tree_data.clear()
        self._scan_results.clear()
        self._service_risks.clear()
        self._update_dashboard()
        self._update_stats()
        self._log("Results cleared.", "info")

    # ══════════════════════════════════════════════════ Dashboard ══════════

    def _update_dashboard(self):
        summary = score_summary(self._service_risks)

        # Update cards
        for key in ("total", "critical", "high", "medium", "exploitable"):
            val = summary.get(key, 0)
            try:
                self._dash_cards[key]["num"].configure(text=str(val))
            except (KeyError, tk.TclError):
                pass

        # Update service rows in dashboard
        for widget in self._dash_inner.winfo_children():
            widget.destroy()

        # Sort by risk score
        sorted_risks = sorted(self._service_risks, key=lambda r: r.risk_score, reverse=True)

        for risk in sorted_risks[:30]:   # Show top 30
            svc  = risk.service
            key  = f"{svc.host}:{svc.port}"
            if key in self._shutdown_log:
                continue

            row = tk.Frame(self._dash_inner, bg=st.BG_MEDIUM, pady=6, padx=10)
            row.pack(fill="x", pady=2, padx=2)

            # Severity indicator
            ind = tk.Frame(row, bg=risk.severity_color, width=5)
            ind.pack(side="left", fill="y", padx=(0, 10))

            # Service info
            info_frame = tk.Frame(row, bg=st.BG_MEDIUM)
            info_frame.pack(side="left", fill="both", expand=True)

            top_line = tk.Frame(info_frame, bg=st.BG_MEDIUM)
            top_line.pack(fill="x")

            tk.Label(top_line, text=f"{svc.host}:{svc.port}",
                     font=st.FONT_MONO_MD, fg=st.TEXT_PRIMARY, bg=st.BG_MEDIUM
                     ).pack(side="left")
            tk.Label(top_line, text=f" {svc.service}", font=st.FONT_MONO,
                     fg=st.CYAN, bg=st.BG_MEDIUM).pack(side="left")
            tk.Label(top_line, text=f" v{svc.display_version}",
                     font=st.FONT_MONO_SM, fg=st.TEXT_SECONDARY, bg=st.BG_MEDIUM
                     ).pack(side="left")

            # CVE count badge
            if risk.cves:
                badge_text = f"{len(risk.cves)} CVE{'s' if len(risk.cves) > 1 else ''}"
                tk.Label(top_line, text=badge_text,
                         font=st.FONT_MONO_SM, fg=risk.severity_color,
                         bg=st.BG_MEDIUM).pack(side="right")

            if risk.is_exploitable:
                tk.Label(top_line, text="⚡ EXPLOIT", font=st.FONT_UI_BOLD,
                         fg=st.ORANGE, bg=st.BG_MEDIUM).pack(side="right", padx=8)

            # CVSS bar
            bar_frame = tk.Frame(info_frame, bg=st.BG_MEDIUM)
            bar_frame.pack(fill="x", pady=(3, 0))

            tk.Label(bar_frame, text=f"CVSS {risk.max_cvss:.1f}",
                     font=st.FONT_MONO_SM, fg=st.TEXT_MUTED, bg=st.BG_MEDIUM,
                     width=9).pack(side="left")

            SeverityBar(bar_frame, risk.max_cvss, width=200).pack(side="left", padx=4)

            tk.Label(bar_frame, text=risk.severity, font=st.FONT_MONO_SM,
                     fg=risk.severity_color, bg=st.BG_MEDIUM).pack(side="left")

    # ══════════════════════════════════════════════════ CVE Tab ═══════════

    def _on_tree_select(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        risk = self._tree_data.get(sel[0])
        if risk:
            self._selected_risk = risk
            self._show_cve_details(risk)

    def _on_tree_double_click(self, event):
        self._notebook.select(2)   # Go to CVE tab

    def _show_cve_details(self, risk: ServiceRisk):
        svc = risk.service
        self._cve_header_var.set(
            f"  {svc.host}:{svc.port}/{svc.protocol}  |  "
            f"{svc.service}  {svc.display_version}  |  "
            f"OS: {risk.service.host}"
        )

        # Clear existing CVE tree
        for iid in self._cve_tree.get_children():
            self._cve_tree.delete(iid)

        for cve in sorted(risk.cves, key=lambda c: c.cvss, reverse=True):
            exploit_icon = "⚡ Yes" if cve.has_exploit else "No"
            tag = cve.severity if cve.severity in ("CRITICAL","HIGH","MEDIUM","LOW") else ""
            if cve.has_exploit:
                tag = "EXPLOIT"

            self._cve_tree.insert("", "end", values=(
                cve.cve_id,
                f"{cve.cvss:.1f}",
                cve.severity,
                cve.published,
                exploit_icon,
                cve.description[:120] + "…" if len(cve.description) > 120 else cve.description,
            ), tags=(tag,))

        self._notebook.select(2)

    def _on_cve_select(self, event):
        sel = self._cve_tree.selection()
        if not sel:
            return
        vals   = self._cve_tree.item(sel[0], "values")
        cve_id = vals[0] if vals else ""

        if not self._selected_risk:
            return

        cve_obj = next((c for c in self._selected_risk.cves if c.cve_id == cve_id), None)
        if not cve_obj:
            return

        svc    = self._selected_risk.service
        detail = (
            f"CVE: {cve_obj.cve_id}\n"
            f"CVSS v3: {cve_obj.cvss_v3:.1f}    CVSS v2: {cve_obj.cvss_v2:.1f}\n"
            f"Severity: {cve_obj.severity}\n"
            f"Published: {cve_obj.published}\n"
            f"Exploit Available: {'Yes ⚡' if cve_obj.has_exploit else 'No'}\n"
        )
        if cve_obj.exploit_db_id:
            detail += f"ExploitDB ID: {cve_obj.exploit_db_id}\n"
            detail += f"ExploitDB URL: {cve_obj.exploitdb_url}\n"
        detail += f"NVD URL: {cve_obj.nvd_url}\n\n"
        detail += f"Service: {svc.service} on {svc.host}:{svc.port}\n"
        detail += f"Version: {svc.display_version}\n\n"
        detail += f"Description:\n{cve_obj.description}\n\n"
        if cve_obj.references:
            detail += "References:\n"
            for ref in cve_obj.references:
                detail += f"  • {ref}\n"

        self._cve_detail.configure(state="normal")
        self._cve_detail.delete("1.0", "end")
        self._cve_detail.insert("1.0", detail)
        self._cve_detail.configure(state="disabled")

    # ══════════════════════════════════════════════════ Remediation ═══════

    def _update_remediation_list(self):
        options = []
        for risk in self._service_risks:
            svc = risk.service
            key = f"{svc.host}:{svc.port}"
            if key not in self._shutdown_log and risk.cves:
                label = f"{svc.host}:{svc.port}  {svc.service}  {svc.display_version}  [CVSS {risk.max_cvss:.1f}]"
                options.append(label)
        self._rem_combo["values"] = options
        if options and not self._rem_svc_var.get():
            self._rem_combo.current(0)

        # Update disabled list
        if self._shutdown_log:
            items = []
            for key, info in self._shutdown_log.items():
                items.append(
                    f"{info.get('service','?')} on {key} "
                    f"[CVE: {info.get('cve','?')}]"
                )
            self._disabled_var.set(" | ".join(items))
        else:
            self._disabled_var.set("None")

    def _on_rem_select(self, event):
        pass

    def _get_selected_risk_for_remediation(self) -> Optional[ServiceRisk]:
        selected = self._rem_svc_var.get()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a service first.")
            return None
        for risk in self._service_risks:
            svc   = risk.service
            label = f"{svc.host}:{svc.port}  {svc.service}  {svc.display_version}  [CVSS {risk.max_cvss:.1f}]"
            if label == selected:
                return risk
        return None

    def _do_upgrade(self):
        risk = self._get_selected_risk_for_remediation()
        if not risk:
            return
        svc = risk.service

        top_cve = risk.top_cve
        cve_str = top_cve.cve_id if top_cve else "N/A"

        confirm = messagebox.askyesno(
            "Confirm Upgrade",
            f"Upgrade {svc.service} ({svc.display_version}) on {svc.host}?\n\n"
            f"CVE: {cve_str}   CVSS: {risk.max_cvss:.1f}\n\n"
            f"This will remove the old version and install the latest patched version.\n"
            f"Proceed?",
        )
        if not confirm:
            return

        self._rem_write(f"\n[*] Upgrading {svc.service} on {svc.host}:{svc.port} ...\n")

        def run():
            result = self._remediation.upgrade_service(
                host=svc.host,
                service_name=svc.service,
                product=svc.product,
                on_output=lambda msg: self.root.after(0, self._rem_write, msg + "\n"),
            )
            self.root.after(0, self._rem_write,
                f"\n{'='*50}\n{result.message}\n{'='*50}\n")
            if result.details:
                self.root.after(0, self._rem_write, result.details + "\n")
            if result.success:
                self.root.after(0, messagebox.showinfo, "Upgrade Complete", result.message)
            else:
                self.root.after(0, messagebox.showwarning, "Upgrade Result", result.message)

        threading.Thread(target=run, daemon=True).start()

    def _do_shutdown(self):
        risk = self._get_selected_risk_for_remediation()
        if not risk:
            return
        svc = risk.service
        key = f"{svc.host}:{svc.port}"

        top_cve = risk.top_cve
        cve_str = top_cve.cve_id if top_cve else "N/A"

        confirm = messagebox.askyesno(
            "Confirm Shutdown",
            f"Stop and disable {svc.service} on {svc.host}:{svc.port}?\n\n"
            f"CVE: {cve_str}\n\n"
            f"The service will be stopped and disabled from auto-start.\n"
            f"It will NOT appear in future scans until re-enabled.\n\n"
            f"Proceed?",
        )
        if not confirm:
            return

        self._rem_write(f"\n[*] Stopping {svc.service} on {svc.host} ...\n")

        def run():
            result = self._remediation.shutdown_service(
                host=svc.host,
                service_name=svc.service,
                product=svc.product,
                on_output=lambda msg: self.root.after(0, self._rem_write, msg + "\n"),
            )
            self.root.after(0, self._rem_write,
                f"\n{'='*50}\n{result.message}\n{'='*50}\n")
            if result.success:
                # Record in shutdown log
                self._shutdown_log[key] = {
                    "service": svc.service,
                    "host":    svc.host,
                    "port":    svc.port,
                    "product": svc.product,
                    "version": svc.display_version,
                    "cve":     cve_str,
                }
                self.root.after(0, self._apply_filter)
                self.root.after(0, self._update_remediation_list)
                self.root.after(0, messagebox.showinfo,
                    "Service Stopped",
                    f"⚠️ {svc.service} is now disabled.\n"
                    f"CVE: {cve_str}\n\n"
                    f"It will not appear in future scans.\n"
                    f"You can re-enable it from the Remediation tab.",
                )
            else:
                self.root.after(0, messagebox.showwarning, "Shutdown Result", result.message + "\n\n" + result.details)

        threading.Thread(target=run, daemon=True).start()

    def _do_restart(self):
        if not self._shutdown_log:
            messagebox.showinfo("No Disabled Services", "No services are currently disabled.")
            return

        items = list(self._shutdown_log.items())
        if len(items) == 1:
            key, info = items[0]
            choice_key = key
        else:
            # Build a selection dialog for multiple disabled services
            names = [f"{info['service']} on {key}" for key, info in items]
            sel   = self._simple_select_dialog("Re-enable Service", names)
            if sel is None:
                return
            choice_key = items[sel][0]

        info = self._shutdown_log[choice_key]
        confirm = messagebox.askyesno(
            "Re-enable Service",
            f"Re-enable {info['service']} on {info['host']}:{info['port']}?\n"
            f"(CVE: {info['cve']} — vulnerability still present!)"
        )
        if not confirm:
            return

        def run():
            result = self._remediation.restart_service(
                host=info["host"],
                service_name=info["service"],
                on_output=lambda msg: self.root.after(0, self._rem_write, msg + "\n"),
            )
            if result.success:
                del self._shutdown_log[choice_key]
            self.root.after(0, self._rem_write, result.message + "\n")
            self.root.after(0, self._update_remediation_list)
            self.root.after(0, self._apply_filter)
            self.root.after(0, messagebox.showinfo, "Result", result.message)

        threading.Thread(target=run, daemon=True).start()

    def _simple_select_dialog(self, title: str, options: list) -> Optional[int]:
        """Show a simple selection dialog, return index or None."""
        result = [None]
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=st.BG_DARK)
        win.geometry("400x300")
        win.grab_set()

        tk.Label(win, text="Select a service:", font=st.FONT_UI_BOLD,
                 fg=st.TEXT_PRIMARY, bg=st.BG_DARK).pack(pady=10)

        lb = tk.Listbox(win, font=st.FONT_MONO, bg=st.BG_MEDIUM, fg=st.TEXT_PRIMARY,
                        selectbackground=st.BLUE, height=8)
        lb.pack(fill="both", expand=True, padx=10, pady=4)
        for opt in options:
            lb.insert("end", opt)

        def confirm():
            sel = lb.curselection()
            if sel:
                result[0] = sel[0]
            win.destroy()

        DarkButton(win, "OK", confirm, color=st.GREEN).pack(pady=8)
        win.wait_window()
        return result[0]

    # ══════════════════════════════════════════════════ Export ═════════════

    def _export(self, fmt: str):
        if not self._service_risks:
            messagebox.showwarning("No Data", "Run a scan first.")
            return

        ext_map = {"json": ".json", "html": ".html", "csv": ".csv"}
        ext  = ext_map.get(fmt, ".txt")
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}"), ("All files", "*.*")],
            initialfile=f"nullbyte_report_{datetime.now():%Y%m%d_%H%M%S}{ext}",
        )
        if not path:
            return

        try:
            if fmt == "json":
                self._export_json(path)
            elif fmt == "html":
                self._export_html(path)
            elif fmt == "csv":
                self._export_csv(path)
            messagebox.showinfo("Export Complete", f"Report saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def _export_json(self, path: str):
        data = []
        for risk in self._service_risks:
            svc = risk.service
            data.append({
                "host":         svc.host,
                "port":         svc.port,
                "protocol":     svc.protocol,
                "service":      svc.service,
                "product":      svc.product,
                "version":      svc.version,
                "severity":     risk.severity,
                "cvss":         risk.max_cvss,
                "is_exploitable": risk.is_exploitable,
                "exploit_count": risk.exploit_count,
                "cves": [
                    {
                        "id":       c.cve_id,
                        "cvss":     c.cvss,
                        "severity": c.severity,
                        "published":c.published,
                        "has_exploit": c.has_exploit,
                        "exploit_db_id": c.exploit_db_id,
                        "nvd_url":  c.nvd_url,
                        "description": c.description,
                    }
                    for c in risk.cves
                ],
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"generated": datetime.now().isoformat(), "results": data},
                      f, indent=2, ensure_ascii=False)

    def _export_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Host","Port","Proto","Service","Version",
                             "Severity","CVSS","Exploitable","CVE IDs","Top CVE URL"])
            for risk in self._service_risks:
                svc = risk.service
                writer.writerow([
                    svc.host, svc.port, svc.protocol, svc.service,
                    svc.display_version, risk.severity, risk.max_cvss,
                    risk.is_exploitable, risk.cve_ids,
                    risk.top_cve.nvd_url if risk.top_cve else "",
                ])

    def _export_html(self, path: str):
        sev_colors = {
            "CRITICAL": "#ff4444", "HIGH": "#ff8800",
            "MEDIUM": "#f0c030", "LOW": "#3fb950", "NONE": "#484f58",
        }
        rows_html = ""
        for risk in self._service_risks:
            svc   = risk.service
            color = sev_colors.get(risk.severity, "#888")
            cve_links = " ".join(
                f'<a href="{c.nvd_url}" style="color:{color}">{c.cve_id}</a>'
                for c in risk.cves[:5]
            )
            exploit_badge = (
                '<span style="color:#f0883e;font-weight:bold">⚡ YES</span>'
                if risk.is_exploitable else "No"
            )
            rows_html += f"""
            <tr>
              <td>{svc.host}</td>
              <td>{svc.port}/{svc.protocol}</td>
              <td>{svc.service}</td>
              <td>{svc.display_version}</td>
              <td style="color:{color};font-weight:bold">{risk.severity}</td>
              <td>{risk.max_cvss:.1f}</td>
              <td>{exploit_badge}</td>
              <td style="font-size:12px">{cve_links}</td>
            </tr>
            """
        summary = score_summary(self._service_risks)
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NullByte Scan Report</title>
<style>
  body {{ font-family: Consolas, monospace; background: #0d1117; color: #e6edf3; margin: 0; padding: 20px; }}
  h1   {{ color: #ff2222; text-align: center; }}
  .meta {{ text-align:center; color:#8b949e; margin-bottom:20px; }}
  .summary {{ display:flex; gap:16px; margin-bottom:24px; justify-content:center; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 24px; text-align:center; }}
  .card .num {{ font-size:32px; font-weight:bold; }}
  .card .lbl {{ font-size:11px; color:#8b949e; }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; }}
  th    {{ background:#21262d; color:#8b949e; padding:10px; text-align:left; }}
  td    {{ padding:8px 10px; border-bottom:1px solid #21262d; font-size:13px; }}
  tr:hover {{ background:#1c2128; }}
  a {{ text-decoration:none; }}
  .badge {{ color:#ff2222; font-weight:bold; text-align:right; margin-top:30px; }}
</style>
</head>
<body>
<h1>⬡ NullByte Penetration Test Report</h1>
<div class="meta">Generated: {datetime.now():%Y-%m-%d %H:%M:%S}</div>
<div class="summary">
  <div class="card"><div class="num" style="color:#39c5cf">{summary['total']}</div><div class="lbl">TOTAL</div></div>
  <div class="card"><div class="num" style="color:#ff4444">{summary['critical']}</div><div class="lbl">CRITICAL</div></div>
  <div class="card"><div class="num" style="color:#ff8800">{summary['high']}</div><div class="lbl">HIGH</div></div>
  <div class="card"><div class="num" style="color:#f0c030">{summary['medium']}</div><div class="lbl">MEDIUM</div></div>
  <div class="card"><div class="num" style="color:#bc8cff">{summary['exploitable']}</div><div class="lbl">EXPLOITABLE</div></div>
</div>
<table>
  <thead>
    <tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Severity</th><th>CVSS</th><th>Exploit</th><th>CVEs</th></tr>
  </thead>
  <tbody>
    {rows_html}
  </tbody>
</table>
<div class="badge">● NullByte Team</div>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    # ══════════════════════════════════════════════════ Helpers ═══════════

    def _update_stats(self):
        hosts   = len(set(r.service.host for r in self._service_risks))
        ports   = len(self._service_risks)
        vulns   = len([r for r in self._service_risks if r.cves])
        crits   = len([r for r in self._service_risks if r.severity == "CRITICAL"])
        expls   = len([r for r in self._service_risks if r.is_exploitable])

        updates = {"hosts": hosts, "ports": ports, "vulns": vulns,
                   "critical": crits, "exploits": expls}
        for key, val in updates.items():
            try:
                self._stats_labels[key].configure(text=str(val))
            except (KeyError, tk.TclError):
                pass

    def _update_status(self, msg: str):
        try:
            self._status_var.set(msg)
        except tk.TclError:
            pass

    def _log(self, msg: str, tag: str = ""):
        try:
            self._log_text.configure(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self._log_text.insert("end", f"[{ts}] {msg}\n", tag or "")
            self._log_text.see("end")
            self._log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def _clear_log(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")

    def _rem_write(self, msg: str):
        try:
            self._rem_output.configure(state="normal")
            self._rem_output.insert("end", msg)
            self._rem_output.see("end")
            self._rem_output.configure(state="disabled")
        except tk.TclError:
            pass

    def _on_close(self):
        if self._scanner.is_running():
            if not messagebox.askyesno("Exit", "A scan is running. Exit anyway?"):
                return
            self._scanner.stop()
        self.root.destroy()
