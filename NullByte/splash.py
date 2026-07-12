"""
NullByte Tool - Splash / Welcome Screen
Animated "Welcome Hacker, Are You Ready For Attack?" intro screen.
"""

import tkinter as tk
import time
import threading
import ui.styles as st

_WELCOME_TEXT    = "Welcome Hacker,"
_SUBTITLE_TEXT   = "Are You Ready For Attack?"
_BADGE_TEXT      = "● NullByte Team"
_AUTO_CLOSE_MS   = 4500    # auto-close after 4.5 s


class SplashScreen:
    """
    Full-screen intro window with:
    - Typing animation for the welcome message
    - Glowing red NullByte badge
    - Click-anywhere or wait to dismiss
    """

    def __init__(self, on_close_callback=None):
        self._callback = on_close_callback
        self._root = tk.Tk()
        self._root.title("NullByte")
        self._root.configure(bg=st.BG_ROOT)
        self._root.resizable(False, False)
        self._closed = False

        # ── Size / position ──────────────────────────────────────────────────
        w, h = 900, 520
        sw = self._root.winfo_screenwidth()
        sh = self._root.winfo_screenheight()
        x  = (sw - w) // 2
        y  = (sh - h) // 2
        self._root.geometry(f"{w}x{h}+{x}+{y}")
        self._root.overrideredirect(True)   # borderless

        self._build_ui(w, h)
        self._root.after(200, self._start_animation)
        self._root.after(_AUTO_CLOSE_MS, self._close)
        self._root.bind("<Button-1>", lambda e: self._close())
        self._root.bind("<Key>",      lambda e: self._close())

    def run(self):
        self._root.mainloop()

    # ─────────────────────────────────────────────────────── UI Build ──

    def _build_ui(self, w: int, h: int):
        canvas = tk.Canvas(
            self._root, width=w, height=h,
            bg=st.BG_ROOT, highlightthickness=0
        )
        canvas.pack(fill="both", expand=True)
        self._canvas = canvas

        # Border glow (simulated with nested rectangles)
        canvas.create_rectangle(0, 0, w, h, outline=st.RED_GLOW, width=2)
        canvas.create_rectangle(3, 3, w-3, h-3, outline="#6b0011", width=1)

        # Top decoration line
        canvas.create_line(40, 60, w-40, 60, fill=st.RED_GLOW, width=1)

        # ── Top Label ─────────────────────────────────────────────────────────
        canvas.create_text(
            w // 2, 35,
            text="[ NULLBYTE PENETRATION TESTER ]",
            font=("Consolas", 11),
            fill=st.TEXT_MUTED,
        )

        # ── Main animated text ────────────────────────────────────────────────
        self._main_var = tk.StringVar(value="")
        self._sub_var  = tk.StringVar(value="")

        # Main text label via canvas window
        self._main_lbl = tk.Label(
            canvas,
            textvariable=self._main_var,
            font=("Consolas", 30, "bold"),
            fg=st.GREEN_BRIGHT,
            bg=st.BG_ROOT,
        )
        canvas.create_window(w // 2, h // 2 - 55, window=self._main_lbl)

        self._sub_lbl = tk.Label(
            canvas,
            textvariable=self._sub_var,
            font=("Consolas", 22),
            fg=st.TEXT_PRIMARY,
            bg=st.BG_ROOT,
        )
        canvas.create_window(w // 2, h // 2 + 15, window=self._sub_lbl)

        # Cursor blink element
        self._cursor_id = canvas.create_text(
            w // 2, h // 2 + 70,
            text="█",
            font=("Consolas", 14),
            fill=st.GREEN_BRIGHT,
        )

        # Bottom line
        canvas.create_line(40, h-60, w-40, h-60, fill=st.RED_GLOW, width=1)

        # Click hint
        canvas.create_text(
            w // 2, h - 38,
            text="[ Press any key or click to enter ]",
            font=("Consolas", 10),
            fill=st.TEXT_MUTED,
        )

        # ── NullByte Badge (bottom-right, red glowing) ────────────────────────
        badge_frame = tk.Frame(canvas, bg="#1a0000", bd=0)
        badge_lbl   = tk.Label(
            badge_frame,
            text=_BADGE_TEXT,
            font=("Consolas", 10, "bold"),
            fg=st.RED_GLOW,
            bg="#1a0000",
            padx=10, pady=4,
        )
        badge_lbl.pack()
        canvas.create_window(w - 90, h - 30, window=badge_frame)

        # Animate badge glow
        self._badge_lbl = badge_lbl
        self._glow_state = False
        self._animate_badge()

    # ─────────────────────────────────────────────────────── Animation ──

    def _start_animation(self):
        """Start typing animations sequentially."""
        threading.Thread(target=self._type_text, daemon=True).start()

    def _type_text(self):
        # Type main text
        for i in range(len(_WELCOME_TEXT) + 1):
            if self._closed:
                return
            self._main_var.set(_WELCOME_TEXT[:i])
            time.sleep(0.05)

        time.sleep(0.25)

        # Type subtitle
        for i in range(len(_SUBTITLE_TEXT) + 1):
            if self._closed:
                return
            self._sub_var.set(_SUBTITLE_TEXT[:i])
            time.sleep(0.045)

    def _animate_badge(self):
        """Toggle badge between bright red and dark red for glow effect."""
        if self._closed:
            return
        self._glow_state = not self._glow_state
        color = st.RED_GLOW if self._glow_state else "#990011"
        try:
            self._badge_lbl.configure(fg=color)
        except tk.TclError:
            return
        self._root.after(600, self._animate_badge)

    # ─────────────────────────────────────────────────────── Close ──

    def _close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._root.destroy()
        except tk.TclError:
            pass
        if self._callback:
            self._callback()
