#!/usr/bin/env python3
"""
NullByte Penetration Testing Tool
Entry point — shows splash screen then launches the main application.

Usage:
    python main.py

Requirements:
    pip install -r requirements.txt
    Nmap must be installed on the system.
"""

import sys
import os
import tkinter as tk

# Ensure project root is in path regardless of how the script is launched
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def check_dependencies() -> bool:
    """Verify required libraries are installed."""
    missing = []

    try:
        import nmap
    except ImportError:
        missing.append("python-nmap  →  pip install python-nmap")

    try:
        import requests
    except ImportError:
        missing.append("requests     →  pip install requests")

    if missing:
        print("=" * 60)
        print("NullByte — Missing dependencies detected:")
        for m in missing:
            print(f"  ✗  {m}")
        print("\nRun:  pip install -r requirements.txt")
        print("=" * 60)
        return False

    # Check Nmap binary
    import shutil
    if not shutil.which("nmap"):
        print("=" * 60)
        print("NullByte — Nmap not found on this system.")
        print("  Windows : Download from https://nmap.org/download.html")
        print("  Linux   : sudo apt install nmap")
        print("  macOS   : brew install nmap")
        print("=" * 60)
        return False

    return True


def main():
    if not check_dependencies():
        input("\nPress Enter to exit...")
        sys.exit(1)

    # ── Splash Screen ────────────────────────────────────────────────────────
    from ui.splash import SplashScreen

    splash_done = [False]

    def on_splash_close():
        splash_done[0] = True

    splash = SplashScreen(on_close_callback=on_splash_close)
    splash.run()   # blocks until splash closes

    # ── Main Application ─────────────────────────────────────────────────────
    from ui.app import NullByteApp

    root = tk.Tk()
    app  = NullByteApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
