"""
NullByte Tool - Design System / Theme
Dark cyberpunk aesthetic with calm professional tones
"""

# ─── Background Palette ───────────────────────────────────────────────────────
BG_ROOT       = "#08090f"   # Deepest background
BG_DARK       = "#0d1117"   # Main background (GitHub Dark)
BG_MEDIUM     = "#161b22"   # Card / panel background
BG_LIGHT      = "#1c2128"   # Hover / selected state
BG_BORDER     = "#21262d"   # Subtle border

# ─── Text Palette ─────────────────────────────────────────────────────────────
TEXT_PRIMARY   = "#e6edf3"  # Main text
TEXT_SECONDARY = "#8b949e"  # Subdued text
TEXT_MUTED     = "#484f58"  # Very muted / placeholders
TEXT_ACCENT    = "#58a6ff"  # Highlighted text / links

# ─── Accent Colors ────────────────────────────────────────────────────────────
GREEN         = "#3fb950"   # Success / safe
GREEN_BRIGHT  = "#00ff88"   # Neon green highlight
CYAN          = "#39c5cf"   # Info / scanning
BLUE          = "#58a6ff"   # Links / primary action
PURPLE        = "#bc8cff"   # Special info
YELLOW        = "#d29922"   # Warning
ORANGE        = "#f0883e"   # High severity
RED           = "#f85149"   # Error / critical
RED_BRIGHT    = "#ff2222"   # NullByte badge / critical alert
RED_GLOW      = "#ff0033"   # Glowing red for badge

# ─── Severity Colors ──────────────────────────────────────────────────────────
SEV_CRITICAL  = "#ff4444"
SEV_HIGH      = "#ff8800"
SEV_MEDIUM    = "#f0c030"
SEV_LOW       = "#3fb950"
SEV_INFO      = "#58a6ff"
SEV_NONE      = "#484f58"

SEV_CRITICAL_BG = "#2d1010"
SEV_HIGH_BG     = "#2d1a08"
SEV_MEDIUM_BG   = "#2d2408"
SEV_LOW_BG      = "#0d2510"
SEV_INFO_BG     = "#0d1e30"

def severity_color(cvss: float) -> str:
    """Return color for a given CVSS score."""
    if cvss >= 9.0:   return SEV_CRITICAL
    if cvss >= 7.0:   return SEV_HIGH
    if cvss >= 4.0:   return SEV_MEDIUM
    if cvss >= 0.1:   return SEV_LOW
    return SEV_NONE

def severity_bg(cvss: float) -> str:
    if cvss >= 9.0:   return SEV_CRITICAL_BG
    if cvss >= 7.0:   return SEV_HIGH_BG
    if cvss >= 4.0:   return SEV_MEDIUM_BG
    if cvss >= 0.1:   return SEV_LOW_BG
    return BG_MEDIUM

def severity_label(cvss: float) -> str:
    if cvss >= 9.0:   return "CRITICAL"
    if cvss >= 7.0:   return "HIGH"
    if cvss >= 4.0:   return "MEDIUM"
    if cvss >= 0.1:   return "LOW"
    return "NONE"

# ─── Typography ───────────────────────────────────────────────────────────────
FONT_MONO        = ("Consolas", 9)
FONT_MONO_SM     = ("Consolas", 8)
FONT_MONO_MD     = ("Consolas", 10)
FONT_MONO_LG     = ("Consolas", 12)
FONT_MONO_TITLE  = ("Consolas", 15, "bold")
FONT_MONO_HUGE   = ("Consolas", 22, "bold")

FONT_UI          = ("Segoe UI", 9)
FONT_UI_SM       = ("Segoe UI", 8)
FONT_UI_MD       = ("Segoe UI", 10)
FONT_UI_BOLD     = ("Segoe UI", 9, "bold")
FONT_UI_TITLE    = ("Segoe UI", 12, "bold")
FONT_UI_LG       = ("Segoe UI", 14, "bold")
FONT_UI_HUGE     = ("Segoe UI", 20, "bold")

# ─── Dimensions ───────────────────────────────────────────────────────────────
CORNER_RADIUS    = 8
PAD_SM           = 4
PAD_MD           = 8
PAD_LG           = 16
PAD_XL           = 24
