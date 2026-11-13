"""MGU iDrive SSH Tool - a small Tkinter front-end over ssh_enable.py.

Three actions - Flash + Enable, Enable, Disable - plus VIN auto-detection over
ENET. It drives the exact same code as the command line (it runs
ssh_enable.main on a background thread and streams the log into the window).
The root SSH key is written out (all formats) + a connect.txt during enroll;
their location is printed in the log. Packages into a Windows .exe with
PyInstaller (build_exe.bat).
"""

import os
import queue
import sys
import threading

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

if getattr(sys, "frozen", False):
    HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


class _NullWriter:
    """Stand-in for sys.stdout/err. In a windowed (--noconsole) PyInstaller exe
    sys.stdout and sys.stderr are None, so any print() before the GUI redirect
    would raise and the exe would vanish on launch. Keep writes harmless."""

    def write(self, *_):
        pass

    def flush(self):
        pass


if sys.stdout is None:
    sys.stdout = _NullWriter()
if sys.stderr is None:
    sys.stderr = _NullWriter()

import ssh_enable
from i18n import Translator
from mgu7 import discovery
from mgu7.flash import ID7, ID8_BDC3, ID8_BCP

ARCHES = (ID7, ID8_BDC3, ID8_BCP)
# The flash contract MUST match the head unit. Flashing an ID8 with the ID7
# image (or vice-versa) partially writes the wrong regions and leaves the unit
# stuck in programming mode (issue #47). The software baseline alone (030 vs
# 036) is not a reliable enough discriminator to auto-pick, so we make the user
# choose their exact variant - there is no silent default.
VARIANT_PROMPT = "— select your car —"
VARIANT_CHOICES = (
    (ID7, "ID7 — BDC2 / BDC3  (software 030.xxx)"),
    (ID8_BDC3, "ID8 — BDC3  (software 036.xxx)"),
    (ID8_BCP, "ID8 — BCP  (software 036.xxx)"),
)
_VARIANT_BY_LABEL = {label: code for code, label in VARIANT_CHOICES}

# ---------------------------------------------------------------------------
# Visual world: "diagnostic cockpit". A laptop jacked into the car's ENET port,
# often in a garage or driveway - dark cuts glare and lets the live log read as
# the darkest inset of one coherent instrument surface. The signature is a drawn
# BMW-motorsport tricolour mark + stripe, used once; colour otherwise does one
# job each (blue = go, amber = caution/required, red = destructive, green = ok).
# ---------------------------------------------------------------------------
BG         = "#0e1319"   # app field
PANEL      = "#161d26"   # raised card
PANEL_HI   = "#202935"   # control fill / hover base
FIELD      = "#0a0e13"   # inset input well
LINE       = "#2a3542"   # hairline border
LINE_SOFT  = "#1d2530"   # inner divider
TEXT       = "#e8eef6"   # primary
MUTED      = "#9aa9bd"   # secondary (blue-tinted, ~7:1 on BG)
DIM        = "#6f7f93"   # tertiary
HEADER_BG  = "#0a0d12"   # chrome (header + status rail)
ACCENT     = "#3b82f6"   # primary action
ACCENT_HI  = "#2f6fe0"
ACCENT_LT  = "#86b4ff"   # accent text / caret
GREEN      = "#35c281"
AMBER      = "#e0a93a"
RED        = "#e2554f"
CONSOLE_BG = "#070a0e"
CONSOLE_FG = "#c8d4e4"
DISABLED   = "#38424f"
DISABLED_FG = "#79838f"
# BMW Motorsport tricolour - the one branded flourish, drawn, used once.
M_LBLUE    = "#4fb3e8"
M_DBLUE    = "#315fd4"
M_RED      = "#e8323f"

# Tinted-ghost secondary buttons: a dark wash of the button's own hue so the
# single filled hero stays unmistakably primary.
ENABLE_BG, ENABLE_HI, ENABLE_FG = "#13271c", "#1a3528", "#55d699"
FIX_BG, FIX_HI, FIX_FG          = "#2a2210", "#372d16", "#edbb5f"
DISABLE_BG, DISABLE_HI, DISABLE_FG = "#2a1716", "#381e1d", "#f29a94"

UI, UI_SEMI, MONO = "Segoe UI", "Segoe UI Semibold", "Consolas"
OUTER = 22


class _QueueWriter:
    """File-like object funnelling writes to a thread-safe queue."""

    def __init__(self, q):
        self.q = q
        self.pending = ""

    def write(self, text):
        if text:
            self.pending += text
            while "\n" in self.pending:
                line, self.pending = self.pending.split("\n", 1)
                self.q.put(line + "\n")
        return len(text)

    def flush(self):
        if self.pending:
            self.q.put(self.pending)
            self.pending = ""


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.worker = None
        self.i18n = Translator()
        self._labels = []
        self._history = []
        self._is_busy = False

        root.title("MGU iDrive SSH Tool")
        root.configure(bg=BG)
        root.minsize(860, 660)

        self.vin = tk.StringVar()
        self.gateway = tk.StringVar(value="auto")
        self.mgu_ip = tk.StringVar()
        self.arch = tk.StringVar(value="")  # empty until the user picks a variant
        self.variant_label = tk.StringVar(value=VARIANT_PROMPT)
        self.disable_debug = tk.BooleanVar(value=True)
        self.unique_key = tk.BooleanVar(value=False)

        self._style()
        self._build()
        self.root.after(100, self._drain)

    # --- styling ----------------------------------------------------------

    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass

        # Frames + labels, keyed by the surface they sit on (body vs card).
        st.configure("TFrame", background=BG)
        st.configure("Card.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=TEXT, font=(UI, 10))
        st.configure("Strong.TLabel", background=BG, foreground=TEXT, font=(UI, 10, "bold"))
        st.configure("Hint.TLabel", background=BG, foreground=MUTED, font=(UI, 9))
        st.configure("CardLabel.TLabel", background=PANEL, foreground=TEXT, font=(UI, 10))
        st.configure("CardStrong.TLabel", background=PANEL, foreground=TEXT, font=(UI, 11, "bold"))
        st.configure("CardHint.TLabel", background=PANEL, foreground=MUTED, font=(UI, 9))

        # Variant picker (ttk.OptionMenu -> TMenubutton).
        st.configure("TMenubutton", background=PANEL_HI, foreground=TEXT, font=(UI, 10, "bold"),
                     padding=(12, 8), relief="flat", borderwidth=0, arrowcolor=MUTED, focuscolor=PANEL_HI)
        st.map("TMenubutton", background=[("active", "#273340"), ("disabled", DISABLED)],
               foreground=[("disabled", DISABLED_FG)])

        # Language combobox.
        st.configure("TCombobox", fieldbackground=PANEL_HI, background=PANEL_HI, foreground=TEXT,
                     arrowcolor=MUTED, bordercolor=LINE, lightcolor=PANEL_HI, darkcolor=PANEL_HI,
                     selectbackground=PANEL_HI, selectforeground=TEXT, padding=(8, 5))
        st.map("TCombobox", fieldbackground=[("readonly", PANEL_HI)],
               foreground=[("readonly", TEXT)], arrowcolor=[("active", TEXT)])
        self.root.option_add("*TCombobox*Listbox.background", PANEL)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        self.root.option_add("*TCombobox*Listbox.font", (UI, 10))

        # Checkbuttons on the body surface.
        st.configure("TCheckbutton", background=BG, foreground=TEXT, font=(UI, 10), focuscolor=BG)
        try:
            st.configure("TCheckbutton", indicatorbackground=FIELD, indicatorforeground="#ffffff",
                         bordercolor=LINE, indicatorrelief="flat")
            st.map("TCheckbutton",
                   background=[("active", BG)],
                   indicatorbackground=[("selected", ACCENT), ("active", PANEL_HI)])
        except tk.TclError:
            pass

        def filled(name, bg, active, fg="#ffffff", font=(UI, 11, "bold"), pad=(16, 12)):
            st.configure(name, background=bg, foreground=fg, font=font,
                         padding=pad, borderwidth=0, relief="flat", focuscolor=bg)
            st.map(name, background=[("active", active), ("disabled", DISABLED)],
                   foreground=[("disabled", DISABLED_FG)])

        # Hero: the one button most people ever need - big and unmissable.
        filled("Hero.TButton", ACCENT, ACCENT_HI, font=(UI, 16, "bold"), pad=(16, 20))
        # Tinted-ghost secondaries, each washed with its own meaning's hue.
        filled("Enable.TButton", ENABLE_BG, ENABLE_HI, ENABLE_FG, font=(UI, 10, "bold"), pad=(10, 11))
        filled("Fix.TButton", FIX_BG, FIX_HI, FIX_FG, font=(UI, 10, "bold"), pad=(10, 11))
        filled("Disable.TButton", DISABLE_BG, DISABLE_HI, DISABLE_FG, font=(UI, 10, "bold"), pad=(10, 11))
        # Quiet utility buttons.
        filled("Detect.TButton", PANEL_HI, "#273340", ACCENT_LT, font=(UI, 9, "bold"), pad=(13, 8))
        filled("Ghost.TButton", PANEL_HI, "#273340", TEXT, font=(UI, 9), pad=(11, 6))

    # --- small drawn primitives -------------------------------------------

    def _tick(self, parent, color, bg):
        """A short colour tick that opens a section header."""
        t = tk.Frame(parent, bg=color, width=3, height=13)
        t.pack_propagate(False)
        return t

    def _section(self, parent, source, color, bg):
        """Uppercase section header: colour tick + translated label."""
        row = tk.Frame(parent, bg=bg)
        self._tick(row, color, bg).pack(side="left", padx=(0, 10))
        lbl = self._label(tk.Label, row, source, bg=bg, fg=MUTED, font=(UI, 9, "bold"))
        lbl.pack(side="left")
        return row

    def _entry(self, parent, var, width, bg=FIELD):
        return tk.Entry(parent, textvariable=var, width=width, font=(MONO, 11),
                        bg=bg, fg=TEXT, insertbackground=ACCENT_LT, relief="flat",
                        disabledbackground=bg, highlightthickness=1,
                        highlightbackground=LINE, highlightcolor=ACCENT)

    # --- layout -----------------------------------------------------------

    def _build(self):
        self._build_menu()

        # Header chrome + the single branded tricolour stripe beneath it.
        header = tk.Frame(self.root, bg=HEADER_BG)
        header.pack(fill="x")

        mark = tk.Canvas(header, width=38, height=24, bg=HEADER_BG, highlightthickness=0, bd=0)
        for x0, color in ((0, M_LBLUE), (12, M_DBLUE), (24, M_RED)):
            mark.create_polygon(x0, 24, x0 + 8, 24, x0 + 14, 0, x0 + 6, 0, fill=color, outline=color)
        mark.pack(side="left", padx=(18, 13), pady=16)

        wordmark = tk.Frame(header, bg=HEADER_BG)
        wordmark.pack(side="left", pady=12)
        self._label(tk.Label, wordmark, "MGU iDrive  SSH", bg=HEADER_BG, fg=TEXT,
                    font=(UI_SEMI, 16)).pack(anchor="w")
        self._label(tk.Label, wordmark, "BMW ID7 / ID8  •  root over ENET", bg=HEADER_BG,
                    fg=MUTED, font=(UI, 9)).pack(anchor="w")

        language_frame = tk.Frame(header, bg=HEADER_BG)
        language_frame.pack(side="right", padx=16, pady=12)
        self.language = tk.StringVar(value="English")
        self.language_box = ttk.Combobox(language_frame, textvariable=self.language,
            values=[data['name'] for data in self.i18n.catalogs.values()],
            state="readonly", width=14)
        self.language_box.pack(anchor="e")
        self.language_box.bind("<<ComboboxSelected>>", self._change_language)

        stripe = tk.Frame(self.root, bg=LINE)
        stripe.pack(fill="x")
        for color, w in ((M_LBLUE, 68), (M_DBLUE, 68), (M_RED, 68)):
            seg = tk.Frame(stripe, bg=color, width=w, height=3)
            seg.pack(side="left")
            seg.pack_propagate(False)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="x", padx=OUTER, pady=(18, 0))

        # One setup card: VIN, the required variant, and the optional
        # connection overrides, divided by hairlines.
        card = tk.Frame(body, bg=PANEL, highlightthickness=1,
                        highlightbackground=LINE, highlightcolor=LINE)
        card.pack(fill="x")
        inner = tk.Frame(card, bg=PANEL)
        inner.pack(fill="x", padx=18, pady=16)

        # VIN
        self._section(inner, "VIN", M_LBLUE, PANEL).pack(fill="x")
        vin_row = tk.Frame(inner, bg=PANEL)
        vin_row.pack(fill="x", pady=(9, 0))
        self._entry(vin_row, self.vin, 24).pack(side="left", ipady=4)
        self.detect_btn = self._label(ttk.Button, vin_row, "Detect VIN",
                                      style="Detect.TButton", command=self.detect_vin)
        self.detect_btn.pack(side="left", padx=12)
        self._label(ttk.Label, vin_row, "(auto-reads the VIN from the car)",
                    style="CardHint.TLabel").pack(side="left")

        tk.Frame(inner, bg=LINE_SOFT, height=1).pack(fill="x", pady=16)

        # Your car - REQUIRED. No default: flashing the wrong variant bricks the
        # unit into programming mode (issue #47), so the user must pick it.
        car_hdr = self._section(inner, "YOUR CAR (required before flashing)", AMBER, PANEL)
        car_hdr.pack(fill="x")
        self.car_led = tk.Canvas(car_hdr, width=12, height=12, bg=PANEL, highlightthickness=0)
        self.car_dot = self.car_led.create_oval(2, 2, 10, 10, fill=AMBER, outline=AMBER)
        self.car_led.pack(side="left", padx=(10, 0))
        car_row = tk.Frame(inner, bg=PANEL)
        car_row.pack(fill="x", pady=(9, 0))
        self.variant_mb = ttk.OptionMenu(car_row, self.variant_label, self.variant_label.get(),
                                         *[label for _, label in VARIANT_CHOICES],
                                         command=self._on_variant)
        self.variant_mb.configure(style="TMenubutton")
        self.variant_mb["menu"].configure(bg=PANEL, fg=TEXT, activebackground=ACCENT,
                                          activeforeground="#ffffff", borderwidth=0,
                                          activeborderwidth=0, relief="flat", font=(UI, 10))
        self.variant_mb.pack(side="left")
        self._label(ttk.Label, inner,
                    "Pick ID7 or ID8 to match your head unit. If you are not 100% sure, STOP and check - "
                    "flashing the wrong one can leave the unit stuck in programming mode.",
                    style="CardHint.TLabel", justify="left", wraplength=760).pack(anchor="w", pady=(9, 0))

        tk.Frame(inner, bg=LINE_SOFT, height=1).pack(fill="x", pady=16)

        # Connection overrides (optional, discovered automatically otherwise).
        self._section(inner, "CONNECTION (optional)", DIM, PANEL).pack(fill="x")
        conn = tk.Frame(inner, bg=PANEL)
        conn.pack(fill="x", pady=(9, 0))
        self._label(ttk.Label, conn, "Gateway", style="CardLabel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self._entry(conn, self.gateway, 16).grid(row=0, column=1, sticky="w", ipady=3)
        self._label(ttk.Label, conn, "MGU IP", style="CardLabel.TLabel").grid(row=0, column=2, sticky="w", padx=(22, 8))
        self._entry(conn, self.mgu_ip, 16).grid(row=0, column=3, sticky="w", ipady=3)

        # Primary one-click action - this is all most people ever need.
        hero = tk.Frame(body, bg=BG)
        hero.pack(fill="x", pady=(18, 0))
        self.btn_flash = self._label(ttk.Button, hero, "Flash + Enable", style="Hero.TButton", command=self.do_flash)
        self.btn_flash.pack(fill="x")
        self._label(ttk.Label, hero,
                  "Start here - this is all you need. It flashes the debug image and turns on root SSH in one step.\n"
                  "If the car connects afterwards but refuses the key, then use “Fix refusing SSH key” below.",
                  style="Hint.TLabel", justify="left", wraplength=1100).pack(anchor="w", pady=(8, 0))

        # Secondary actions (smaller), only needed in specific cases.
        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(14, 0))
        actions.columnconfigure((0, 1, 2), weight=1, uniform="a")
        self.btn_enable = self._label(ttk.Button, actions, "Enable", style="Enable.TButton", command=self.do_enable)
        self.btn_fix = self._label(ttk.Button, actions, "Fix refusing SSH key", style="Fix.TButton", command=self.do_fix_key)
        self.btn_disable = self._label(ttk.Button, actions, "Disable", style="Disable.TButton", command=self.do_disable)
        self.btn_enable.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.btn_fix.grid(row=0, column=1, sticky="ew", padx=8)
        self.btn_disable.grid(row=0, column=2, sticky="ew", padx=(8, 0))
        self._label(ttk.Label, actions,
                  "Enable: re-open SSH on an already-flashed unit (no flashing).      "
                  "Fix refusing SSH key: login refused after a good flash.      "
                  "Disable: undo persistence and stop SSH.",
                  style="Hint.TLabel", justify="left", wraplength=1100).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        opt = tk.Frame(body, bg=BG)
        opt.pack(fill="x", pady=(14, 0))
        self._label(ttk.Checkbutton, opt, "Turn debug mode off after enabling (clears the B7F8E5 DTC)",
                        variable=self.disable_debug).pack(anchor="w")
        self._label(ttk.Label, opt, "On = SSH stays up with debug off (recommended).  Off = SSH persistent but debug mode stays on.",
                  style="Hint.TLabel", wraplength=1100, justify="left").pack(anchor="w", padx=(24, 0))
        self._label(ttk.Checkbutton, opt, "Give this car its own unique SSH key  (advanced - NOT recommended)",
                        variable=self.unique_key).pack(anchor="w", pady=(10, 0))
        self._label(ttk.Label, opt, "Swaps the shared dev key for a per-car key. Can only be done ONCE - if you lose the key or reflash, you can't create a new identity. Leave off unless you know why you need it.",
                  style="Hint.TLabel", wraplength=1100, justify="left").pack(anchor="w", padx=(24, 0))

        self.action_buttons = [self.btn_flash, self.btn_enable, self.btn_disable, self.btn_fix]

        # log-console header: label + a button to open the saved session logs
        loghdr = tk.Frame(self.root, bg=BG)
        loghdr.pack(fill="x", padx=OUTER, pady=(18, 7))
        loghdr_left = tk.Frame(loghdr, bg=BG)
        loghdr_left.pack(side="left")
        self._tick(loghdr_left, ACCENT, BG).pack(side="left", padx=(0, 10))
        ttk.Label(loghdr_left, text="Session log (saved to data\\logs\\):", style="Hint.TLabel").pack(side="left")
        ttk.Button(loghdr, text="Open logs folder", style="Ghost.TButton", command=self.open_logs_folder).pack(side="right")

        # log console, inset inside a 1px hairline frame
        console = tk.Frame(self.root, bg=LINE)
        console.pack(fill="both", expand=True, padx=OUTER, pady=(0, 12))
        self.out = scrolledtext.ScrolledText(console, height=15, wrap="word", font=(MONO, 9),
                                             bg=CONSOLE_BG, fg=CONSOLE_FG, insertbackground=ACCENT_LT,
                                             relief="flat", borderwidth=0, padx=12, pady=10,
                                             selectbackground="#1d3350", selectforeground=TEXT)
        self.out.pack(fill="both", expand=True, padx=1, pady=1)
        self.out.configure(state="disabled")
        try:
            self.out.vbar.configure(bg=PANEL, troughcolor=CONSOLE_BG, activebackground=PANEL_HI,
                                    relief="flat", borderwidth=0, width=12, highlightthickness=0,
                                    elementborderwidth=0)
        except (AttributeError, tk.TclError):
            pass

        # status rail with a drawn state LED
        statusbar = tk.Frame(self.root, bg=HEADER_BG)
        statusbar.pack(fill="x")
        self.led = tk.Canvas(statusbar, width=14, height=14, bg=HEADER_BG, highlightthickness=0)
        self.led_dot = self.led.create_oval(3, 3, 11, 11, fill=GREEN, outline=GREEN)
        self.led.pack(side="left", padx=(16, 9), pady=7)
        self.status = self._label(tk.Label, statusbar, "Ready.", anchor="w", bg=HEADER_BG,
                               fg=MUTED, font=(UI, 9))
        self.status.pack(side="left", pady=7)

    # --- helpers ----------------------------------------------------------

    def _label(self, widget_type, parent, source, **kwargs):
        widget = widget_type(parent, text=self.i18n.t(source), **kwargs)
        self._labels.append((widget, source))
        return widget

    def _set_led(self, color):
        try:
            self.led.itemconfig(self.led_dot, fill=color, outline=color)
        except (AttributeError, tk.TclError):
            pass

    def _change_language(self, _event=None):
        tag = next(tag for tag, data in self.i18n.catalogs.items()
                   if data['name'] == self.language.get())
        self.i18n.select(tag)
        for widget, source in self._labels:
            widget.configure(text=self.i18n.t(source))
        self.status.configure(text=self.i18n.t("Working…" if self._is_busy else "Ready."))
        # Re-render from raw history; switching languages does not lose diagnostic data.
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        for text in self._history:
            self.out.insert("end", self.i18n.log(text))
        self.out.see("end")
        self.out.configure(state="disabled")

    def _append(self, text):
        self._history.append(text)
        self.out.configure(state="normal")
        self.out.insert("end", self.i18n.log(text))
        self.out.see("end")
        self.out.configure(state="disabled")

    def open_logs_folder(self):
        """Open the folder holding the saved session logs (creating it if the
        tool has not been run yet), so a log is easy to attach to an issue."""
        folder = os.path.join(HERE, "data", "logs")
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError:
            pass
        try:
            if sys.platform == "win32":
                os.startfile(folder)  # noqa: S606 - open in Explorer
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", folder])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:  # noqa: BLE001
            messagebox.showinfo("Logs folder", "Session logs are saved in:\n%s\n\n(%s)" % (folder, e))

    def _drain(self):
        try:
            while True:
                self._append(self.q.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _busy(self, on):
        self._is_busy = on
        state = "disabled" if on else "normal"
        for b in self.action_buttons:
            b.configure(state=state)
        self.detect_btn.configure(state=state)
        self._set_led(AMBER if on else GREEN)
        self.status.configure(text=self.i18n.t("Working…" if on else "Ready."))

    def _build_menu(self):
        """A small 'Recovery' menu for the programming-mode helpers - kept out of
        the main one-click flow since they are only for getting a unit unstuck."""
        menubar = tk.Menu(self.root, bg=PANEL, fg=TEXT, activebackground=ACCENT,
                          activeforeground="#ffffff", borderwidth=0)
        recovery = tk.Menu(menubar, tearoff=0, bg=PANEL, fg=TEXT, activebackground=ACCENT,
                           activeforeground="#ffffff", borderwidth=0)
        recovery.add_command(label="Enter programming mode…", command=self.do_enter_prog)
        recovery.add_command(label="Exit programming mode (recovery)…", command=self.do_exit_prog)
        menubar.add_cascade(label="Recovery", menu=recovery)
        self.root.config(menu=menubar)

    def _common_args(self):
        args = ["--yes"]
        if self.vin.get().strip():
            args += ["--vin", self.vin.get().strip()]
        if self.gateway.get().strip():
            args += ["--gateway", self.gateway.get().strip()]
        if self.mgu_ip.get().strip():
            args += ["--mgu-ip", self.mgu_ip.get().strip()]
        if self.arch.get() in ARCHES:
            args += ["--arch", self.arch.get()]
        return args

    def _on_variant(self, label):
        """Map the friendly menu label back to the arch code the CLI expects."""
        self.arch.set(_VARIANT_BY_LABEL.get(label, ""))
        ok = self.arch.get() in ARCHES
        self._set_car_led(GREEN if ok else AMBER)

    def _set_car_led(self, color):
        try:
            self.car_led.itemconfig(self.car_dot, fill=color, outline=color)
        except (AttributeError, tk.TclError):
            pass

    def _require_variant(self):
        """True if a head-unit variant is selected; otherwise warn and return False.
        Flashing the wrong variant bricks the unit into programming mode (#47)."""
        if self.arch.get() in ARCHES:
            return True
        messagebox.showerror(
            "Select your car first",
            "Choose your head-unit variant (ID7, ID8 BDC3, or ID8 BCP) under "
            "\"YOUR CAR\" before flashing.\n\n"
            "There is no default on purpose: flashing the wrong variant partially "
            "writes the wrong image and can leave the unit stuck in programming mode.")
        return False

    def _run(self, argv, label):
        if self.worker and self.worker.is_alive():
            return
        self._busy(True)
        self._append("\n$ ssh_enable %s\n" % " ".join(argv))

        def task():
            saved_out, saved_err = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = _QueueWriter(self.q)
            rc = 1
            try:
                rc = ssh_enable.main(argv)
            except SystemExit as e:
                self.q.put("\n%s\n" % e)
                rc = e.code if isinstance(e.code, int) else 1
            except Exception as e:  # noqa: BLE001 - surface everything to the log
                self.q.put("\nERROR: %s\n" % e)
            finally:
                sys.stdout.flush()
                sys.stdout, sys.stderr = saved_out, saved_err
                self.q.put("\n[%s finished, exit %s]\n" % (label, rc))
                self.root.after(0, lambda: self._busy(False))

        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    # --- actions ----------------------------------------------------------

    def _persist_args(self):
        args = ["--persist"]
        if not self.disable_debug.get():
            args.append("--keep-debug")
        args.append("--unique-key" if self.unique_key.get() else "--no-unique-key")
        return args

    def do_enable(self):
        self._run(["enable"] + self._persist_args() + self._common_args(), "enable")

    def do_flash(self):
        if not self._require_variant():
            return
        if not self.vin.get().strip():
            messagebox.showerror(self.i18n.t("VIN required"),
                                 self.i18n.t("Flashing writes the VIN to the unit, so it is required.\n"
                                 "Enter it or click Detect VIN first."))
            return
        if not messagebox.askyesno(
            self.i18n.t("Flash the debug image?"),
            self.i18n.t("This puts the head unit into programming mode and reboots it.\n\n"
            "VIN %s will be written to the unit.\n\nContinue?") % self.vin.get().strip()):
            return
        self._run(["flash"] + self._persist_args() + self._common_args(), "flash")

    def do_fix_key(self):
        if not self._require_variant():
            return
        if not self.vin.get().strip():
            messagebox.showerror("VIN required",
                                 "Fix-key re-flashes the debug image (writing the VIN to the unit),\n"
                                 "so the VIN is required. Enter it or click Detect VIN first.")
            return
        if not messagebox.askyesno(
            "Fix the refusing SSH key?",
            "For units that flash + enroll fine and open port 22, but still refuse\n"
            "root login because their stock key differs.\n\n"
            "This re-flashes the debug image carrying OUR key in the one unsigned\n"
            "region (replacing debugCA). It only changes that region's bytes, so the\n"
            "worst case is the key not persisting - not a brick. The head unit enters\n"
            "programming mode and reboots, and (like any flash) CAFD coding is cleared;\n"
            "restore it from your backup.\n\n"
            "VIN %s will be written to the unit.\n\nContinue?" % self.vin.get().strip()):
            return
        self._run(["fix-key"] + self._persist_args() + self._common_args(), "fix-key")

    def do_disable(self):
        if not messagebox.askyesno(self.i18n.t("Disable SSH?"),
                                   self.i18n.t("Revert SSH to stock and stop debug mode on the head unit?")):
            return
        self._run(["disable"] + self._common_args(), "disable")

    def do_enter_prog(self):
        if not self._require_variant():
            return
        if not messagebox.askyesno(
            "Enter programming mode?",
            "Runs the proven pre-flash sequence (extended session, communication "
            "control, programming-precondition routines, an ECU reset, then the "
            "programming session) and stops the moment the unit is in programming "
            "mode.\n\n"
            "It writes NOTHING to flash and sends no VIN. The head unit shows the "
            "blue programming screen; use \"Exit programming mode\" to return it to "
            "normal (the session also lapses on its own after a few idle seconds).\n\n"
            "Continue?"):
            return
        self._run(["enter-prog"] + self._common_args(), "enter-prog")

    def do_exit_prog(self):
        if not messagebox.askyesno(
            "Exit programming mode?",
            "Leaves programming mode (default session) and reboots the head unit "
            "back to normal operation (ECU reset).\n\n"
            "Use this if a unit is stuck on the blue programming screen after a "
            "failed flash. It reboots the unit; give it ~30 s to come back.\n\n"
            "Continue?"):
            return
        self._run(["exit-prog"] + self._common_args(), "exit-prog")

    def detect_vin(self):
        if self.worker and self.worker.is_alive():
            return
        self._busy(True)
        self._append("\nScanning for an ENET gateway (UDP 6811)…\n")

        def task():
            try:
                gws = discovery.discover(log=lambda *a, **k: self.q.put(" ".join(str(x) for x in a) + "\n"))
            except Exception as e:  # noqa: BLE001
                gws = []
                self.q.put("Discovery failed: %s\n" % e)

            def apply():
                if gws:
                    g = gws[0]
                    if g.vin:
                        self.vin.set(g.vin)
                    self.gateway.set(g.ip)
                    self.q.put("Found gateway %s | VIN: %s\n" % (g.ip, g.vin or "not reported"))
                    if len(gws) > 1:
                        self.q.put("(%d gateways responded; using the first)\n" % len(gws))
                else:
                    self.q.put("No ENET gateway responded. Check the cable/adapter and that the car is awake.\n")
                self._busy(False)

            self.root.after(0, apply)

        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()


def main():
    try:
        root = tk.Tk()
        App(root)
        root.mainloop()
    except Exception:
        # A windowed exe would otherwise just disappear - leave a trace and,
        # if possible, show it.
        import traceback
        tb = traceback.format_exc()
        try:
            with open(os.path.join(HERE, "mgu-ssh-error.log"), "w", encoding="utf-8") as f:
                f.write(tb)
        except Exception:
            pass
        try:
            messagebox.showerror("MGU-SSH failed to start", tb)
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
