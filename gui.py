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
import re
import sys
import threading
import webbrowser

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

_URL_RE = re.compile(r'https?://\S+')

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
from mgu7 import discovery
from mgu7.flash import ID7, ID8_BDC3, ID8_BCP

ARCHES = (ID7, ID8_BDC3, ID8_BCP)

# palette
BG = "#f3f4f6"
HEADER = "#14315c"
HEADER_FG = "#ffffff"
ACCENT = "#1f6feb"
GREEN = "#1f9d55"
RED = "#c23b3b"
MUTED = "#64748b"
CONSOLE_BG = "#0f131a"
CONSOLE_FG = "#d6dbe5"


class _QueueWriter:
    """File-like object funnelling writes to a thread-safe queue."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)

    def flush(self):
        pass


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.worker = None
        self._link_n = 0

        root.title("MGU iDrive SSH Tool")
        root.configure(bg=BG)
        root.minsize(760, 560)

        self.vin = tk.StringVar()
        self.gateway = tk.StringVar(value="auto")
        self.mgu_ip = tk.StringVar()
        self.arch = tk.StringVar(value=ID7)
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
        st.configure("TFrame", background=BG)
        st.configure("TLabel", background=BG, foreground="#1f2937", font=("Segoe UI", 10))
        st.configure("Hint.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        st.configure("TEntry", fieldbackground="#ffffff", padding=5)
        st.configure("TMenubutton", background="#ffffff", padding=4)
        st.configure("Card.TLabelframe", background=BG, bordercolor="#d1d5db")
        st.configure("Card.TLabelframe.Label", background=BG, foreground=MUTED, font=("Segoe UI", 9, "bold"))

        def button(name, bg, active):
            st.configure(name, background=bg, foreground="#ffffff", font=("Segoe UI", 11, "bold"),
                         padding=(16, 12), borderwidth=0, focuscolor=bg)
            st.map(name, background=[("active", active), ("disabled", "#9aa4b2")])

        button("Primary.TButton", ACCENT, "#1a5fd0")
        button("Green.TButton", GREEN, "#17824a")
        button("Red.TButton", RED, "#a93030")
        st.configure("Detect.TButton", background=HEADER, foreground="#ffffff",
                     font=("Segoe UI", 9, "bold"), padding=(10, 6), borderwidth=0)
        st.map("Detect.TButton", background=[("active", "#1d4273"), ("disabled", "#9aa4b2")])

    # --- layout -----------------------------------------------------------

    def _build(self):
        header = tk.Frame(self.root, bg=HEADER)
        header.pack(fill="x")
        tk.Label(header, text="MGU iDrive  SSH", bg=HEADER, fg=HEADER_FG,
                 font=("Segoe UI Semibold", 16)).pack(side="left", padx=16, pady=12)
        tk.Label(header, text="BMW ID7 / ID8  •  root over ENET", bg=HEADER,
                 fg="#9fb3d1", font=("Segoe UI", 9)).pack(side="left", pady=12)

        body = ttk.Frame(self.root, padding=16)
        body.pack(fill="x")

        # VIN row
        vin_row = ttk.Frame(body)
        vin_row.pack(fill="x")
        ttk.Label(vin_row, text="VIN", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Entry(vin_row, textvariable=self.vin, width=24, font=("Consolas", 11)).pack(side="left", padx=8)
        self.detect_btn = ttk.Button(vin_row, text="Detect VIN", style="Detect.TButton", command=self.detect_vin)
        self.detect_btn.pack(side="left")
        ttk.Label(vin_row, text="(auto-reads the VIN from the car)", style="Hint.TLabel").pack(side="left", padx=8)

        # advanced row (compact, secondary)
        adv = ttk.Labelframe(body, text="CONNECTION (optional)", style="Card.TLabelframe", padding=8)
        adv.pack(fill="x", pady=(12, 0))
        ttk.Label(adv, text="Gateway").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(adv, textvariable=self.gateway, width=16).grid(row=0, column=1, sticky="w")
        ttk.Label(adv, text="Variant").grid(row=0, column=2, sticky="w", padx=(16, 6))
        ttk.OptionMenu(adv, self.arch, self.arch.get(), *ARCHES).grid(row=0, column=3, sticky="w")
        ttk.Label(adv, text="MGU IP").grid(row=0, column=4, sticky="w", padx=(16, 6))
        ttk.Entry(adv, textvariable=self.mgu_ip, width=16).grid(row=0, column=5, sticky="w")

        # the three actions
        actions = ttk.Frame(body)
        actions.pack(fill="x", pady=(16, 0))
        actions.columnconfigure((0, 1, 2), weight=1, uniform="a")
        self.btn_flash = ttk.Button(actions, text="Flash + Enable", style="Primary.TButton", command=self.do_flash)
        self.btn_enable = ttk.Button(actions, text="Enable", style="Green.TButton", command=self.do_enable)
        self.btn_disable = ttk.Button(actions, text="Disable", style="Red.TButton", command=self.do_disable)
        self.btn_flash.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.btn_enable.grid(row=0, column=1, sticky="ew", padx=6)
        self.btn_disable.grid(row=0, column=2, sticky="ew", padx=(6, 0))
        opt = ttk.Frame(body)
        opt.pack(fill="x", pady=(10, 0))
        ttk.Checkbutton(opt, text="Turn debug mode off after enabling (clears the B7F8E5 DTC)",
                        variable=self.disable_debug).pack(anchor="w")
        ttk.Label(opt, text="On = SSH stays up with debug off (recommended).  Off = SSH persistent but debug mode stays on.",
                  style="Hint.TLabel").pack(anchor="w")
        ttk.Checkbutton(opt, text="Give this car its own unique SSH key  (advanced - NOT recommended)",
                        variable=self.unique_key).pack(anchor="w", pady=(6, 0))
        ttk.Label(opt, text="Swaps the shared dev key for a per-car key. Can only be done ONCE - if you lose the key or reflash, you can't create a new identity. Leave off unless you know why you need it.",
                  style="Hint.TLabel").pack(anchor="w")

        self.action_buttons = [self.btn_flash, self.btn_enable, self.btn_disable]

        # log console
        console = ttk.Frame(self.root, padding=(16, 0, 16, 8))
        console.pack(fill="both", expand=True)
        self.out = scrolledtext.ScrolledText(console, height=16, wrap="word", font=("Consolas", 9),
                                             bg=CONSOLE_BG, fg=CONSOLE_FG, insertbackground=CONSOLE_FG,
                                             relief="flat", borderwidth=0, padx=10, pady=8)
        self.out.pack(fill="both", expand=True)
        self.out.configure(state="disabled")

        self.status = tk.Label(self.root, text="Ready.", anchor="w", bg="#e5e7eb",
                               fg="#374151", font=("Segoe UI", 9), padx=10, pady=4)
        self.status.pack(fill="x")

    # --- helpers ----------------------------------------------------------

    def _append(self, text):
        self.out.configure(state="normal")
        start = self.out.index("end-1c")
        self.out.insert("end", text)
        for m in _URL_RE.finditer(text):
            tag = "link%d" % self._link_n
            self._link_n += 1
            a, b = "%s+%dc" % (start, m.start()), "%s+%dc" % (start, m.end())
            self.out.tag_add(tag, a, b)
            self.out.tag_config(tag, foreground="#4da3ff", underline=True)
            self.out.tag_bind(tag, "<Button-1>", lambda e, url=m.group(0): webbrowser.open(url))
            self.out.tag_bind(tag, "<Enter>", lambda e: self.out.configure(cursor="hand2"))
            self.out.tag_bind(tag, "<Leave>", lambda e: self.out.configure(cursor=""))
        self.out.see("end")
        self.out.configure(state="disabled")

    def _drain(self):
        try:
            while True:
                self._append(self.q.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _busy(self, on):
        state = "disabled" if on else "normal"
        for b in self.action_buttons:
            b.configure(state=state)
        self.detect_btn.configure(state=state)
        self.status.configure(text="Working…" if on else "Ready.")

    def _common_args(self):
        args = ["--yes"]
        if self.vin.get().strip():
            args += ["--vin", self.vin.get().strip()]
        if self.gateway.get().strip():
            args += ["--gateway", self.gateway.get().strip()]
        if self.mgu_ip.get().strip():
            args += ["--mgu-ip", self.mgu_ip.get().strip()]
        args += ["--arch", self.arch.get()]
        return args

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
        if not self.vin.get().strip():
            messagebox.showerror("VIN required",
                                 "Flashing writes the VIN to the unit, so it is required.\n"
                                 "Enter it or click Detect VIN first.")
            return
        if not messagebox.askyesno(
            "Flash the debug image?",
            "This puts the head unit into programming mode and reboots it.\n\n"
            "VIN %s will be written to the unit.\n\nContinue?" % self.vin.get().strip()):
            return
        self._run(["flash"] + self._persist_args() + self._common_args(), "flash")

    def do_disable(self):
        if not messagebox.askyesno("Disable SSH?",
                                   "Revert SSH to stock and stop debug mode on the head unit?"):
            return
        self._run(["disable"] + self._common_args(), "disable")

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
