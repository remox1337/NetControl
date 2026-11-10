"""NetControl - Internet fuer ein bestimmtes Programm per Hotkey ab- und wieder anschalten."""

import ctypes
import functools
import io
import json
import math
import os
import struct
import wave
import webbrowser
import queue
import sys
import threading
import winsound
from tkinter import filedialog, messagebox

import customtkinter as ctk
import keyboard

import firewall
import updater
from version import VERSION

FROZEN = getattr(sys, "frozen", False)
# In der exe liegen gebuendelte Dateien im Entpack-Ordner sys._MEIPASS
_RES_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
ICON_PATH = os.path.join(_RES_DIR, "NetControl.ico")
# Einstellungen im Benutzerprofil ablegen, damit neben der exe keine zweite Datei liegt
_CFG_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "NetControl")
CONFIG_PATH = os.path.join(_CFG_DIR, "config.json")

DEFAULTS = {"exe_path": "", "hotkey": "f8", "sound": True, "volume": 25, "on_top": False,
            "same_name": True, "children": True}

RED = "#d64545"
RED_HOVER = "#b83a3a"
GREEN = "#2e9e5b"
GREEN_HOVER = "#268a4e"
MUTED = "gray60"


def ensure_admin():
    """Firewall-Regeln brauchen Administratorrechte - sonst mit UAC-Abfrage neu starten."""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    args = sys.argv[1:] if FROZEN else [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = " ".join(f'"{a}"' for a in args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, APP_DIR, 1)
    if rc <= 32:
        ctypes.windll.user32.MessageBoxW(None, "NetControl benoetigt Administratorrechte.", "NetControl", 0x10)
    sys.exit(0)


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg


class Card(ctk.CTkFrame):
    def __init__(self, master, title):
        super().__init__(master, corner_radius=12)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(10, 6)
        )


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.blocked = False
        self.busy = False
        self.recording = False
        self.hotkey_handle = None
        self.events = queue.Queue()   # Ereignisse aus Hotkey-/Worker-Threads -> UI-Thread
        self.programs = {}
        self.blocker = firewall.Blocker(
            on_change=lambda paths, closed: self.events.put(("family", paths, closed))
        )

        self.title(f"NetControl {VERSION}")
        if os.path.exists(ICON_PATH):
            try:
                self.iconbitmap(ICON_PATH)
            except Exception:
                pass
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.attributes("-topmost", self.cfg["on_top"])

        # Reste aus einem Absturz entfernen, damit das Programm nicht dauerhaft gesperrt bleibt
        firewall.unblock()

        self._build_ui()
        self._fit_window()
        self._register_hotkey()
        self.refresh_programs()
        self.after(50, self._poll_events)
        self.after(1500, lambda: self.check_updates(silent=True))

    # ------------------------------------------------------------------ UI

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        pad = {"padx": 16, "pady": 8, "sticky": "ew"}

        ctk.CTkLabel(self, text="NetControl", font=ctk.CTkFont(size=24, weight="bold")).grid(
            row=0, column=0, padx=16, pady=(16, 0), sticky="w"
        )
        ctk.CTkLabel(self, text="Internet für ein einzelnes Programm per Hotkey abschalten",
                     text_color=MUTED).grid(row=1, column=0, padx=16, pady=(0, 2), sticky="w")
        # Hinweis - kleiner und etwas dunkler als die Beschreibung, damit er sich abhebt
        ctk.CTkLabel(self, text="Beim Beenden wird das Internet automatisch wieder freigegeben.",
                     text_color="gray45", font=ctk.CTkFont(size=11)).grid(
            row=2, column=0, padx=16, pady=(0, 6), sticky="w")

        # --- Programm
        prog = Card(self, "Programm")
        prog.grid(row=3, column=0, **pad)
        self.path_var = ctk.StringVar(value=self.cfg["exe_path"])
        self.path_var.trace_add("write", lambda *_: self._on_path_changed())
        ctk.CTkEntry(prog, textvariable=self.path_var, placeholder_text="Pfad zur .exe").grid(
            row=1, column=0, padx=(14, 6), pady=4, sticky="ew"
        )
        ctk.CTkButton(prog, text="Durchsuchen", width=110, command=self.browse).grid(
            row=1, column=1, padx=(0, 14), pady=4
        )
        self.proc_box = ctk.CTkComboBox(prog, values=[], command=self._on_program_picked, state="readonly")
        self.proc_box.set("Laufendes Programm wählen …")
        self.proc_box.grid(row=2, column=0, padx=(14, 6), pady=4, sticky="ew")
        ctk.CTkButton(prog, text="↻ Aktualisieren", width=110, fg_color="gray30", hover_color="gray25",
                      command=self.refresh_programs).grid(row=2, column=1, padx=(0, 14), pady=4)
        self.same_var = ctk.BooleanVar(value=self.cfg["same_name"])
        ctk.CTkCheckBox(prog, text="Gleichnamige Programme mitsperren (z.B. mehrere chrome.exe)",
                        variable=self.same_var, command=self._on_family_option).grid(
            row=3, column=0, columnspan=2, padx=14, pady=(8, 4), sticky="w")
        self.children_var = ctk.BooleanVar(value=self.cfg["children"])
        ctk.CTkCheckBox(prog, text="Gestartete Unterprozesse mitsperren (Launcher, Helfer)",
                        variable=self.children_var, command=self._on_family_option).grid(
            row=4, column=0, columnspan=2, padx=14, pady=(4, 12), sticky="w")

        # --- Schalter
        sw = Card(self, "Internet")
        sw.grid(row=4, column=0, **pad)
        self.toggle_btn = ctk.CTkButton(sw, height=64, corner_radius=10,
                                        font=ctk.CTkFont(size=18, weight="bold"), command=self.toggle)
        self.toggle_btn.grid(row=1, column=0, columnspan=2, padx=14, pady=(4, 6), sticky="ew")
        self.status_lbl = ctk.CTkLabel(sw, text="", text_color=MUTED)
        self.status_lbl.grid(row=2, column=0, columnspan=2, padx=14, pady=(0, 2), sticky="w")
        self.family_lbl = ctk.CTkLabel(sw, text="", text_color=MUTED, justify="left", anchor="w",
                                       font=ctk.CTkFont(size=11), wraplength=460)
        self.family_lbl.grid(row=3, column=0, columnspan=2, padx=14, pady=(0, 10), sticky="w")

        # --- Hotkey & Optionen
        opt = Card(self, "Hotkey & Optionen")
        opt.grid(row=5, column=0, **pad)
        ctk.CTkLabel(opt, text="Hotkey zum Umschalten:").grid(row=1, column=0, padx=14, pady=4, sticky="w")
        self.hotkey_btn = ctk.CTkButton(opt, width=150, fg_color="gray30", hover_color="gray25",
                                        command=self.record_hotkey)
        self.hotkey_btn.grid(row=1, column=1, padx=14, pady=4)
        self.sound_var = ctk.BooleanVar(value=self.cfg["sound"])
        ctk.CTkCheckBox(opt, text="Ton beim Umschalten", variable=self.sound_var,
                        command=self.save_config).grid(row=2, column=0, padx=14, pady=4, sticky="w")
        vol = ctk.CTkFrame(opt, fg_color="transparent")
        vol.grid(row=2, column=1, padx=14, pady=4)
        self.volume_var = ctk.IntVar(value=self.cfg["volume"])
        self.volume_lbl = ctk.CTkLabel(vol, width=40, text=f"{self.cfg['volume']} %")
        slider = ctk.CTkSlider(vol, from_=1, to=100, number_of_steps=99, width=110, variable=self.volume_var,
                               command=lambda v: self.volume_lbl.configure(text=f"{int(v)} %"))
        slider.grid(row=0, column=0)
        self.volume_lbl.grid(row=0, column=1, padx=(6, 0))
        # Beim Loslassen Probeton abspielen und speichern
        slider.bind("<ButtonRelease-1>", lambda _: (self.save_config(), self._beep(False, force=True)))
        self.top_var = ctk.BooleanVar(value=self.cfg["on_top"])
        ctk.CTkCheckBox(opt, text="Fenster immer im Vordergrund", variable=self.top_var,
                        command=self._on_top_changed).grid(row=3, column=0, columnspan=2, padx=14,
                                                            pady=4, sticky="w")
        ctk.CTkLabel(opt, text=f"Version {VERSION}", text_color=MUTED).grid(
            row=4, column=0, padx=14, pady=(8, 12), sticky="w")
        self.update_btn = ctk.CTkButton(opt, text="Nach Updates suchen", width=150, fg_color="gray30",
                                        hover_color="gray25", command=self.check_updates)
        self.update_btn.grid(row=4, column=1, padx=14, pady=(8, 2))
        # Update-Meldungen erscheinen hier direkt beim Button, nicht beim Sperr-Status
        self.update_lbl = ctk.CTkLabel(opt, text="", text_color=MUTED, font=ctk.CTkFont(size=11),
                                       justify="right", anchor="e", wraplength=360)
        self.update_lbl.grid(row=5, column=1, padx=14, pady=(0, 12), sticky="e")

        self._update_view()

    def _fit_window(self):
        """Fenster an den tatsaechlich benoetigten Platz des Inhalts anpassen, damit bei
        beliebiger Windows-Skalierung nichts unten abgeschnitten wird."""
        self.update_idletasks()
        w = max(self.winfo_reqwidth(), 540)
        h = self.winfo_reqheight()
        # mittig auf dem Bildschirm, aber nie hoeher als der verfuegbare Platz
        h = min(h, self.winfo_screenheight() - 80)
        x = (self.winfo_screenwidth() - w) // 2
        y = max(0, (self.winfo_screenheight() - h) // 2 - 20)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(w, min(h, self.winfo_reqheight()))

    def _update_view(self, status=None):
        hk = self.cfg["hotkey"].upper()
        if self.blocked:
            self.toggle_btn.configure(text="⛔  INTERNET AUS  –  klicken zum Freigeben",
                                      fg_color=RED, hover_color=RED_HOVER)
        else:
            self.toggle_btn.configure(text="🌐  Internet an  –  klicken zum Sperren",
                                      fg_color=GREEN, hover_color=GREEN_HOVER)
        self.toggle_btn.configure(state="disabled" if self.busy else "normal")
        self.hotkey_btn.configure(text="Taste drücken …" if self.recording else f"⌨  {hk}")
        if status is None:
            name = os.path.basename(self.path_var.get()) or "kein Programm gewählt"
            status = f"{'Gesperrt' if self.blocked else 'Frei'}: {name}   ·   Hotkey: {hk}"
        self.status_lbl.configure(text=status)

    # ------------------------------------------------------------ Programm

    def browse(self):
        path = filedialog.askopenfilename(title="Programm wählen", filetypes=[("Programme", "*.exe")])
        if path:
            self.path_var.set(os.path.normpath(path))

    def refresh_programs(self):
        def work():
            self.events.put(("programs", firewall.network_programs()))
        threading.Thread(target=work, daemon=True).start()

    def _on_program_picked(self, name):
        if name in self.programs:
            self.path_var.set(self.programs[name])

    def _on_path_changed(self):
        # Programmwechsel waehrend der Sperre: alte Regel aufheben
        if self.blocked and not self.busy:
            self._run_worker(False)
        self.save_config()
        self._update_view()

    # -------------------------------------------------------------- Sperre

    def toggle(self):
        if self.busy or self.recording:
            return
        if not self.blocked:
            path = self.path_var.get().strip()
            if not path or not os.path.isfile(path):
                self._update_view("⚠  Bitte zuerst eine gültige .exe auswählen.")
                return
        self._run_worker(not self.blocked)

    def _run_worker(self, block):
        self.busy = True
        self._update_view("Wird umgeschaltet …")
        path = self.path_var.get().strip()

        def work():
            try:
                if block:
                    self.blocker.start(path, self.same_var.get(), self.children_var.get())
                    self.events.put(("done", True, None))
                    self.events.put(("family", list(self.blocker.paths.values()), self.blocker.closed_total))
                else:
                    self.blocker.stop()
                    self.events.put(("done", False, None))
            except Exception as e:
                self.blocker.stop()
                self.events.put(("done", False, f"⚠  Fehler: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _on_family_option(self):
        # wirkt bei laufender Sperre ab dem naechsten Scan
        self.blocker.same_name = self.same_var.get()
        self.blocker.children = self.children_var.get()
        self.save_config()

    def _show_family(self, paths, closed):
        if not self.blocked:
            self.family_lbl.configure(text="")
            return
        names = sorted({os.path.basename(p) for p in paths}, key=str.lower)
        self.status_lbl.configure(
            text=f"Gesperrt: {len(paths)} Programmdatei(en)   ·   {closed} Verbindung(en) getrennt")
        self.family_lbl.configure(text="Gesperrt: " + ", ".join(names))

    def _beep(self, blocked, force=False):
        # winsound.Beep hat keine Lautstaerke - daher eigenen Sinuston als WAV erzeugen
        if not (self.sound_var.get() or force):
            return
        wav = self._tone(500 if blocked else 1000, self.volume_var.get())
        threading.Thread(target=winsound.PlaySound, args=(wav, winsound.SND_MEMORY), daemon=True).start()

    @staticmethod
    @functools.lru_cache(maxsize=32)
    def _tone(freq, volume_pct, duration=0.18, rate=44100):
        # Stille vorweg: Audiogeraete im Energiesparmodus verschlucken beim Aufwachen den Anfang,
        # ohne Vorlauf bleibt dann oft nur das Einschalt-Klacken uebrig
        lead, tail = int(rate * 0.25), int(rate * 0.05)
        n = int(rate * duration)
        fade = int(rate * 0.02)  # Ein-/Ausblenden gegen Knacken
        amp = 32767 * (volume_pct / 100) ** 2  # quadratisch, damit der Regler sich gleichmaessiger anfuehlt
        frames = bytearray(lead * 2)
        for i in range(n):
            env = min(1.0, i / fade, (n - i) / fade)
            frames += struct.pack("<h", int(amp * env * math.sin(2 * math.pi * freq * i / rate)))
        frames += bytes(tail * 2)
        buf = io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(rate)
            w.writeframes(bytes(frames))
        return buf.getvalue()

    # -------------------------------------------------------------- Hotkey

    def _unregister_hotkey(self):
        if self.hotkey_handle is not None:
            try:
                keyboard.remove_hotkey(self.hotkey_handle)
            except Exception:
                pass
            self.hotkey_handle = None

    def _register_hotkey(self):
        self._unregister_hotkey()
        try:
            self.hotkey_handle = keyboard.add_hotkey(self.cfg["hotkey"], lambda: self.events.put(("hotkey",)))
        except Exception as e:
            self._update_view(f"⚠  Hotkey ungültig: {e}")

    def record_hotkey(self):
        if self.recording:
            return
        self.recording = True
        self._unregister_hotkey()
        self._update_view("Neue Tastenkombination drücken …")

        def work():
            hk = keyboard.read_hotkey(suppress=False)
            self.events.put(("hotkey_set", hk))
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------ Ereignisse

    def _poll_events(self):
        try:
            while True:
                ev = self.events.get_nowait()
                kind = ev[0]
                if kind == "hotkey":
                    self.toggle()
                elif kind == "hotkey_set":
                    self.recording = False
                    if ev[1] and ev[1] != "esc":
                        self.cfg["hotkey"] = ev[1]
                        self.save_config()
                    self._register_hotkey()
                    self._update_view()
                elif kind == "done":
                    self.busy = False
                    changed = self.blocked != ev[1]
                    self.blocked = ev[1]
                    if changed:
                        self._beep(self.blocked)
                    self._update_view(ev[2])
                    if not self.blocked:
                        self.family_lbl.configure(text="")
                elif kind == "family":
                    self._show_family(ev[1], ev[2])
                elif kind == "programs":
                    self.programs = ev[1]
                    self.proc_box.configure(values=list(self.programs) or ["(keine gefunden)"])
                elif kind == "update_status":
                    self.update_btn.configure(state="normal")
                    self._set_update_msg(ev[1])
                elif kind == "update_found":
                    self._offer_update(ev[1])
                elif kind == "update_progress":
                    self._set_update_msg(f"Lädt … {ev[1]} %")
                elif kind == "update_ready":
                    self._finish_update(ev[1])
        except queue.Empty:
            pass
        self.after(50, self._poll_events)

    # -------------------------------------------------------------- Updates

    def _set_update_msg(self, text):
        self.update_lbl.configure(text=text or "")

    def check_updates(self, silent=False):
        if not updater.configured():
            if not silent:
                self._set_update_msg("Update-Prüfung nicht eingerichtet.")
            return
        self.update_btn.configure(state="disabled")
        if not silent:
            self._set_update_msg("Suche …")

        def work():
            try:
                info = updater.check()
            except Exception as e:
                # offline o.ae. - beim automatischen Check beim Start still bleiben
                self.events.put(("update_status", None if silent else f"GitHub nicht erreichbar ({type(e).__name__})"))
                return
            if info:
                self.events.put(("update_found", info))
            else:
                self.events.put(("update_status", None if silent else f"Aktuell ({VERSION})"))
        threading.Thread(target=work, daemon=True).start()

    def _offer_update(self, info):
        self.update_btn.configure(state="normal")
        self._set_update_msg(f"Version {info['version']} verfügbar")
        notes = f"\n\nNeu:\n{info['notes'][:500]}" if info["notes"] else ""
        # In der exe: herunterladen und automatisch austauschen. Als Skript: nur Seite oeffnen.
        if not updater.FROZEN:
            if messagebox.askyesno("NetControl – Update",
                                   f"Version {info['version']} ist verfügbar (installiert: {VERSION}).{notes}\n\n"
                                   "Download-Seite öffnen? (Automatischer Austausch nur in der .exe)",
                                   parent=self):
                webbrowser.open(info["page"])
            return
        if not messagebox.askyesno("NetControl – Update",
                                   f"Version {info['version']} ist verfügbar (installiert: {VERSION}).{notes}\n\n"
                                   "Jetzt herunterladen und installieren? NetControl startet danach neu.",
                                   parent=self):
            return
        self.update_btn.configure(state="disabled")
        self._set_update_msg("Lädt …")

        def progress(done, total):
            if total:
                self.events.put(("update_progress", done * 100 // total))

        def work():
            try:
                self.events.put(("update_ready", updater.download(info, progress)))
            except Exception as e:
                self.events.put(("update_status", f"⚠ Fehlgeschlagen: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _finish_update(self, new_path):
        # Vor dem Austausch die Sperre loesen, sonst bleiben Firewall-Regeln zurueck
        self.blocker.stop()
        self._set_update_msg("Installiere, Neustart …")
        self.update_idletasks()
        updater.install_and_restart(new_path)
        self.on_close()

    # -------------------------------------------------------------- Sonstiges

    def _on_top_changed(self):
        self.attributes("-topmost", self.top_var.get())
        self.save_config()

    def save_config(self):
        self.cfg.update(exe_path=self.path_var.get().strip(), sound=self.sound_var.get(),
                        volume=self.volume_var.get(), on_top=self.top_var.get(),
                        same_name=self.same_var.get(), children=self.children_var.get())
        try:
            os.makedirs(_CFG_DIR, exist_ok=True)
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.cfg, f, indent=2)
        except Exception:
            pass

    def on_close(self):
        self.save_config()
        keyboard.unhook_all()
        self.blocker.stop()
        self.destroy()


if __name__ == "__main__":
    ensure_admin()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    App().mainloop()
