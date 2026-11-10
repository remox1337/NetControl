"""Internet fuer ein Programm ueber die Windows-Firewall sperren/freigeben.

Ein Programm besteht oft aus mehreren Prozessen (Launcher, Helfer, gleichnamige exe-Dateien
an verschiedenen Orten). Der Blocker sperrt deshalb die ganze Prozessfamilie und prueft
im Hintergrund laufend auf neu gestartete Prozesse.
"""

import ctypes
import os
import re
import socket
import struct
import subprocess
import threading
from ctypes import wintypes

import psutil

RULE_NAME = "NetControl_Block"
CREATE_NO_WINDOW = 0x08000000
MIB_TCP_STATE_DELETE_TCB = 12
SCAN_INTERVAL = 1.0

# Kindprozesse aus dem Windows-Ordner (cmd, conhost, WerFault ...) nicht sperren -
# eine Regel auf deren Pfad wuerde sie systemweit treffen
_SYSTEM_DIR = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + os.sep


def _netsh(args):
    r = subprocess.run(
        "netsh advfirewall firewall " + args,
        capture_output=True,
        text=True,
        creationflags=CREATE_NO_WINDOW,
    )
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def unblock():
    """Entfernt alle NetControl-Regeln (Fehler, wenn keine existiert, wird ignoriert)."""
    _netsh(f'delete rule name="{RULE_NAME}"')


def _norm(path):
    return os.path.normcase(os.path.abspath(path))


# ---------------------------------------------------------------- Store-Apps

def _package_sid(exe_path):
    """AppContainer-SID fuer Programme aus C:\\Program Files\\WindowsApps, sonst None."""
    m = re.search(r"\\WindowsApps\\([^\\]+)\\", exe_path, re.I)
    if not m:
        return None
    parts = m.group(1).split("_")  # Name_Version_Arch_Resource_PublisherId
    if len(parts) < 5:
        return None
    family = f"{parts[0]}_{parts[-1]}"
    userenv, advapi, kernel = ctypes.windll.userenv, ctypes.windll.advapi32, ctypes.windll.kernel32
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    psid = ctypes.c_void_p()
    if userenv.DeriveAppContainerSidFromAppContainerName(family, ctypes.byref(psid)) != 0:
        return None
    try:
        s = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(psid, ctypes.byref(s)):
            return None
        sid = s.value
        kernel.LocalFree(s)
        return sid
    finally:
        advapi.FreeSid(psid)


def _add_package_rules(sid):
    script = "; ".join(
        f"New-NetFirewallRule -DisplayName '{RULE_NAME}' -Direction {d} -Action Block -Package '{sid}' | Out-Null"
        for d in ("Outbound", "Inbound")
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", script],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)


# ------------------------------------------------------------ TCP trennen

class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]


def _addr(ip):
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def close_tcp_connections(pids):
    """Trennt bestehende IPv4-TCP-Verbindungen der Prozesse hart. Gibt die Anzahl zurueck."""
    if not pids:
        return 0
    closed = 0
    for c in psutil.net_connections("tcp4"):
        if c.pid in pids and c.raddr and c.status == psutil.CONN_ESTABLISHED:
            row = MIB_TCPROW(
                MIB_TCP_STATE_DELETE_TCB,
                _addr(c.laddr.ip),
                socket.htons(c.laddr.port),
                _addr(c.raddr.ip),
                socket.htons(c.raddr.port),
            )
            if ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row)) == 0:
                closed += 1
    return closed


# ---------------------------------------------------------------- Blocker

class Blocker:
    """Sperrt ein Programm samt Prozessfamilie, solange es aktiv ist.

    on_change(paths, closed) wird aus dem Hintergrund-Thread aufgerufen, wenn neue
    exe-Dateien gesperrt oder Verbindungen getrennt wurden.
    """

    def __init__(self, on_change=None):
        self.on_change = on_change
        self.paths = {}        # normcase-Pfad -> Originalpfad
        self.closed_total = 0
        self._sids = set()
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()

    @property
    def active(self):
        return self._thread is not None

    def start(self, exe_path, same_name=True, children=True):
        self.stop()
        self.exe_path = exe_path
        self.same_name = same_name
        self.children = children
        self.paths = {}
        self.closed_total = 0
        self._sids = set()
        self._stop.clear()
        # Erste Runde synchron, damit die Sperre sofort greift und Fehler direkt ankommen
        self._add_rules([exe_path])
        self._scan()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread:
            self._stop.set()
            self._thread.join(3)
            self._thread = None
        unblock()
        self.paths = {}

    def _run(self):
        while not self._stop.wait(SCAN_INTERVAL):
            try:
                self._scan()
            except Exception:
                pass

    def _family(self):
        """PIDs und exe-Pfade aller Prozesse, die zum Zielprogramm gehoeren."""
        target = _norm(self.exe_path)
        target_name = os.path.basename(target)
        roots = []
        for p in psutil.process_iter(["exe", "name"]):
            exe = p.info.get("exe")
            if not exe:
                continue
            n = os.path.normcase(exe)
            if n == target or (self.same_name and os.path.basename(n) == target_name):
                roots.append(p)
        family = {p.pid: p.info["exe"] for p in roots}
        if self.children:
            for root in roots:
                try:
                    for child in root.children(recursive=True):
                        try:
                            exe = child.exe()
                        except Exception:
                            continue
                        if exe and not os.path.normcase(exe).startswith(_SYSTEM_DIR):
                            family[child.pid] = exe
                except Exception:
                    pass
        return family

    def _add_rules(self, exe_paths):
        new = []
        with self._lock:
            for path in exe_paths:
                key = _norm(path)
                if key in self.paths or self._stop.is_set():
                    continue
                for direction in ("out", "in"):
                    ok, msg = _netsh(
                        f'add rule name="{RULE_NAME}" dir={direction} action=block '
                        f'program="{path}" enable=yes profile=any'
                    )
                    if not ok:
                        raise RuntimeError(msg or "netsh-Fehler")
                self.paths[key] = path
                new.append(path)
                sid = _package_sid(path)
                if sid and sid not in self._sids:
                    self._sids.add(sid)
                    _add_package_rules(sid)
        return new

    def _scan(self):
        family = self._family()
        new = self._add_rules(set(family.values()))
        # Jede Runde trennen: erwischt auch Verbindungen, die kurz vor der Regel entstanden sind
        closed = close_tcp_connections(set(family))
        self.closed_total += closed
        if (new or closed) and self.on_change:
            self.on_change(list(self.paths.values()), self.closed_total)


# ------------------------------------------------------------- Auswahl-Liste

def network_programs():
    """{Anzeigename: exe-Pfad} aller Prozesse mit Netzwerkverbindungen.
    Gleichnamige exe-Dateien an verschiedenen Orten bekommen den Ordner dazugeschrieben."""
    paths = set()
    try:
        pids = {c.pid for c in psutil.net_connections("inet") if c.pid}
    except Exception:
        pids = set()
    for pid in pids:
        try:
            exe = psutil.Process(pid).exe()
        except Exception:
            continue
        if exe and not exe.lower().endswith("svchost.exe"):
            paths.add(exe)

    by_name = {}
    for path in paths:
        by_name.setdefault(os.path.basename(path).lower(), []).append(path)
    result = {}
    for group in by_name.values():
        for path in group:
            label = os.path.basename(path)
            if len(group) > 1:
                folder = os.path.dirname(path).split(os.sep)
                label += "  –  …\\" + "\\".join(folder[-2:])
            result[label] = path
    return dict(sorted(result.items(), key=lambda kv: kv[0].lower()))
