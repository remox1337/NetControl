"""Automatische Updates ueber GitHub-Releases.

check()  fragt das neueste Release ab und vergleicht die Version.
download()  laedt die neue exe (ueber HTTPS von github.com) und prueft, falls im Release
            eine Datei NetControl.exe.sha256 liegt, die Pruefsumme.
install_and_restart()  ersetzt nach dem Beenden die laufende exe und startet neu.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request

from version import GITHUB_REPO, VERSION

FROZEN = getattr(sys, "frozen", False)
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
ASSET_NAME = "NetControl.exe"


def _vtuple(v):
    return tuple(int(x) for x in v.lstrip("vV").split("."))


def configured():
    return bool(GITHUB_REPO)


def _get(url, timeout, accept="application/vnd.github+json"):
    req = urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": f"NetControl/{VERSION}"}
    )
    return urllib.request.urlopen(req, timeout=timeout)


def check(timeout=5):
    """Gibt {"version", "page", "notes", "url", "sha_url"} zurueck, wenn ein neueres
    Release mit NetControl.exe bereitliegt, sonst None. Netzwerkfehler -> Exception."""
    if not configured():
        return None
    with _get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest", timeout) as r:
        release = json.loads(r.read())
    tag = release.get("tag_name", "")
    try:
        if _vtuple(tag) <= _vtuple(VERSION):
            return None
    except ValueError:  # Tag ist keine Versionsnummer
        return None

    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    if ASSET_NAME not in assets:
        return None  # Release ohne exe - nichts zum Installieren
    return {
        "version": tag.lstrip("vV"),
        "page": release["html_url"],
        "notes": release.get("body") or "",
        "url": assets[ASSET_NAME],
        "sha_url": assets.get(ASSET_NAME + ".sha256"),
    }


def _expected_sha(sha_url, timeout):
    with _get(sha_url, timeout, accept="text/plain") as r:
        # Format wie von certutil/sha256sum: Hash steht am Anfang
        return r.read().decode("utf-8", "replace").split()[0].lower()


def download(info, progress=None, timeout=30):
    """Laedt die neue exe neben die laufende und prueft den Hash (falls vorhanden).
    Gibt den Pfad der heruntergeladenen Datei zurueck."""
    target = sys.executable + ".new"
    h = hashlib.sha256()
    with _get(info["url"], timeout, accept="application/octet-stream") as r, open(target, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while chunk := r.read(256 * 1024):
            h.update(chunk)
            f.write(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)

    if info.get("sha_url"):
        try:
            expected = _expected_sha(info["sha_url"], timeout)
        except Exception:
            expected = None
        if expected and h.hexdigest() != expected:
            os.remove(target)
            raise ValueError("Prüfsumme stimmt nicht – Update verworfen")
    return target


def install_and_restart(new_path):
    """Startet ein Hilfsskript, das wartet, bis die App beendet ist, dann die exe
    ersetzt und neu startet. Danach muss die App sich selbst beenden."""
    exe = sys.executable
    bat = os.path.join(tempfile.gettempdir(), "netcontrol_update.bat")
    # Die exe ist gesperrt, bis die App (inkl. PyInstaller-Bootloader) beendet ist -> Retry-Schleife
    script = f"""@echo off
chcp 65001 >nul
set n=0
:retry
ping -n 2 127.0.0.1 >nul
move /Y "{new_path}" "{exe}" >nul 2>&1
if not errorlevel 1 goto done
set /a n+=1
if %n% lss 30 goto retry
:done
start "" "{exe}"
del "%~f0"
"""
    with open(bat, "w", encoding="utf-8") as f:
        f.write(script)
    # Die laufende exe ist selbst eine PyInstaller-onefile-App und hat _PYI_*-Variablen gesetzt.
    # Werden sie an das Hilfsskript und damit an die neue exe vererbt, haelt diese sich faelschlich
    # fuer einen Kindprozess der (schon beendeten) alten exe und bricht mit
    # "Security validation failure ... invalid originating onefile parent process" ab.
    # Deshalb alle _PYI_*- und _MEIPASS-Variablen aus der Umgebung des Neustarts entfernen.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("_PYI") and "MEIPASS" not in k}
    subprocess.Popen(["cmd", "/c", bat], creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                     close_fds=True, env=env)
