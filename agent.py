"""ISS Cloud Security Agent (lite).

What it does:
  * registers this PC with your license (the server enforces the device limit)
  * watches your folders and scans every new or changed file
  * quarantines anything that matches a signature or a threat hash from the ISS cloud
  * shows a pop-up and reports the event to your Client Portal
  * runs the portal's "Test" button using the harmless EICAR test file, through the
    SAME pipeline as a real threat

Usage:
  python agent.py                run protection (keep it running)
  python agent.py scan <folder>  scan a folder now
  python agent.py restore <name> restore a quarantined file
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import uuid

import requests

BASE_URL = "https://iss-antivirus-cloud.onrender.com"
CONFIG_FILE = "config.json"
QUARANTINE_DIR = "quarantine"
TEST_DIR = "iss_test"
MAX_SCAN_BYTES = 50 * 1024 * 1024

# Standard, harmless EICAR antivirus test string (split so this file is not flagged itself).
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SIGNATURES = {"EICAR-Test-File": EICAR.encode()}

threat_hashes = set()
last_command_id = 0


def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def device_id():
    raw = f"{uuid.getnode()}-{platform.node()}-{platform.system()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def call(path, extra=None):
    payload = {"license_key": load_config().get("license_key", ""), "device_id": device_id(),
               "device_name": platform.node() or "Unnamed PC"}
    payload.update(extra or {})
    try:
        return requests.post(BASE_URL + path, json=payload, timeout=15).json()
    except Exception:
        return {"status": "error", "message": "Server unreachable."}


def popup(title, msg):
    def run():
        print(f"[POPUP] {title}: {msg}")
        try:
            if os.name == "nt":
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30)
            elif sys.platform == "darwin":
                subprocess.run(["osascript", "-e", 'display notification "%s" with title "%s"' % (msg.replace('"', "'"), title)])
            else:
                subprocess.run(["notify-send", title, msg])
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def detect(path):
    """Return a threat name or None. Test files and real malware use this same check."""
    try:
        if os.path.getsize(path) > MAX_SCAN_BYTES:
            return None
        with open(path, "rb") as f:
            data = f.read()
        for name, sig in SIGNATURES.items():
            if sig in data:
                return name
        if hashlib.sha256(data).hexdigest() in threat_hashes:
            return "Known-Malware-Hash"
    except Exception:
        return None
    return None


def quarantine(path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{os.path.basename(path)}.iss")
    shutil.move(path, dest)
    with open(dest + ".json", "w") as f:
        json.dump({"original": os.path.abspath(path)}, f)
    return dest


def handle_file(path, command_id=0, is_test=False):
    """One pipeline for every file: detect, quarantine, warn, report."""
    name = detect(path)
    if not name:
        return False
    try:
        quarantine(path)
    except Exception as e:
        print(f"[!] Could not quarantine {path}: {e}")
        if is_test:
            call("/api/agent/event", {"type": "test_missed", "command_id": command_id, "detail": "could not quarantine"})
        return False
    popup("ISS Security - Threat blocked", f"{name} was blocked and quarantined:\n{os.path.basename(path)}")
    call("/api/agent/event", {"type": "test_blocked" if is_test else "threat_blocked", "command_id": command_id,
                              "detail": f"{name}: {os.path.basename(path)}"})
    return True


def run_test(command_id):
    os.makedirs(TEST_DIR, exist_ok=True)
    path = os.path.join(TEST_DIR, f"eicar_test_{int(time.time())}.com")
    with open(path, "w") as f:
        f.write(EICAR)
    handle_file(path, command_id, is_test=True)
    if os.path.exists(path):  # still there = protection failed
        call("/api/agent/event", {"type": "test_missed", "command_id": command_id, "detail": "test file was not blocked"})


def refresh_threats():
    res = call("/api/agent/threats")
    if res.get("status") == "ok":
        threat_hashes.update(res.get("hashes", []))


def watch_folders():
    cfg = load_config()
    home = os.path.expanduser("~")
    folders = cfg.get("watch") or [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), TEST_DIR]
    return [os.path.abspath(p) for p in folders if os.path.isdir(p)]


def scan_folder(folder, seen=None, depth=2):
    found = 0
    base = folder.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(folder):
        if root.count(os.sep) - base >= depth or QUARANTINE_DIR in root:
            dirs[:] = []
        for name in files:
            p = os.path.join(root, name)
            try:
                m = os.path.getmtime(p)
            except OSError:
                continue
            if seen is not None:
                if seen.get(p) == m:
                    continue
                seen[p] = m
            if handle_file(p):
                found += 1
    return found


def protect():
    global last_command_id
    if not load_config().get("license_key"):
        print("[Error] config.json with your license_key was not found. Download it from the Client Portal.")
        return
    res = call("/api/activate")
    if res.get("status") != "active":
        print(f"[Denied] {res.get('message', 'Activation failed')}")
        return
    print(f"[Active] {res['plan']} | devices {res['devices_used']} of {res['devices_max']} | expires {res['expiry']}")
    refresh_threats()
    seen, tick = {}, 0
    for f in watch_folders():
        for root, _, files in os.walk(f):
            for n in files:
                try:
                    seen[os.path.join(root, n)] = os.path.getmtime(os.path.join(root, n))
                except OSError:
                    pass
    print("[+] Real-time protection is running. Watching:", ", ".join(watch_folders()) or "nothing")
    while True:
        for f in watch_folders():
            scan_folder(f, seen)
        if tick % 6 == 0:
            res = call("/api/agent/poll", {"since_id": last_command_id})
            if res.get("status") == "ok":
                for cmd in res.get("commands", []):
                    if cmd["type"] == "eicar_test":
                        run_test(cmd["id"])
                last_command_id = max(last_command_id, res.get("last_id", 0))
            elif res.get("status") == "denied":
                print(f"[Denied] {res.get('message')}")
        if tick % 120 == 0 and tick:
            refresh_threats()
        tick += 1
        time.sleep(5)


def restore(name):
    src = os.path.join(QUARANTINE_DIR, name)
    try:
        with open(src + ".json") as f:
            dest = json.load(f)["original"]
        shutil.move(src, dest)
        os.remove(src + ".json")
        print(f"[+] Restored to {dest}")
    except Exception as e:
        print(f"[Error] {e}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["scan"] and len(args) > 1:
        refresh_threats()
        print(f"[+] Threats found: {scan_folder(args[1], depth=10)}")
    elif args[:1] == ["restore"] and len(args) > 1:
        restore(args[1])
    else:
        try:
            protect()
        except KeyboardInterrupt:
            print("\n[+] Agent stopped.")
