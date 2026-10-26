"""Register the packaged native messaging host after building it with PyInstaller."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

HOST_NAME = "com.local_password_manager.autofill"
ROOT = Path(__file__).resolve().parent

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--extension-id", required=True, help="Extension ID shown by your browser after loading browser_extension/ as unpacked")
    p.add_argument("--browser", choices=["chrome", "chromium", "brave"], default="chrome")
    p.add_argument("--host-path", help="Path to a built native host executable; defaults to password-manager-native-host[.exe]")
    args = p.parse_args()
    if not re.fullmatch(r"[a-p]{32}", args.extension_id): raise SystemExit("Extension ID must be the 32-character ID shown by Chromium.")
    host = Path(args.host_path).resolve() if args.host_path else ROOT / ("password-manager-native-host.exe" if os.name == "nt" else "password-manager-native-host")
    if not host.is_file(): raise SystemExit(f"Native host not found: {host}\nBuild it first: python -m pip install pyinstaller && pyinstaller --onefile --name password-manager-native-host --distpath . browser_native_host.py")
    if os.name != "nt": host.chmod(0o700)
    manifest = {"name": HOST_NAME, "description": "Local password manager native messaging host", "path": str(host), "type": "stdio", "allowed_origins": [f"chrome-extension://{args.extension_id}/"]}
    outdir = ROOT / "native_host_manifest"; outdir.mkdir(exist_ok=True)
    manifest_path = outdir / f"{HOST_NAME}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if os.name == "nt":
        key = f"HKCU\\Software\\{ {'chrome':'Google\\Chrome','chromium':'Chromium','brave':'BraveSoftware\\Brave-Browser'}[args.browser]}\\NativeMessagingHosts\\{HOST_NAME}"
        subprocess.run(["reg", "add", key, "/ve", "/t", "REG_SZ", "/d", str(manifest_path), "/f"], check=True)
    else:
        if args.browser == "brave": dest = Path.home()/".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"/f"{HOST_NAME}.json"
        elif args.browser == "chromium": dest = Path.home()/".config/chromium/NativeMessagingHosts"/f"{HOST_NAME}.json"
        else: dest = Path.home()/".config/google-chrome/NativeMessagingHosts"/f"{HOST_NAME}.json"
        dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(manifest_path, dest); dest.chmod(0o600)
    print(f"Native host manifest registered: {manifest_path}")
    print("Reload the extension and browser. Keep the native host binary and vault files local; do not publish them.")
if __name__ == "__main__": main()
