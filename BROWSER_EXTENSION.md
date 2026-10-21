# Optional browser autofill (Chromium-based browsers)

The browser integration is intentionally opt-in and uses **Native Messaging**, not a local HTTP server. The extension asks the native host to search for credentials matching the active page's exact origin (scheme, hostname, and effective port). It returns only platform, username, and category during search. A password is returned only after the user clicks **Autofill this login**. The extension does not persist the master password or credentials in browser storage.

## Build and install on Windows

1. Install the Python dependencies from `requirements.txt` and the optional packager:
   ```powershell
   python -m pip install -r requirements.txt
   python -m pip install pyinstaller
   pyinstaller --onefile --name password-manager-native-host --distpath . browser_native_host.py
   ```
2. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `browser_extension/`. Copy the extension ID shown by Chromium.
3. Register the native host (replace the ID):
   ```powershell
   python install_native_host.py --extension-id abcdefghijklmnopabcdefghijklmnop --browser chrome
   ```
   The installer writes the native messaging manifest and registers it under the current Windows user. Use `--browser brave` or `--browser chromium` for those browsers.
4. Reload the extension and restart the browser. Open a site, click the extension, unlock with your vault master password, and choose a matching login.

## Linux

Build the host as above (the binary must be in the project root), then run the installer with `--browser chrome` or `--browser chromium`. The script installs the native host manifest in the current user's configuration directory. Ensure the project directory and host executable are not writable by other users.

## Safe use and limitations

- Save a credential with its full website URL in the CLI before trying autofill.
- Matching requires the same scheme, hostname, and effective port; a different subdomain or HTTP/HTTPS scheme will not match. Redirects to a different origin will not receive a credential.
- Autofill is user-triggered. Always check the address bar and visible page before filling, and review fields before submitting. Browser extensions cannot make a compromised website trustworthy.
- The native host keeps the derived key only in its process and locks after five minutes of inactivity. Closing the popup/port normally terminates the host and clears the key. This is not a substitute for OS account security.
- Native host packaging/registration is platform-specific. The included test suite exercises the Python protocol handler but does not simulate a real browser installation or certify browser security.
- The extension requires `activeTab`, `scripting`, and `nativeMessaging`, but does not request blanket website access or inject scripts until the user clicks an autofill button.
- The master password is sent from the extension popup to the native host over the browser's local Native Messaging pipe. Install only this extension from a source you trust; do not share a built extension that you have not reviewed.


## Full vault dashboard (v2)

The action popup remains focused on exact-origin autofill. Select **Open full vault dashboard** to use `dashboard.html`, which supports listing/search, add, generate, update password, metadata editing, delete, reveal, health checks, encrypted backup/restore, master-password change, encrypted sync, and device revocation. Load the entire `browser_extension/` directory as an unpacked extension. Install the Native Messaging host using the extension ID shown by the browser.

The native host returns a password only for an explicit reveal action or when the user selects a matching credential to autofill. Keep extension permissions minimal and do not install the extension from untrusted packages.

The dashboard also supports an explicit **Copy password** action. It requests clipboard read/write permissions and attempts to clear the clipboard after 30 seconds only if the clipboard still contains the copied value. Clipboard clearing is best-effort; OS clipboard history and clipboard managers may retain copies. The dashboard automatically locks after five minutes of inactivity and clears visible password fields.
