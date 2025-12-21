#===----------------------------------------------------------------------===//
#
# This source file is part of the PorocoX open source project
#
# Copyright (c) 2025 PorocoX Pvt. Ltd.
# Proprietary software owned exclusively by PorocoX Pvt. Ltd.
# Redistribution is permitted, but any forked code must be made publicly available.
# This software is open source, allowing anyone to contribute and use it free of charge.
#
# SPDX-License-Identifier: PROPRIETARY
#
#===----------------------------------------------------------------------===//

import os
import sys
import json
import logging
import traceback
import webview
import simpleaudio as sa

import logs

# ---------- PyInstaller + src-safe path resolver ----------
def resource_path(relative_path: str) -> str:
    """
    Resolves paths correctly for:
    - normal execution (project root)
    - PyInstaller onefile execution (_MEIPASS)
    """
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        # project root, NOT src/
        base_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )
    return os.path.join(base_path, relative_path)
# --------------------------------------------------------

# ---------- Configuration ----------
PERMISSIONS_FILE = "Config/permissions.json"
WINDOW_TITLE = "Gestura for Home Users"
WINDOW_WIDTH = 470
WINDOW_HEIGHT = 800
# -----------------------------------

# ---------- Logging setup ----------
logger = logging.getLogger("gestureflow")
logger.setLevel(logging.INFO)
logger.handlers.clear()

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)
# -----------------------------------

# ---------- Persistence helpers ----------
def load_permissions() -> dict:
    path = resource_path(PERMISSIONS_FILE)
    defaults = {"camera": False, "microphone": False, "storage": False}

    if not os.path.exists(path):
        return defaults

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {k: bool(data.get(k, False)) for k in defaults}
    except Exception as e:
        logger.warning("Failed to read permissions file — resetting: %s", e)
        return defaults


def save_permissions(perms: dict) -> None:
    path = resource_path(PERMISSIONS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(perms, f, indent=2)
        os.replace(tmp, path)
        logger.info("Permissions persisted: %s", perms)
    except Exception:
        logger.error("Failed to save permissions:\n%s", traceback.format_exc())
# ----------------------------------------

# ---------- API Bridge ----------
class Api:
    def __init__(self):
        self._permissions = load_permissions()
        logger.info("Loaded permissions: %s", self._permissions)

    def get_permissions(self):
        return self._permissions

    def grant_permission(self, permission_name: str):
        if permission_name not in self._permissions:
            return {"status": "error", "message": "invalid_permission"}
        self._permissions[permission_name] = True
        save_permissions(self._permissions)
        logs.add_log("info", f"Permission granted: {permission_name}")
        return {"status": "ok"}

    def revoke_permission(self, permission_name: str):
        if permission_name not in self._permissions:
            return {"status": "error", "message": "invalid_permission"}
        self._permissions[permission_name] = False
        save_permissions(self._permissions)
        logs.add_log("warn", f"Permission revoked: {permission_name}")
        return {"status": "ok"}

    def reset_permissions(self):
        for k in self._permissions:
            self._permissions[k] = False
        save_permissions(self._permissions)
        logs.add_log("warn", "All permissions reset")
        return {"status": "ok"}

    def add_log(self, log_type: str, message: str):
        logs.add_log(log_type, message)
        return {"status": "ok"}

    def get_logs(self):
        return logs.get_all_logs()
# --------------------------------

# ---------- SFX & Window ----------
sfx_played = False
window_load_count = 0
# --------------------------------

def main():
    global sfx_played, window_load_count

    html_path = resource_path("templates/home.html")

    audio_dir = resource_path("Audio")
    open_audio_path = os.path.join(audio_dir, "open.wav")
    main_audio_path = os.path.join(audio_dir, "open1.wav")

    def window_loaded_callback(window):
        global sfx_played, window_load_count

        if not sfx_played and os.path.exists(open_audio_path):
            try:
                sa.WaveObject.from_wave_file(open_audio_path).play().wait_done()
            except Exception:
                pass
            sfx_played = True

        window_load_count += 1
        if window_load_count == 3 and os.path.exists(main_audio_path):
            try:
                sa.WaveObject.from_wave_file(main_audio_path).play().wait_done()
            except Exception:
                pass

    if not os.path.exists(html_path):
        logger.error("home.html not found at: %s", html_path)
        return

    screen = webview.screens[0]
    x = (screen.width - WINDOW_WIDTH) // 2
    y = (screen.height - WINDOW_HEIGHT) // 2

    window = webview.create_window(
        title=WINDOW_TITLE,
        url=f"file://{html_path}",
        width=WINDOW_WIDTH,
        height=WINDOW_HEIGHT,
        x=x,
        y=y,
        js_api=Api(),
        resizable=False
    )

    window.events.loaded += window_loaded_callback
    webview.start()

# ---------- Entrypoint ----------
if __name__ == "__main__":
    main()
# ---------- END OF FILE ----------
