#===----------------------------------------------------------------------===//
# src/app.py
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
import threading
import socket
import uuid
import io
import qrcode
import secrets
import hashlib
import time
import webbrowser
from datetime import datetime, timedelta
from flask import Flask, render_template, send_file, jsonify, request
from functools import wraps

import logs

# Resource path locatation helper
def resource_path(relative_path: str) -> str:
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_path, relative_path)

#  Configuration ----------
PERMISSIONS_FILE = "Config/permissions.json"
WINDOW_TITLE = "Gestura for Home Users"
WINDOW_WIDTH = 470
WINDOW_HEIGHT = 800

FLASK_PORT = 5000
SESSION_EXPIRY = 300  # 5 minutes
MAX_REQUESTS_PER_MINUTE = 30

#  Logging setup ----------
logger = logging.getLogger("gestureflow")
logger.setLevel(logging.INFO)
logger.handlers.clear()
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)

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

# ---------- API Bridge ----------
class Api:
    def __init__(self):
        self._permissions = load_permissions()
        self.link_status = {"linked": False, "device_ip": None, "linked_at": None}
        self._window = None  # Will be set by main()
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

    def get_link_status(self):
        return self.link_status

    def open_link_page(self):
        url = f"http://localhost:{FLASK_PORT}"
        
        # Schedule navigation after a short delay to allow callback to complete
        def delayed_navigation():
            import time
            time.sleep(0.1)  # Small delay to let JavaScript callback finish
            try:
                if self._window:
                    self._window.load_url(url)
                    logs.add_log("info", "Opened device linking page in webview")
                else:
                    logs.add_log("error", "Window reference not available")
            except Exception as e:
                logger.error(f"Error in open_link_page: {e}")
                logs.add_log("error", f"Error opening link page: {e}")
        
        # Start navigation in background thread
        import threading
        threading.Thread(target=delayed_navigation, daemon=True).start()
        
        # Return immediately so callback can complete
        return {"status": "ok", "url": url}

# Global API instance
api_instance = Api()

# ---------- Flask Secure Linking Server ----------
flask_app = Flask(__name__, template_folder=resource_path("templates"))

flask_app.config['SECRET_KEY'] = secrets.token_hex(32)
flask_app.config['SESSION_COOKIE_SECURE'] = True
flask_app.config['SESSION_COOKIE_HTTPONLY'] = True
flask_app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
flask_app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

SESSIONS = {}
RATE_LIMIT = {}

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

LOCAL_IP = get_local_ip()

def rate_limit(max_requests=MAX_REQUESTS_PER_MINUTE):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            RATE_LIMIT[client_ip] = [t for t in RATE_LIMIT.get(client_ip, []) if current_time - t < 60]
            if len(RATE_LIMIT.get(client_ip, [])) >= max_requests:
                logger.warning(f"Verification already done for IP: {client_ip}")
                return jsonify({"error": "Rate limit exceeded"}), 429
            RATE_LIMIT.setdefault(client_ip, []).append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def is_valid_session_id(session_id):
    try:
        uuid.UUID(session_id)
        return True
    except ValueError:
        return False

def clean_expired_sessions():
    current_time = time.time()
    expired = [sid for sid, data in SESSIONS.items() if current_time - data['created_at'] > SESSION_EXPIRY]
    for sid in expired:
        del SESSIONS[sid]
        logger.info(f"Expired session removed: {sid}")

def create_secure_session():
    session_id = str(uuid.uuid4())
    verification_code = secrets.token_hex(16)
    SESSIONS[session_id] = {
        'linked': False,
        'created_at': time.time(),
        'verification_code': hashlib.sha256(verification_code.encode()).hexdigest(),
        'attempts': 0,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', '')
    }
    logger.info(f"New session created: {session_id} from IP: {request.remote_addr}")
    return session_id

@flask_app.route("/")
@rate_limit(max_requests=10)
def index():
    clean_expired_sessions()
    session_id = create_secure_session()
    return render_template("link.html", session_id=session_id)

@flask_app.route("/qr/<session_id>")
@rate_limit()
def qr(session_id):
    if not is_valid_session_id(session_id):
        logger.warning(f"Invalid session ID format: {session_id}")
        return "Invalid session", 400
    
    if session_id not in SESSIONS:
        logger.warning(f"QR requested for non-existent session: {session_id}")
        return "Session not found", 404
    
    session_data = SESSIONS[session_id]
    if time.time() - session_data['created_at'] > SESSION_EXPIRY:
        logger.warning(f"QR requested for expired session: {session_id}")
        del SESSIONS[session_id]
        return "Session expired", 410
    
    link = f"http://{LOCAL_IP}:{FLASK_PORT}/link/{session_id}"
    img = qrcode.make(link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    
    return send_file(buf, mimetype="image/png", max_age=0)

@flask_app.route("/link/<session_id>")
@rate_limit()
def link(session_id):
    if not is_valid_session_id(session_id):
        logger.warning(f"Invalid link attempt: {session_id}")
        return "Invalid session", 400
    
    if session_id not in SESSIONS:
        logger.warning(f"Link attempt for non-existent session: {session_id}")
        return "Session not found", 404
    
    session_data = SESSIONS[session_id]
    
    if time.time() - session_data['created_at'] > SESSION_EXPIRY:
        logger.warning(f"Link attempt for expired session: {session_id}")
        del SESSIONS[session_id]
        return "Session expired", 410
    
    if session_data['attempts'] >= 3:
        logger.warning(f"Too many attempts for session: {session_id}")
        return "Too many attempts", 429
    
    session_data['attempts'] += 1
    session_data['linked'] = True
    session_data['linked_at'] = time.time()
    session_data['linked_ip'] = request.remote_addr
    
    api_instance.link_status = {
        "linked": True,
        "device_ip": request.remote_addr,
        "linked_at": datetime.now().isoformat()
    }
    logs.add_log("info", f"Device linked: {session_id} from {request.remote_addr}")
    logger.info(f"Session linked: {session_id} from IP: {request.remote_addr}")
    
    return render_template("linked.html")

@flask_app.route("/status/<session_id>")
@rate_limit(max_requests=60)
def status(session_id):
    if not is_valid_session_id(session_id):
        return jsonify({"error": "Invalid session"}), 400
    
    clean_expired_sessions()
    
    if session_id not in SESSIONS:
        return jsonify({"error": "Session not found", "linked": False}), 404
    
    session_data = SESSIONS[session_id]
    
    if time.time() - session_data['created_at'] > SESSION_EXPIRY:
        del SESSIONS[session_id]
        return jsonify({"error": "Session expired", "linked": False}), 410
    
    return jsonify({
        "linked": session_data['linked'],
        "expires_in": int(SESSION_EXPIRY - (time.time() - session_data['created_at']))
    })

@flask_app.route("/audio/<filename>")
def serve_audio(filename):
    """Serve audio files from Audio directory"""
    allowed_files = ['scan_ok.mp3', 'scan_error.mp3']
    if filename not in allowed_files:
        return "File not found", 404
    
    audio_path = resource_path(os.path.join("Audio", filename))
    if not os.path.exists(audio_path):
        logger.warning(f"Audio file not found: {audio_path}")
        return "File not found", 404
    
    return send_file(audio_path, mimetype="audio/mpeg")

@flask_app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# ---------- SFX & Window ----------
sfx_played = False
window_load_count = 0

def run_flask():
    print(f"\n{'='*60}")
    print(f"  Secure Device Linking Server")
    print(f"{'='*60}")
    print(f"  Access the QR linking page at: http://localhost:{FLASK_PORT}")
    print(f"  Mobile devices on same network: http://{LOCAL_IP}:{FLASK_PORT}")
    print(f"  Session Timeout: {SESSION_EXPIRY}s")
    print(f"  Rate Limit: {MAX_REQUESTS_PER_MINUTE} req/min")
    print(f"{'='*60}\n")
    flask_app.run(host="0.0.0.0", port=FLASK_PORT, debug=False, threaded=True, use_reloader=False)

def main():
    global sfx_played, window_load_count

    html_path = resource_path("templates/home.html")

    if not os.path.exists(html_path):
        logger.error("home.html not found at: %s", html_path)
        return

    # Start Flask server in background thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    audio_dir = resource_path("Audio")
    open_audio_path = os.path.join(audio_dir, "open.wav")
    main_audio_path = os.path.join(audio_dir, "open1.wav")

    # Debug: Check audio files existence
    logger.info(f"open.wav exists: {os.path.exists(open_audio_path)} at {open_audio_path}")
    logger.info(f"open1.wav exists: {os.path.exists(main_audio_path)} at {main_audio_path}")

    def window_loaded_callback():
        global sfx_played, window_load_count

        logger.info(f"Window loaded event triggered (count: {window_load_count + 1})")

        if not sfx_played and os.path.exists(open_audio_path):
            try:
                logger.info(f"Playing open.wav: {open_audio_path}")
                wave_obj = sa.WaveObject.from_wave_file(open_audio_path)
                play_obj = wave_obj.play()
                play_obj.wait_done()  # Blocking, but safe for startup
                logger.info("open.wav played successfully")
            except Exception as e:
                logger.error(f"Failed to play open.wav: {e}")
            sfx_played = True

        window_load_count += 1
        logger.info(f"Window load count now: {window_load_count}")

        if window_load_count >= 3 and os.path.exists(main_audio_path):
            try:
                logger.info(f"Playing open1.wav: {main_audio_path}")
                wave_obj = sa.WaveObject.from_wave_file(main_audio_path)
                play_obj = wave_obj.play()
                play_obj.wait_done()
                logger.info("open1.wav played successfully")
            except Exception as e:
                logger.error(f"Failed to play open1.wav: {e}")

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
        js_api=api_instance,
        resizable=False
    )

    # Store window reference in api_instance so it can navigate the window
    api_instance._window = window   

    # Attach callback without arguments (pywebview calls it as func())
    window.events.loaded += window_loaded_callback

    webview.start()


# ---------- Entrypoint ----------  
if __name__ == "__main__":
    main()
