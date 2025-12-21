# src/logs.py
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from threading import Lock
import tempfile
import shutil

# ---------- CONFIG ----------
LOGS_XML_PATH = os.path.join(os.path.dirname(__file__), "../gesture_logs/logs.xml")
LOCK = Lock()
MAX_LOG_ENTRIES = 500  # Optional: keep last 500 logs only

# Ensure the folder exists
os.makedirs(os.path.dirname(LOGS_XML_PATH), exist_ok=True)

# ---------- Initialize XML if not exists ----------
def initialize_xml():
    if not os.path.exists(LOGS_XML_PATH):
        root = ET.Element("GesturaLogs", version="1.0", lastUpdated=datetime.now().isoformat())
        header = ET.SubElement(root, "Header")
        ET.SubElement(header, "Title").text = "Logs"
        logo = ET.SubElement(header, "Logo")
        logo.set("src", "../static/assets/logo.png")
        logo.set("alt", "Gestura Logo")
        ET.SubElement(root, "LogContainer")
        _safe_write_xml(root)

# ---------- Internal: safe XML write ----------
def _safe_write_xml(root_element):
    """Writes XML atomically to avoid corruption."""
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_file:
        tree = ET.ElementTree(root_element)
        tree.write(tmp_file.name, encoding="utf-8", xml_declaration=True)
    shutil.move(tmp_file.name, LOGS_XML_PATH)

# ---------- Add new log ----------
def add_log(log_type: str, message: str):
    """
    Add a log entry.

    log_type: 'info', 'warn', 'error'
    message: string
    """
    with LOCK:
        initialize_xml()
        tree = ET.parse(LOGS_XML_PATH)
        root = tree.getroot()
        log_container = root.find("LogContainer")
        if log_container is None:
            log_container = ET.SubElement(root, "LogContainer")

        # Trim old logs if exceeding MAX_LOG_ENTRIES
        if len(log_container) >= MAX_LOG_ENTRIES:
            for _ in range(len(log_container) - MAX_LOG_ENTRIES + 1):
                log_container.remove(log_container[0])

        log_id = str(len(log_container) + 1)
        timestamp = datetime.now().isoformat()

        log_entry = ET.SubElement(log_container, "LogEntry", id=log_id, type=log_type, timestamp=timestamp)
        log_entry.text = message

        root.set("lastUpdated", datetime.now().isoformat())
        _safe_write_xml(root)

# ---------- Read all logs (for HTML rendering) ----------
def get_all_logs():
    with LOCK:
        if not os.path.exists(LOGS_XML_PATH):
            return []
        tree = ET.parse(LOGS_XML_PATH)
        root = tree.getroot()
        log_container = root.find("LogContainer")
        if log_container is None:
            return []

        logs = []
        for entry in log_container.findall("LogEntry"):
            logs.append({
                "id": entry.attrib.get("id"),
                "type": entry.attrib.get("type"),
                "timestamp": entry.attrib.get("timestamp"),
                "message": entry.text.strip() if entry.text else ""
            })
        return logs

# ---------- Example Usage ----------
if __name__ == "__main__":
    add_log("info", "Log System initialized successfully.")
    add_log("warn", "----------LOG ENTRIES STARTS FROM HERE----------")

    logs = get_all_logs()
    for log in logs:
        print(f"[{log['type'].upper()}] {log['timestamp']}: {log['message']}")
