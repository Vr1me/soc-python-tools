"""
Folder Monitor with VirusTotal integration.

Watches a folder for new files, computes SHA256, queries VirusTotal,
and logs results. Raises ALERT if any antivirus engine flags the file.
"""

import os
import sys
import time
import hashlib
import logging
from pathlib import Path

import requests
from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# ---------- Configuration ----------
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
WATCH_FOLDER = os.getenv("WATCH_FOLDER", "./watch")
LOG_FILE = os.getenv("LOG_FILE", "./scan.log")
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

# VirusTotal public API: 4 requests/min, 500/day. Wait between requests.
VT_REQUEST_DELAY = 16  # seconds between requests to stay under rate limit


# ---------- Logging setup ----------
logger = logging.getLogger("folder-monitor")
logger.setLevel(logging.INFO)

_fmt = logging.Formatter(
    "%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(_fmt)

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(_fmt)

logger.addHandler(_file_handler)
logger.addHandler(_console_handler)


# ---------- Core logic ----------
def compute_sha256(filepath: str, chunk_size: int = 65536) -> str:
    """Read file in chunks and return its SHA256 hex digest."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha.update(chunk)
    return sha.hexdigest()


def query_virustotal(file_hash: str) -> dict | None:
    """
    Query VirusTotal for a file hash.

    Returns the parsed JSON dict, or None on error / not found.
    """
    if not VT_API_KEY:
        logger.error("VT_API_KEY is not set. Add it to your .env file.")
        return None

    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(
            VT_URL.format(file_hash), headers=headers, timeout=30
        )
    except requests.RequestException as exc:
        logger.error("Network error contacting VirusTotal: %s", exc)
        return None

    if response.status_code == 200:
        return response.json()
    if response.status_code == 404:
        logger.info("File hash not found in VirusTotal database (unknown file).")
        return None
    if response.status_code == 401:
        logger.error("VirusTotal rejected API key (401). Check VT_API_KEY.")
        return None
    if response.status_code == 429:
        logger.warning("VirusTotal rate limit hit (429). Slow down requests.")
        return None

    logger.error(
        "Unexpected VirusTotal response %s: %s",
        response.status_code,
        response.text[:200],
    )
    return None


def analyze_response(filepath: str, file_hash: str, vt_data: dict) -> None:
    """Parse VT response and log verdict."""
    try:
        attributes = vt_data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
    except KeyError as exc:
        logger.error("Unexpected VT response shape, missing key: %s", exc)
        return

    summary = (
        f"file={filepath} sha256={file_hash} "
        f"malicious={malicious}/{total} suspicious={suspicious} "
        f"harmless={harmless} undetected={undetected}"
    )

    if malicious > 0:
        logger.warning("ALERT: Malicious file detected! %s", summary)

        # Log which engines flagged it
        results = attributes.get("last_analysis_results", {})
        flagged = [
            f"{engine}: {res.get('result')}"
            for engine, res in results.items()
            if res.get("category") == "malicious"
        ]
        if flagged:
            logger.warning("Detections: %s", "; ".join(flagged[:10]))
    elif suspicious > 0:
        logger.warning("SUSPICIOUS file (no malicious hits). %s", summary)
    else:
        logger.info("Clean file. %s", summary)


def scan_file(filepath: str) -> None:
    """Full pipeline: hash -> query VT -> log verdict."""
    if not os.path.isfile(filepath):
        return

    # Wait for the file to finish being written (simple stability check)
    last_size = -1
    for _ in range(10):
        try:
            size = os.path.getsize(filepath)
        except OSError:
            return
        if size == last_size and size > 0:
            break
        last_size = size
        time.sleep(0.5)

    logger.info("New file detected: %s", filepath)

    try:
        file_hash = compute_sha256(filepath)
    except OSError as exc:
        logger.error("Cannot read %s: %s", filepath, exc)
        return

    logger.info("SHA256: %s", file_hash)

    vt_data = query_virustotal(file_hash)
    if vt_data:
        analyze_response(filepath, file_hash, vt_data)

    # Respect rate limit before the next request
    time.sleep(VT_REQUEST_DELAY)


# ---------- Watchdog handler ----------
class NewFileHandler(FileSystemEventHandler):
    """React to file creation events in the watched folder."""

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        scan_file(event.src_path)

    def on_moved(self, event) -> None:
        # Some apps write to a temp file and rename it on completion
        if event.is_directory:
            return
        scan_file(event.dest_path)


# ---------- Entrypoint ----------
def main() -> None:
    folder = Path(WATCH_FOLDER).expanduser().resolve()
    folder.mkdir(parents=True, exist_ok=True)

    if not VT_API_KEY:
        logger.error("VT_API_KEY missing. Copy .env.example to .env and set it.")
        sys.exit(1)

    logger.info("Starting monitor on: %s", folder)
    logger.info("Logging to: %s", os.path.abspath(LOG_FILE))

    observer = Observer()
    observer.schedule(NewFileHandler(), str(folder), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping monitor (Ctrl+C).")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
