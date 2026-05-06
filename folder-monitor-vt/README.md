# Folder Monitor with VirusTotal

A Python script that watches a folder in real time. When a new file appears, it computes the SHA256 hash, queries the VirusTotal API, and writes the verdict to a timestamped log. If any antivirus engine flags the file as malicious, the script raises an `ALERT`.

## Features

- Real-time folder monitoring using `watchdog`
- SHA256 hashing via `hashlib` (chunked, works on large files)
- VirusTotal API v3 lookup via `requests`
- Structured logging with timestamps to both console and file
- Rate-limit-aware (free VT public API allows 4 requests/min, 500/day)
- Handles unknown files (404), invalid keys (401), and rate limits (429)

## Requirements

- Python 3.10+
- A free VirusTotal API key — get one at <https://www.virustotal.com/gui/my-apikey>

## Setup

```bash
git clone https://github.com/<your-username>/folder-monitor-vt.git
cd folder-monitor-vt

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env and paste your VirusTotal API key
```

## Usage

```bash
python monitor.py
```

The script creates a `./watch` folder (configurable via `.env`) and starts listening. Drop any file into it and watch the verdict appear in the console and in `scan.log`.

Stop with `Ctrl+C`.

## Example output

```
2026-05-06 14:22:11 | INFO    | Starting monitor on: /home/user/folder-monitor-vt/watch
2026-05-06 14:22:34 | INFO    | New file detected: ./watch/sample.exe
2026-05-06 14:22:34 | INFO    | SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
2026-05-06 14:22:36 | WARNING | ALERT: Malicious file detected! file=./watch/sample.exe sha256=275a... malicious=63/76 suspicious=0 harmless=0 undetected=13
2026-05-06 14:22:36 | WARNING | Detections: Kaspersky: EICAR-Test-File; Microsoft: Virus:DOS/EICAR_Test_File; ...
```

## Test it safely

Use the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) — it is a harmless string that every antivirus engine flags as malicious by convention. It is the standard, safe way to verify that your malware-detection pipeline works.

## Configuration

All settings live in `.env`:

| Variable | Default | Description |
|---|---|---|
| `VT_API_KEY` | _(required)_ | Your VirusTotal API key |
| `WATCH_FOLDER` | `./watch` | Folder to monitor |
| `LOG_FILE` | `./scan.log` | Where to write logs |

## How it works

1. `watchdog.Observer` watches the folder for `on_created` and `on_moved` events.
2. The handler waits briefly until the file size stabilizes (so a half-written file is not hashed).
3. `compute_sha256()` reads the file in 64 KB chunks.
4. `query_virustotal()` sends `GET https://www.virustotal.com/api/v3/files/<hash>` with the API key.
5. `analyze_response()` parses `last_analysis_stats`. If `malicious > 0`, it logs an `ALERT` plus the names of up to 10 flagging engines.
6. The script sleeps 16 seconds between requests to stay under the 4-per-minute free-tier limit.

## Project structure

```
folder-monitor-vt/
├── monitor.py          # Main script
├── requirements.txt    # Python dependencies
├── .env.example        # Template for environment variables
├── .gitignore
└── README.md
```

## Notes on the free VirusTotal tier

- 4 lookups per minute, 500 per day, 15 000 per month
- Hash lookups (what this script does) do not count against your upload quota
- A 404 means the hash is unknown to VT — not necessarily safe, just never seen before. To force analysis you would have to upload the file, which this script intentionally does not do (privacy + quota)

## License

MIT
