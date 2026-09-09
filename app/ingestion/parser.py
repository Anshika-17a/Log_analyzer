"""
Multi-format log ingestion parser.

Supported formats (auto-detected by file extension or content):
  - CSV  (.csv)       — original format
  - JSON (.json)      — array of objects OR single object with a logs array
  - JSONL (.jsonl)    — one JSON object per line (newline-delimited JSON)
  - Syslog (.log, .syslog, .txt) — standard syslog lines

Field normalisation: every format is mapped to the internal schema:
  ts, user, event, resource, ip, status, raw_line
"""

import io
import json
import re
import traceback
from datetime import datetime

import pandas as pd
from sqlalchemy.orm import Session

from app.models.schema import Log

# ── Required internal columns ────────────────────────────────────────────────
REQUIRED_COLS = ["timestamp", "user_id", "event_type", "resource", "src_ip", "status"]

# ── Common field aliases that people use in JSON logs ───────────────────────
FIELD_ALIASES = {
    "timestamp":  ["timestamp", "time", "ts", "datetime", "date", "@timestamp", "event_time", "created_at"],
    "user_id":    ["user_id", "user", "username", "userId", "user_name", "actor", "account", "principal"],
    "event_type": ["event_type", "eventType", "event", "action", "type", "event_name", "operation"],
    "resource":   ["resource", "target", "object", "path", "url", "file", "asset", "service"],
    "src_ip":     ["src_ip", "ip", "source_ip", "client_ip", "remote_ip", "ipAddress", "remote_addr", "sourceIP"],
    "status":     ["status", "result", "outcome", "response", "state", "event_outcome", "success"],
}

# ── Syslog regex (covers RFC3164 and common variants) ────────────────────────
# Example: Sep  9 14:23:01 hostname sshd[1234]: Failed password for user1 from 1.2.3.4
SYSLOG_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)"
    r"\s+(?P<host>\S+)?"
    r"\s+(?P<process>[^\[:]+)(?:\[\d+\])?:\s*"
    r"(?P<message>.+)"
)

# ── Event-type inference for syslog messages ─────────────────────────────────
_EVENT_PATTERNS = [
    (re.compile(r"failed password|authentication failure|invalid user|login failed", re.I), "login_failure"),
    (re.compile(r"accepted password|session opened|logged in|successful login", re.I),      "login_success"),
    (re.compile(r"sudo:|privilege escalat|su\s+to", re.I),                                  "privilege_escalation"),
    (re.compile(r"connection from|connect(ed)?\s+from", re.I),                              "connection"),
    (re.compile(r"file (created|deleted|modified|moved|renamed|accessed)", re.I),           "file_access"),
    (re.compile(r"data (exfil|transfer|download|upload)", re.I),                            "data_transfer"),
    (re.compile(r"scan|nmap|nikto|recon", re.I),                                            "recon"),
    (re.compile(r"permission denied|access denied|forbidden", re.I),                        "access_denied"),
    (re.compile(r"admin|root|superuser", re.I),                                             "admin_action"),
]

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:for|user|from user|by)\s+([A-Za-z0-9_\-\.@]+)", re.I)


def _infer_event_type(msg: str) -> str:
    for pattern, event in _EVENT_PATTERNS:
        if pattern.search(msg):
            return event
    return "system_event"


def _extract_ip(msg: str) -> str:
    m = _IP_RE.search(msg)
    return m.group(0) if m else "0.0.0.0"


def _extract_user(msg: str, host: str = "") -> str:
    m = _USER_RE.search(msg)
    if m:
        return m.group(1)
    return host or "unknown"


# ────────────────────────────────────────────────────────────────────────────
# Normaliser — turns any flat dict into the standard 6-column DataFrame row
# ────────────────────────────────────────────────────────────────────────────
def _normalise_record(rec: dict) -> dict | None:
    """Map a raw dict (from JSON/syslog) to the internal schema."""
    out = {}
    for target, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias in rec and rec[alias] is not None and str(rec[alias]).strip():
                out[target] = str(rec[alias]).strip()
                break
        else:
            out[target] = ""  # fill missing
    return out if any(out.values()) else None


# ────────────────────────────────────────────────────────────────────────────
# DataFrame → DB
# ────────────────────────────────────────────────────────────────────────────
def _ingest_dataframe(df: pd.DataFrame, db: Session) -> tuple[int, int]:
    """Validate, clean and insert a DataFrame that already has the 6 required columns."""
    inserted = skipped = 0

    missing_ip  = df["src_ip"].isna()  | (df["src_ip"].str.strip() == "")
    df["ts_norm"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    invalid_ts  = df["ts_norm"].isna()

    bad = missing_ip | invalid_ts
    skipped += int(bad.sum())
    df = df[~bad].copy()

    if df.empty:
        return inserted, skipped

    df["ts"]       = df["ts_norm"].dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    df["user"]     = df["user_id"].fillna("").str.strip()
    df["event"]    = df["event_type"].fillna("").str.strip()
    df["resource"] = df["resource"].fillna("").str.strip()
    df["ip"]       = df["src_ip"].fillna("").str.strip()
    df["status"]   = df["status"].fillna("").str.strip()
    df["raw_line"] = df[REQUIRED_COLS].fillna("").agg(",".join, axis=1)

    mappings = df[["ts", "user", "event", "resource", "ip", "status", "raw_line"]].to_dict("records")
    db.bulk_insert_mappings(Log, mappings)
    db.commit()
    inserted += len(mappings)
    return inserted, skipped


# ────────────────────────────────────────────────────────────────────────────
# Format-specific readers
# ────────────────────────────────────────────────────────────────────────────
def _read_csv(content: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(content), dtype=str)


def _read_json(content: bytes) -> pd.DataFrame:
    data = json.loads(content.decode("utf-8", errors="replace"))

    # Unwrap common wrapper keys
    if isinstance(data, dict):
        for key in ("logs", "events", "records", "data", "items", "entries", "results"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]  # single object

    if not isinstance(data, list) or not data:
        raise ValueError("JSON file must contain a list of log objects.")

    records = []
    for raw in data:
        if isinstance(raw, dict):
            normed = _normalise_record(raw)
            if normed:
                records.append(normed)

    if not records:
        raise ValueError("No usable log records found in the JSON file.")

    return pd.DataFrame(records)


def _read_jsonl(content: bytes) -> pd.DataFrame:
    records = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            normed = _normalise_record(raw)
            if normed:
                records.append(normed)
        except json.JSONDecodeError:
            pass

    if not records:
        raise ValueError("No valid JSON lines found in JSONL file.")
    return pd.DataFrame(records)


def _read_syslog(content: bytes) -> pd.DataFrame:
    records = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        m = SYSLOG_RE.match(line)
        if m:
            ts   = m.group("timestamp")
            host = m.group("host") or ""
            msg  = m.group("message")
        else:
            # Unstructured — treat the whole line as the message
            ts   = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            host = ""
            msg  = line

        records.append({
            "timestamp":  ts,
            "user_id":    _extract_user(msg, host),
            "event_type": _infer_event_type(msg),
            "resource":   host or "system",
            "src_ip":     _extract_ip(msg),
            "status":     "failure" if re.search(r"fail|error|denied|invalid", msg, re.I) else "success",
        })

    if not records:
        raise ValueError("No syslog lines could be parsed.")
    return pd.DataFrame(records)


# ────────────────────────────────────────────────────────────────────────────
# Main entry point
# ────────────────────────────────────────────────────────────────────────────
def detect_format(filename: str, content: bytes) -> str:
    """Return 'csv' | 'json' | 'jsonl' | 'syslog'."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "csv":
        return "csv"
    if ext in ("json",):
        return "json"
    if ext in ("jsonl", "ndjson"):
        return "jsonl"
    if ext in ("log", "syslog", "txt"):
        # Peek: if first non-empty line is JSON, treat as jsonl
        first = content.lstrip().split(b"\n", 1)[0].strip()
        if first.startswith(b"{"):
            return "jsonl"
        return "syslog"
    # No extension or unknown — try to sniff
    stripped = content.lstrip()
    if stripped.startswith(b"[") or stripped.startswith(b"{"):
        first_line = stripped.split(b"\n", 1)[0].strip()
        if first_line.startswith(b"{") and stripped.count(b"\n") > 0:
            return "jsonl"
        return "json"
    return "csv"


def parse_and_ingest_csv(file_stream, db: Session, filename: str = "upload.csv") -> dict:
    """
    Parse a file (any supported format) and ingest into the Log table.
    Returns {"status", "rows_inserted", "rows_skipped", "format"}.
    """
    rows_inserted = rows_skipped = 0

    try:
        content = file_stream.read() if hasattr(file_stream, "read") else file_stream
        if not content:
            return {"status": "error", "message": "File is empty.", "rows_inserted": 0, "rows_skipped": 0}

        fmt = detect_format(filename, content)

        if fmt == "csv":
            # Process in chunks for memory efficiency
            chunk_iter = pd.read_csv(io.BytesIO(content), chunksize=2000, dtype=str)
            for chunk in chunk_iter:
                missing = {c for c in REQUIRED_COLS if c not in chunk.columns}
                if missing:
                    return {
                        "status": "error",
                        "message": f"CSV is missing required columns: {missing}. "
                                   f"Expected: {REQUIRED_COLS}",
                        "rows_inserted": rows_inserted,
                        "rows_skipped": rows_skipped,
                    }
                ins, skp = _ingest_dataframe(chunk, db)
                rows_inserted += ins
                rows_skipped  += skp

        elif fmt == "json":
            df = _read_json(content)
            ins, skp = _ingest_dataframe(df, db)
            rows_inserted += ins
            rows_skipped  += skp

        elif fmt == "jsonl":
            df = _read_jsonl(content)
            ins, skp = _ingest_dataframe(df, db)
            rows_inserted += ins
            rows_skipped  += skp

        elif fmt == "syslog":
            df = _read_syslog(content)
            ins, skp = _ingest_dataframe(df, db)
            rows_inserted += ins
            rows_skipped  += skp

        else:
            return {"status": "error", "message": f"Unsupported format: {fmt}",
                    "rows_inserted": 0, "rows_skipped": 0}

    except Exception as e:
        traceback.print_exc()
        return {"status": "error", "message": str(e),
                "rows_inserted": rows_inserted, "rows_skipped": rows_skipped}

    return {
        "status": "uploaded",
        "rows_inserted": rows_inserted,
        "rows_skipped":  rows_skipped,
        "format": fmt,
    }
