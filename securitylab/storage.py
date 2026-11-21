"""SQLite is authoritative; JSONL is regenerated from its transactional outbox."""
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from .policy import PolicyError, run_id

STAGES = ("QUEUED", "DISCOVERED", "CONFIRMED", "PATCHED", "VERIFIED", "DONE")

class Store:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "state.sqlite3", timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS projects(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, source_path TEXT NOT NULL,
          metadata_fingerprint TEXT NOT NULL, inventory_json TEXT NOT NULL,
          created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS project_snapshots(
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id),
          created REAL NOT NULL,
          manifest_sha256 TEXT NOT NULL,
          file_count INTEGER NOT NULL,
          total_bytes INTEGER NOT NULL,
          skipped_secrets INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS meta(version INTEGER NOT NULL);
        INSERT INTO meta SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM meta);
        CREATE TABLE IF NOT EXISTS runs(
          id TEXT PRIMARY KEY, stage TEXT NOT NULL, status TEXT NOT NULL,
          mode TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          stop INTEGER NOT NULL DEFAULT 0, error TEXT, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(
          run_id TEXT PRIMARY KEY REFERENCES runs(id), body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(
          run_id TEXT REFERENCES runs(id), kind TEXT, body TEXT NOT NULL,
          PRIMARY KEY(run_id,kind));
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT REFERENCES runs(id),
          time REAL NOT NULL, type TEXT NOT NULL, body TEXT NOT NULL);
        ''')
        if self.db.execute("SELECT version FROM meta").fetchone()[0] != 1:
            raise PolicyError("Unsupported database version")

    def close(self):
        self.db.close()

    def event(self, rid, kind, body):
        self.db.execute("INSERT INTO events(run_id,time,type,body) VALUES(?,?,?,?)",
                        (rid, time.time(), kind, json.dumps(body, ensure_ascii=False)))

    def create(self, mode="scripted-demo-no-ai"):
        if mode not in {"scripted-demo-no-ai", "scripted-demo-docker-no-ai"}:
            raise PolicyError("Unknown execution mode")
        rid = uuid.uuid4().hex
        with self.db:
            self.db.execute("INSERT INTO runs(id,stage,status,mode,created) VALUES(?,?,?,?,?)",
                            (rid, "QUEUED", "QUEUED", mode, time.time()))
            self.event(rid, "created", {"mode": mode})
        return rid

    def get(self, rid):
        row = self.db.execute("SELECT * FROM runs WHERE id=?", (run_id(rid),)).fetchone()
        if row is None:
            raise PolicyError("Unknown run")
        return dict(row)

    def runs(self):
        return [dict(x) for x in self.db.execute("SELECT * FROM runs ORDER BY created")]

    def begin(self, rid, max_attempts):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(rid)
            if row["stage"] == "DONE":
                return False
            if row["status"] not in {"QUEUED", "RUNNING"}:
                raise PolicyError("Use retry for stopped/blocked jobs")
            if row["attempts"] >= max_attempts:
                raise PolicyError("Attempt limit reached")
            self.db.execute("UPDATE runs SET status='RUNNING',attempts=attempts+1,error=NULL WHERE id=?", (rid,))
            self.event(rid, "started", {"attempt": row["attempts"] + 1})
        return True

    def advance(self, rid, expected, target, evidence=None, finding=None):
        if STAGES.index(target) != STAGES.index(expected) + 1:
            raise PolicyError("Invalid state transition")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(rid)
            if row["stage"] != expected or row["status"] != "RUNNING" or row["stop"]:
                raise PolicyError("Stale, inactive or stopped task")
            if evidence:
                for kind, body in evidence.items():
                    self.db.execute("INSERT INTO evidence VALUES(?,?,?)", (rid, kind, json.dumps(body)))
            if finding:
                self.db.execute("INSERT OR REPLACE INTO findings VALUES(?,?)", (rid, json.dumps(finding)))
            self.db.execute("UPDATE runs SET stage=?,status=? WHERE id=?",
                            (target, "DONE" if target == "DONE" else "RUNNING", rid))
            self.event(rid, "transition", {"from": expected, "to": target})

    def stop(self, rid):
        with self.db:
            row = self.get(rid)
            if row['stage'] == 'DONE':
                raise PolicyError("Completed job cannot be stopped")
            self.db.execute("UPDATE runs SET stop=1 WHERE id=?", (rid,))
            self.event(rid, "stop_requested", {})

    def pause(self, rid, status, error):
        if status not in {"BLOCKED", "STOPPED"}:
            raise PolicyError("Invalid pause status")
        with self.db:
            self.db.execute("UPDATE runs SET status=?,error=? WHERE id=?", (status, error[:2000], rid))
            self.event(rid, status.lower(), {"reason": error[:2000]})

    def retry(self, rid, limit):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.get(rid)
            if row["status"] not in {"BLOCKED", "STOPPED"} or row["attempts"] >= limit:
                raise PolicyError("Retry not permitted")
            self.db.execute("UPDATE runs SET status='QUEUED',stop=0,error=NULL WHERE id=?", (rid,))
            self.event(rid, "retry", {})

    def evidence(self, rid):
        self.get(rid)
        return {r["kind"]: json.loads(r["body"]) for r in self.db.execute("SELECT * FROM evidence WHERE run_id=?", (rid,))}

    def finding(self, rid):
        self.get(rid)
        row = self.db.execute("SELECT body FROM findings WHERE run_id=?", (rid,)).fetchone()
        return json.loads(row[0]) if row else None

    def history(self, rid):
        self.get(rid)
        return [dict(r) | {"body": json.loads(r["body"])} for r in self.db.execute("SELECT * FROM events WHERE run_id=? ORDER BY id", (rid,))]

    def export_events(self, rid, path):
        atomic_text(path, ''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in self.history(rid)))


def atomic_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("x", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


@contextlib.contextmanager
def worker_lock(root: Path):
    """One worker for this DB; OS releases the lock on process death."""
    path = root / "worker.lock"
    with path.open("a+b") as f:
        f.seek(0)
        f.write(b"0")
        f.flush()
        f.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise PolicyError('Another worker owns this state directory (locked: ' + str(root) +
                              '); stop the previous dashboard or CLI process using it, then start again') from e
        try:
            yield
        finally:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f, fcntl.LOCK_UN)
