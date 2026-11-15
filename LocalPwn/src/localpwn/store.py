"""SQLite audit log, artifact hashing, durable state."""
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, ts TEXT NOT NULL, phase TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL, recommendation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assessments (id TEXT PRIMARY KEY, target TEXT NOT NULL, phase TEXT NOT NULL, status TEXT NOT NULL, created TEXT NOT NULL);
"""

def now():
    return datetime.now(timezone.utc).isoformat()

class Store:
    def __init__(self, root=".localpwn"):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.root / "localpwn.sqlite")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def create(self, target):
        ident = uuid.uuid4().hex[:12]
        self.db.execute("INSERT INTO assessments VALUES (?,?,?,?,?)", (ident, target, "new", "pending", now()))
        self.db.commit()
        return ident

    def update(self, aid, phase, status):
        self.db.execute("UPDATE assessments SET phase=?,status=? WHERE id=?", (phase,status,aid))
        self.db.commit()

    def action(self, aid, phase, kind, status, details):
        ident = uuid.uuid4().hex
        self.db.execute("INSERT INTO actions VALUES (?,?,?,?,?,?,?)", (ident,aid,now(),phase,kind,status,json.dumps(details,sort_keys=True)))
        self.db.commit()
        return ident

    def finding(self, aid, title, severity, evidence, recommendation):
        ident = uuid.uuid4().hex
        self.db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?)", (ident,aid,severity,title,evidence,recommendation))
        self.db.commit()
        return ident

    def artifact(self, aid, name, data):
        folder = self.root / aid
        folder.mkdir(mode=0o700, exist_ok=True)
        path = folder / Path(name).name
        path.write_bytes(data)
        path.chmod(0o600)
        digest = hashlib.sha256(data).hexdigest()
        self.db.execute("INSERT INTO artifacts VALUES (?,?,?,?)", (uuid.uuid4().hex,aid,str(path),digest))
        self.db.commit()
        return {"path":str(path),"sha256":digest}

    def snapshot(self, aid):
        a = self.db.execute("SELECT * FROM assessments WHERE id=?",(aid,)).fetchone()
        if a is None: raise ValueError("Unknown assessment")
        rows=lambda table: [dict(r) for r in self.db.execute(f"SELECT * FROM {table} WHERE assessment_id=? ORDER BY rowid",(aid,))]
        return {"assessment":dict(a), "actions":rows("actions"),"findings":rows("findings"),"artifacts":rows("artifacts")}
