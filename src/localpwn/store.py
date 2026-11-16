"""Local SQLite state, read-only summaries, cancellation, and hashed evidence."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, ts TEXT NOT NULL,
  phase TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, severity TEXT NOT NULL,
  title TEXT NOT NULL, evidence TEXT NOT NULL, recommendation TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY, target TEXT NOT NULL, phase TEXT NOT NULL,
  status TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS controls (
  assessment_id TEXT PRIMARY KEY, scope TEXT NOT NULL, provider TEXT NOT NULL,
  model TEXT, worker TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0,
  cancellation INTEGER NOT NULL DEFAULT 0, lab_kind TEXT NOT NULL DEFAULT 'fixture', lab_persistence INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS action_hashes (
  action_id TEXT PRIMARY KEY, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_actions_assessment ON actions(assessment_id, ts);
CREATE INDEX IF NOT EXISTS idx_artifacts_assessment ON artifacts(assessment_id);
"""

def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root='.localpwn'):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == 'posix':
            self.root.chmod(0o700)
        self.db = sqlite3.connect(self.root / 'localpwn.sqlite', timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA busy_timeout=30000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript(SCHEMA)
        if os.name == 'posix':
            (self.root / 'localpwn.sqlite').chmod(0o600)

    def close(self):
        self.db.close()

    def create(self, target):
        ident = uuid.uuid4().hex[:12]
        self.db.execute('INSERT INTO assessments VALUES (?,?,?,?,?)',
                        (ident, target, 'new', 'pending', now()))
        self.db.commit()
        return ident

    def update(self, aid, phase, status):
        self.db.execute('UPDATE assessments SET phase=?, status=? WHERE id=?',
                        (phase, status, aid))
        self.db.commit()

    def set_control(self, aid, scope, provider='none', model=None, worker='native', demo=False, lab_kind='fixture', lab_persistence=False):
        self.db.execute('INSERT OR REPLACE INTO controls '
                        '(assessment_id,scope,provider,model,worker,demo,cancellation,lab_kind,lab_persistence) '
                        'VALUES (?,?,?,?,?,?,0,?,?)',
                        (aid, json.dumps(list(scope)), provider, model, worker, int(demo), lab_kind, int(lab_persistence)))
        self.db.commit()

    def control(self, aid):
        record = self.db.execute('SELECT * FROM controls WHERE assessment_id=?',
                                 (aid,)).fetchone()
        return dict(record) if record else None

    def request_cancel(self, aid):
        cursor = self.db.execute('UPDATE controls SET cancellation=1 WHERE assessment_id=?', (aid,))
        self.db.commit()
        return cursor.rowcount > 0

    def cancelled(self, aid):
        row = self.db.execute('SELECT cancellation FROM controls WHERE assessment_id=?', (aid,)).fetchone()
        return bool(row and row[0])

    def reset_cancel(self, aid):
        self.db.execute('UPDATE controls SET cancellation=0 WHERE assessment_id=?', (aid,))
        self.db.commit()

    def action(self, aid, phase, kind, status, details):
        ident = uuid.uuid4().hex
        timestamp = now()
        details_json = json.dumps(details, sort_keys=True, default=str)
        with self.db:
            # Acquire a writer lock before reading the chain head.
            self.db.execute('BEGIN IMMEDIATE')
            prev = self.db.execute(
                '''SELECT ah.event_hash FROM action_hashes ah
                   JOIN actions a ON a.id=ah.action_id
                   WHERE a.assessment_id=? ORDER BY a.rowid DESC LIMIT 1''',
                (aid,)).fetchone()
            previous = prev[0] if prev else '0' * 64
            data = json.dumps([ident, aid, timestamp, phase, kind, status, details_json], separators=(',', ':'))
            digest = hashlib.sha256((previous + data).encode()).hexdigest()
            self.db.execute('INSERT INTO actions VALUES (?,?,?,?,?,?,?)',
                            (ident, aid, timestamp, phase, kind, status, details_json))
            self.db.execute('INSERT INTO action_hashes VALUES (?,?,?)', (ident, previous, digest))
        return ident

    def verify_actions(self, aid):
        previous = '0' * 64
        rows = self.db.execute(
            '''SELECT a.*, ah.previous_hash, ah.event_hash FROM actions a
               LEFT JOIN action_hashes ah ON ah.action_id=a.id
               WHERE a.assessment_id=? ORDER BY a.rowid''', (aid,)).fetchall()
        for row in rows:
            if row['event_hash'] is None:
                # Older v0.2 actions predate the hash chain; caller is told it is incomplete.
                return {'valid': False, 'reason': 'legacy unhashed actions', 'checked': 0}
            data = json.dumps([row[x] for x in ('id','assessment_id','ts','phase','kind','status','details')], separators=(',', ':'))
            digest = hashlib.sha256((previous + data).encode()).hexdigest()
            if row['previous_hash'] != previous or row['event_hash'] != digest:
                return {'valid': False, 'reason': 'hash chain mismatch', 'checked': len(rows)}
            previous = digest
        return {'valid': True, 'checked': len(rows), 'head': previous}

    def finding(self, aid, title, severity, evidence, recommendation):
        ident = uuid.uuid4().hex
        self.db.execute('INSERT INTO findings VALUES (?,?,?,?,?,?)',
                        (ident, aid, severity, title, evidence, recommendation))
        self.db.commit()
        return ident

    def artifact(self, aid, name, data):
        folder = self.root / aid
        folder.mkdir(mode=0o700, exist_ok=True)
        name = Path(name).name
        if name in {'', '.', '..'}:
            raise ValueError('Invalid artifact name')
        path = folder / name
        if path.exists():
            original = Path(name)
            path = folder / (original.stem + '-' + uuid.uuid4().hex[:8] + original.suffix)
        temporary = folder / ('.' + path.name + '.tmp')
        temporary.write_bytes(data)
        if os.name == 'posix':
            temporary.chmod(0o600)
        temporary.replace(path)
        digest = hashlib.sha256(data).hexdigest()
        self.db.execute('INSERT INTO artifacts VALUES (?,?,?,?)',
                        (uuid.uuid4().hex, aid, str(path), digest))
        self.db.commit()
        return {'path': str(path), 'sha256': digest}

    def verify_artifacts(self, aid):
        result = []
        for r in self.db.execute('SELECT * FROM artifacts WHERE assessment_id=? ORDER BY rowid', (aid,)):
            path = Path(r['path']).resolve()
            safe = path.parent == (self.root / aid).resolve() and path.is_file()
            actual = hashlib.sha256(path.read_bytes()).hexdigest() if safe else None
            result.append({'name': path.name, 'valid': bool(safe and actual == r['sha256'])})
        return result

    def snapshot(self, aid):
        a = self.db.execute('SELECT * FROM assessments WHERE id=?', (aid,)).fetchone()
        if a is None:
            raise ValueError('Unknown assessment')
        tables = ('actions', 'findings', 'artifacts')
        result = {'assessment': dict(a)}
        for table in tables:
            result[table] = [dict(r) for r in self.db.execute(
                f'SELECT * FROM {table} WHERE assessment_id=? ORDER BY rowid', (aid,))]
        result['audit_integrity'] = self.verify_actions(aid)
        return result
