"""INTENTIONALLY VULNERABLE, SYNTHETIC TRAINING SERVICE.

DO NOT expose this fixture outside localhost. Contains zero real secrets.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path

MARKER = Path('/tmp/localpwn-persistence-demo')

class Handler(BaseHTTPRequestHandler):
    def send(self, code, value):
        body = value.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-LocalPwn-Synthetic-Lab', 'yes')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/lab/identity':
            self.send(200, 'LOCALPWN_SYNTHETIC_LAB_V1')
        elif self.path == '/objects/42':
            # Deliberately missing object-level authorization in a lab-only fixture.
            self.send(200, 'SYNTHETIC_CONFIDENTIAL_RECORD_42')
        elif self.path == '/lab/persistence':
            self.send(200, 'MARKER_PRESENT' if MARKER.exists() else 'MARKER_ABSENT')
        else:
            self.send(404, 'not-found')

    def do_POST(self):
        if self.path == '/lab/persistence':
            MARKER.write_text('LAB_SIMULATED_PERSISTENCE')
            self.send(200, 'MARKER_CREATED')
        else:
            self.send(404, 'not-found')

    def do_DELETE(self):
        if self.path == '/lab/persistence':
            MARKER.unlink(missing_ok=True)
            self.send(200, 'MARKER_REMOVED')
        else:
            self.send(404, 'not-found')

if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8080'))), Handler).serve_forever()
