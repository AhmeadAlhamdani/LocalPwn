"""Bounded Nmap TCP service inventory, with optional isolated Docker worker.

Docker isolates the process, not the target network; host egress firewalls and
external scope approval are still the operator's responsibility.
"""
from __future__ import annotations
import os
import shutil
import subprocess
import tempfile
import uuid
import time
import xml.etree.ElementTree as ET


class ScanError(Exception):
    pass


class ScanCancelled(ScanError):
    pass


def parse_nmap(xml: str):
    if len(xml.encode('utf-8')) > 16_000_000:
        raise ScanError('Nmap XML exceeds the 16 MB limit')
    if '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():
        raise ScanError('XML entities and DTD declarations are not permitted')
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ScanError('Invalid Nmap XML') from exc
    hosts = []
    for host in root.findall('host'):
        addr = host.find('address')
        if addr is None or not addr.get('addr'):
            continue
        ports = []
        for p in host.findall('./ports/port'):
            state = p.find('state')
            if state is None or state.get('state') != 'open':
                continue
            svc = p.find('service')
            try:
                number = int(p.get('portid', '0'))
                if not 1 <= number <= 65535:
                    continue
            except ValueError:
                continue
            ports.append({
                'port': number, 'protocol': p.get('protocol', 'tcp'),
                'service': svc.get('name', 'unknown') if svc is not None else 'unknown',
                'product': svc.get('product', '') if svc is not None else '',
                'version': svc.get('version', '') if svc is not None else '',
            })
        hosts.append({'address': addr.get('addr'), 'ports': ports})
    return hosts


def _command(target: str, worker: str = 'native', container_name: str | None = None) -> list[str]:
    args = ['nmap', '-sT', '-sV', '--version-light', '-Pn', '--max-retries', '1',
            '--host-timeout', '90s', '--max-rate', '80', '-oX', '-', target]
    if worker == 'native':
        if not shutil.which('nmap'):
            raise ScanError('Nmap missing: sudo apt install nmap')
        return args
    if worker == 'docker':
        if not shutil.which('docker'):
            raise ScanError('Docker missing: install Docker Engine or use --worker native')
        return ['docker', 'run', '--rm', '--pull=never', '--read-only',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
                '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
                '--pids-limit', '64', '--memory', '256m', '--cpus', '1',
                '--user', '65534:65534', '--network', 'bridge',
                '--name', container_name or ('localpwn-'+uuid.uuid4().hex[:16]),
                'localpwn-scanner:1.0', *args]
    raise ScanError('Worker must be native or docker')


def scan(target: str, timeout: int = 240, worker: str = 'native', should_cancel=None):
    name = 'localpwn-' + uuid.uuid4().hex[:16] if worker == 'docker' else None
    command = _command(target, worker, name)
    with tempfile.TemporaryFile(mode='w+t') as out, tempfile.TemporaryFile(mode='w+t') as err:
        try:
            p = subprocess.Popen(command, stdout=out, stderr=err,
                                 start_new_session=(os.name == 'posix'))
        except OSError as exc:
            raise ScanError('Unable to start scanner') from exc
        start = time.monotonic()
        try:
            while p.poll() is None:
                if should_cancel and should_cancel():
                    raise ScanCancelled('Scan cancelled by user')
                if time.monotonic() - start > timeout:
                    raise ScanError('Nmap scan timed out')
                time.sleep(0.15)
            out.seek(0)
            xml = out.read(16_000_001)
            err.seek(0)
            error_text = err.read(1500)
            if len(xml) > 16_000_000:
                raise ScanError('Nmap output limit exceeded')
            if p.returncode:
                raise ScanError((error_text or 'Nmap exited unsuccessfully')[-1000:])
            return parse_nmap(xml), xml
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=2)
            if name:
                # Do not leave a detached worker container after CLI cancellation.
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True,
                               timeout=8, check=False)
