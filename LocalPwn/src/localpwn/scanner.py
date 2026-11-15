"""Conservative Nmap subprocess adapter; no shell interpolation."""
import subprocess
import shutil
import xml.etree.ElementTree as ET

class ScanError(Exception): pass

def parse_nmap(xml: str):
    root = ET.fromstring(xml)
    hosts=[]
    for host in root.findall("host"):
        addr=host.find("address")
        if addr is None: continue
        ports=[]
        for p in host.findall("./ports/port"):
            state=p.find("state")
            if state is None or state.get("state")!="open": continue
            svc=p.find("service")
            ports.append({"port":int(p.get("portid")),"protocol":p.get("protocol"),"service":svc.get("name", "unknown") if svc is not None else "unknown", "product":svc.get("product","") if svc is not None else "", "version":svc.get("version","") if svc is not None else ""})
        hosts.append({"address":addr.get("addr"),"ports":ports})
    return hosts

def scan(target, timeout=180):
    if not shutil.which("nmap"):
        raise ScanError("Nmap not installed: install nmap or run localpwn doctor")
    # No NSE scripts, exploit probes, shell or privileged raw packets.
    cmd=["nmap","-sT","-sV","--version-light","-Pn","--max-retries","1","--host-timeout","90s","-oX","-",target]
    try:
        result=subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Scan timed out") from exc
    if result.returncode != 0:
        raise ScanError(result.stderr[-1200:] or "Nmap scan failed")
    try: return parse_nmap(result.stdout),result.stdout
    except ET.ParseError as exc: raise ScanError("Invalid Nmap XML") from exc
