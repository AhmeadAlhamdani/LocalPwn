"""Scope enforcement and execution gating."""
from dataclasses import dataclass
import ipaddress
import socket

@dataclass(frozen=True)
class Policy:
    networks: tuple[str, ...]
    lab: bool = False
    approved_intrusive: bool = False
    max_hosts: int = 32

    def __post_init__(self):
        if not self.networks:
            raise ValueError("At least one authorized CIDR must be specified")
        for n in self.networks:
            ipaddress.ip_network(n, strict=False)

    def allows_ip(self, addr: str) -> bool:
        ip = ipaddress.ip_address(addr)
        return any(ip in ipaddress.ip_network(n, strict=False) for n in self.networks)

    def validate_target(self, target: str) -> str:
        """MVP deliberately accepts literal IPv4/IPv6 only; no DNS rebinding."""
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError("MVP accepts literal IP addresses/CIDRs, not DNS names") from exc
        if network.num_addresses > self.max_hosts:
            raise ValueError(f"Target contains {network.num_addresses} addresses, limit is {self.max_hosts}")
        if not all(self.allows_ip(str(ip)) for ip in network):
            raise ValueError("Target outside authorized scope")
        return str(network)

    def permits(self, action: str) -> bool:
        if action in {"discovery", "enumeration", "report", "offline_analysis", "safe_validation"}:
            return True
        if action == "intrusive_validation":
            return self.lab or self.approved_intrusive
        if action in {"lab_exploitation", "lab_persistence"}:
            return self.lab
        return False
