import pytest
from localpwn.policy import Policy

def test_target_allowed():
    p=Policy(("192.168.56.0/24",))
    assert p.validate_target("192.168.56.10")=="192.168.56.10/32"

def test_target_outside_scope():
    with pytest.raises(ValueError): Policy(("192.168.56.0/24",)).validate_target("10.10.10.10")

def test_large_subnet_rejected():
    with pytest.raises(ValueError): Policy(("192.168.56.0/24",)).validate_target("192.168.56.0/24")

def test_lab_gate():
    assert not Policy(("127.0.0.1/32",)).permits("lab_persistence")
    assert Policy(("127.0.0.1/32",),lab=True).permits("lab_persistence")
    assert not Policy(("127.0.0.1/32",),lab=True).permits("arbitrary_shell")

def test_no_hostname():
    with pytest.raises(ValueError): Policy(("127.0.0.1/32",)).validate_target("example.com")
