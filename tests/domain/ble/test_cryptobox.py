"""Test BLE cryptobox
"""
import pytest
from whad.ble import BDAddress
from whad.ble.crypto import f5
from whad.ble.stack.smp import SMPLayer, SM_Peer

def test_f5():
    """Test cryptobox f5 function."""
    W = bytes.fromhex((
        "ec0234a357c8ad05341010a60a397d9b"
        "99796b13b4f866f1868d34f373bfa698"
    ))
    N1 = bytes.fromhex("d5cb8454d177733effffb2ec712baeab")
    N2 = bytes.fromhex("a6e8e7cc25a75f6e216583f7ff3dc4cf")
    A1 = bytes.fromhex("0056123737bfce")
    A2 = bytes.fromhex("00a713702dcfc1")
    RES = bytes.fromhex((
        "6986791169d7cd23980522b594750a38"
        "2965f176a1084a02fd3f6a20ce636e20"
    ))
    assert f5(W, N1, N2, A1, A2) == RES

def test_smp_ltk_mac_gen():
    """Test SMP layer LTK/MAC computation."""
    W = bytes.fromhex((
        "ec0234a357c8ad05341010a60a397d9b"
        "99796b13b4f866f1868d34f373bfa698"
    ))
    N1 = bytes.fromhex("d5cb8454d177733effffb2ec712baeab")
    N2 = bytes.fromhex("a6e8e7cc25a75f6e216583f7ff3dc4cf")
    MAC = bytes.fromhex("6986791169d7cd23980522b594750a38")
    LTK = bytes.fromhex("2965f176a1084a02fd3f6a20ce636e20")
    initiator = SM_Peer(BDAddress("56:12:37:37:bf:ce"))
    initiator.rand = N1
    responder = SM_Peer(BDAddress("a7:13:70:2d:cf:c1"))
    responder.rand = N2
    smp = SMPLayer()
    assert smp.compute_ltk_and_mackey(W, initiator, responder) == (MAC, LTK)

