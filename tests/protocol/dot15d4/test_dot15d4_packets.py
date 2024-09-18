"""Protocol hub Dot15d4 PDU/Scapy packet conversion unit tests
"""
import pytest

from whad.hub import ProtocolHub
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS

@pytest.fixture
def factory():
    return ProtocolHub(1).dot15d4

def test_pdu_recv(factory):
    """Test conversion from PduReceived to packet
    """
    # Craft a BlePduReceived message
    pdu_recv = factory.create_pdu_received(
        14,
        b"FOOBAR",
        rssi=-40,
        timestamp=1234,
        fcs_validity=True,
        lqi=120
    )

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check metadata and packet content

    assert Dot15d4 in packet
    assert packet.metadata.channel == 14
    assert packet.metadata.rssi == -40
    assert packet.metadata.timestamp == 1234
    assert packet.metadata.is_fcs_valid == True
    assert packet.metadata.lqi == 120
    assert bytes(packet) == b"FOOBAR"


def test_raw_pdu_recv(factory):
    """Test conversion from RawPduReceived to packet
    """
    # Craft a RawBlePduReceived message
    pdu_recv = factory.create_raw_pdu_received(
        14,
        b"FOOBAR",
        fcs=0x1122,
        rssi=-40,
        timestamp=1234,
        fcs_validity=True,
        lqi=120
    )

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check packet metadata and content
    assert Dot15d4FCS in packet
    assert packet.metadata.channel == 14
    assert packet.metadata.rssi == -40
    assert packet.metadata.timestamp == 1234
    assert packet.metadata.is_fcs_valid == True
    assert packet.metadata.lqi == 120
    assert bytes(packet) == b"FOOBAR" + b'\x11\x22'
