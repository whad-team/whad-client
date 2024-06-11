"""Protocol hub Dot15d4 PDU/Scapy packet conversion unit tests
"""
import pytest

from whad.hub import ProtocolHub
from whad.hub.esb import EsbNodeAddress
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr


@pytest.fixture
def factory():
    return ProtocolHub(1).esb

def test_pkt_recv(factory):
    """Test conversion from BlePduReceived to packet
    """
    # Craft a BlePduReceived message
    pdu_recv = factory.createPduReceived(
        14,
        b"FOOBAR",
        rssi=-40,
        timestamp=1234,
        crc_validity=True,
        address=EsbNodeAddress(0x1122334455, 5)
    )

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check metadata and packet content

    assert ESB_Payload_Hdr in packet
    assert packet.metadata.channel == 14
    assert packet.metadata.rssi == -40
    assert packet.metadata.timestamp == 1234
    assert packet.metadata.is_crc_valid == True
    assert packet.metadata.address == '11:22:33:44:55'
    assert bytes(packet) == b"FOOBAR"


def test_raw_pdu_recv(factory):
    """Test conversion from RawBlePduReceived to packet
    """
    # Craft a RawBlePduReceived message
    pdu_recv = factory.createRawPduReceived(
        14,
        b"\xAAFOOBAR",
        rssi=-40,
        timestamp=1234,
        crc_validity=True,
        address=EsbNodeAddress(b'\x11\x22\x33\x44\x55')
    )
    print(pdu_recv)

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check packet metadata and content
    assert ESB_Hdr in packet
    assert packet.metadata.channel == 14
    assert packet.metadata.rssi == -40
    assert packet.metadata.timestamp == 1234
    assert packet.metadata.is_crc_valid == True
    assert packet.metadata.address == '11:22:33:44:55'
    assert bytes(packet) == b"\xAA\x00\x05FOOBAR" + b'\x00'
