"""Protocol hub Dot15d4 PDU/Scapy packet conversion unit tests
"""
import pytest

from whad.hub import ProtocolHub
from whad.hub.esb import EsbNodeAddress
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, compute_crc

def build_esb_frame(address='01:02:03:04:05', payload=b'', no_ack=False, pid=0):
    """Build an ESB frame
    """
    preamble = 0xaa if bytes.fromhex(address[:2])[0] >= 0x80 else 0x55

    # Compute payload length
    payload_len = len(payload)&0x3F

    # Build packet config field
    pcf = (payload_len)<<3
    pcf |= (pid&0x3)<<1
    if no_ack:
        pcf |= 1

    # Build payload bytes
    carry = pcf&1
    out = []
    for x in payload:
        out.append((x>>1) | (carry << 7))
        carry = x&1
    out.append(carry<<7)

    # Compute CRC
    frame = bytes.fromhex(address.replace(':','')) + bytes([pcf>>1]) + bytes(out)
    crc = compute_crc(frame)

    # Append the packet CRC
    out[-1] |= crc[0]>>1
    out.append((crc[1]>>1) | (crc[0]&1)<<7)
    out.append((crc[1]&1)<<7)

    # Build the final frame
    return bytes([preamble]) + bytes.fromhex(address.replace(':','')) + bytes([pcf>>1]) + bytes(out)

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
    esb_frame = build_esb_frame("11:22:33:44:55", b"FOOBAR")
    pdu_recv = factory.createRawPduReceived(
        14,
        esb_frame,
        rssi=-40,
        timestamp=1234,
        crc_validity=True,
        address=EsbNodeAddress(b'\x11\x22\x33\x44\x55')
    )

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check packet metadata and content
    assert ESB_Hdr in packet
    assert packet.metadata.channel == 14
    assert packet.metadata.rssi == -40
    assert packet.metadata.timestamp == 1234
    assert packet.metadata.is_crc_valid == True
    assert packet.metadata.address == "11:22:33:44:55"
    assert bytes(packet) == esb_frame
