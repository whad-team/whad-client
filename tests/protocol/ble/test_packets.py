"""Protocol hub BLE PDU/Scapy packet conversion unit tests
"""
import pytest

from whad.hub import ProtocolHub
from whad.hub.ble import Direction, AdvType, BDAddress
from scapy.layers.bluetooth4LE import BTLE, BTLE_DATA, BTLE_ADV, BTLE_ADV_IND

@pytest.fixture
def factory():
    return ProtocolHub(1).ble

def test_pdu_recv(factory):
    """Test conversion from BlePduReceived to packet
    """
    # Craft a BlePduReceived message
    pdu_recv = factory.create_pdu_received(
        Direction.MASTER_TO_SLAVE,
        b"FOOBAR",
        12,
        processed=False,
        decrypted=False
    )

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check metadata and packet content
    assert packet.metadata.processed == False
    assert packet.metadata.decrypted == False
    assert packet.metadata.connection_handle == 12
    assert packet.metadata.direction == Direction.MASTER_TO_SLAVE
    assert BTLE_DATA in packet
    assert bytes(packet.getlayer(BTLE_DATA)) == b"FOOBAR"

def test_raw_pdu_recv(factory):
    """Test conversion from RawBlePduReceived to packet
    """
    # Craft a RawBlePduReceived message
    pdu_recv = factory.create_raw_pdu_received(
        Direction.MASTER_TO_SLAVE,
        b"FOOBAR",
        access_address=0x12345678,
        rssi=-42,
        timestamp=12345,
        rel_timestamp=6789,
        conn_handle=12,
        processed=False,
        decrypted=False,
    )

    # Convert message to packet
    packet = pdu_recv.to_packet()

    # Check packet metadata and content
    assert packet.metadata.processed == False
    assert packet.metadata.connection_handle == 12
    assert packet.metadata.rssi == -42
    assert packet.metadata.timestamp == 12345
    assert packet.metadata.decrypted == False
    assert BTLE in packet
    assert BTLE_DATA in packet
    assert bytes(packet.getlayer(BTLE_DATA)) == b"FOOBAR"

def test_adv(factory):
    """Test conversion from BleAdvPduReceived to packet
    """
    # Craft a BleAdvPduReceive message
    adv_pdu = factory.create_adv_pdu_received(
        AdvType.ADV_IND,
        -50,
        BDAddress("00:11:22:33:44:55", random=True),
        b"\x02\x01\0x06\x0A\x09TestDevice"
    )

    # Convert to packet
    packet = adv_pdu.to_packet()

    # Check packet
    assert BTLE_ADV in packet
    assert BTLE_ADV_IND in packet
    assert packet.metadata.rssi == -50
    assert packet.metadata.direction == Direction.UNKNOWN
    assert packet.getlayer(BTLE_ADV).AdvA == "00:11:22:33:44:55"
    assert packet.getlayer(BTLE_ADV).RxAdd == 0
    assert packet.getlayer(BTLE_ADV).TxAdd == 1


    